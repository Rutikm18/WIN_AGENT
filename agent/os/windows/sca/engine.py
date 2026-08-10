"""
agent/os/windows/sca/engine.py — Security Configuration Assessment engine.

OS-agnostic policy-evaluation core used by the Windows SCA collector. It loads
declarative benchmark policies (a bundled Python policy plus operator drop-ins),
runs each check's rules through a caller-supplied command runner, and returns a
canonical result document (per-check pass/fail plus a summary score).

Rule grammar (a compact, declarative check syntax)
──────────────────────────────────────────────────
A rule is a string. Optional leading ``not `` inverts the whole rule.

    c:<command>[ -> <matcher>]   run a command; evaluate matcher on stdout
    f:<path>                     true if the file or directory exists

Matchers (applied to command stdout; case-insensitive)
    r:<regex>                    regex search — matches if found
    n:<regex> compare <op> <n>   extract first capture group as int, compare (<,<=,>,>=,==,!=)
    !<matcher>                   negate the matcher
    <literal>                    substring search
    (absent)                     matches if the command exit code is 0

Check condition semantics
    all   (default) → pass when every rule matches
    any             → pass when at least one rule matches
    none            → pass when no rule matches

The engine NEVER raises. A rule whose command cannot be run (timeout / missing
tool) is tri-state "error"; a check that hits an error where it changes the
outcome is reported with result ``error`` and the scan continues.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Callable, Optional

log = logging.getLogger("agent.windows.sca")

# runner(command: str, timeout: float) returns either
# (returncode | None, stdout) or (returncode | None, stdout, stderr).
# returncode is None when the command could not be executed (timeout / not found).
Runner = Callable[[str, float], tuple]

_VALID_CONDITIONS = ("all", "any", "none")

RESULT_PASS = "pass"
RESULT_FAIL = "fail"
RESULT_NA   = "not_applicable"
RESULT_ERR  = "error"
RESULT_UNKNOWN = "unknown"

_VALID_RESULTS = {RESULT_PASS, RESULT_FAIL, RESULT_NA, RESULT_ERR, RESULT_UNKNOWN}
_EVIDENCE_LIMIT = 1024
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)"
    r"\b(\s*[:=]\s*)([^\s,;]+)"
)


class ScaEngine:
    """Evaluate one or more SCA policies and return a canonical result document."""

    def __init__(
        self,
        runner: Runner,
        extra_policy_dirs: "list[str] | None" = None,
        platform: str = "windows",
        rule_timeout: float = 15.0,
        bundled_policies: "list[dict] | None" = None,
    ):
        self._runner = runner
        self._dirs = list(extra_policy_dirs or [])
        self._platform = str(platform or "").lower()
        self._rule_timeout = float(rule_timeout)
        self._bundled = list(bundled_policies or [])

    # ── public API ────────────────────────────────────────────────────────────

    def scan(self) -> dict:
        """Run every applicable policy. Returns {"policies": [...], "summary": {...}}."""
        started = time.monotonic()
        policies = list(self._bundled) + load_policies(self._dirs, self._platform)
        pol_results: list[dict] = []
        for pol in policies:
            if not isinstance(pol, dict):
                continue
            if not self._applies(pol):
                continue
            try:
                pol_results.append(self._run_policy(pol))
            except Exception as exc:  # defensive — a policy must not crash the scan
                log.debug("SCA policy %r failed: %s", pol.get("id"), exc)
        result = {
            "policies": pol_results,
            "summary": _aggregate_summary(pol_results),
        }
        result["duration_ms"] = _elapsed_ms(started)
        return result

    # ── policy / check evaluation ─────────────────────────────────────────────

    def _applies(self, pol: dict) -> bool:
        plats = pol.get("platform")
        if not plats:
            return True
        if isinstance(plats, str):
            plats = [plats]
        return self._platform in {str(p).lower() for p in plats}

    def _run_policy(self, pol: dict) -> dict:
        checks_out: list[dict] = []
        counts = {
            RESULT_PASS: 0,
            RESULT_FAIL: 0,
            RESULT_NA: 0,
            RESULT_ERR: 0,
            RESULT_UNKNOWN: 0,
        }
        scored_pass = 0
        scored_fail = 0
        for chk in pol.get("checks", []) or []:
            if not isinstance(chk, dict):
                continue
            evaluated = self._run_check(chk)
            result = str(evaluated.get("result") or RESULT_ERR)
            if result not in _VALID_RESULTS:
                result = RESULT_ERR
            counts[result] = counts.get(result, 0) + 1
            if bool(chk.get("scored", True)):
                scored_pass += int(result == RESULT_PASS)
                scored_fail += int(result == RESULT_FAIL)
            checks_out.append({
                "id":          str(chk.get("id") or ""),
                "title":       str(chk.get("title") or ""),
                "result":      result,
                "severity":    str(chk.get("severity") or "medium").lower(),
                "profile":     chk.get("profile") or pol.get("profile"),
                "scored":      bool(chk.get("scored", True)),
                "rationale":   _opt_str(chk.get("rationale")),
                "remediation": _opt_str(chk.get("remediation")),
                "compliance":  chk.get("compliance") if isinstance(chk.get("compliance"), dict) else {},
                "duration_ms": int(evaluated.get("duration_ms") or 0),
                "rules":       evaluated.get("rules") or [],
            })
        total = len(checks_out)
        scored = scored_pass + scored_fail
        score = round(100.0 * scored_pass / scored, 1) if scored else None
        assessed = scored + counts[RESULT_NA]
        coverage = round(100.0 * assessed / total, 1) if total else None
        return {
            "policy_id":   str(pol.get("id") or "policy"),
            "policy_name": str(pol.get("name") or pol.get("id") or "policy"),
            "policy_version": str(pol.get("version") or ""),
            "benchmark":   _opt_str(pol.get("benchmark")),
            "profile":     pol.get("profile"),
            "checks":      checks_out,
            "summary": {
                "total":          total,
                "pass":           counts[RESULT_PASS],
                "fail":           counts[RESULT_FAIL],
                "not_applicable": counts[RESULT_NA],
                "error":          counts[RESULT_ERR],
                "unknown":        counts[RESULT_UNKNOWN],
                "scored_checks":  scored,
                "scored_pass":    scored_pass,
                "scored_fail":    scored_fail,
                "score_pct":      score,
                "coverage_pct":   coverage,
                "status":         _summary_status(counts),
            },
        }

    def _run_check(self, chk: dict) -> dict:
        started = time.monotonic()
        condition = str(chk.get("condition") or "all").lower()
        if condition not in _VALID_CONDITIONS:
            condition = "all"

        applicability = chk.get("applicability")
        if applicability:
            app_eval = self._eval_rule(applicability)
            app_result = app_eval.get("result")
            if app_result == RESULT_FAIL:
                return {
                    "result": RESULT_NA,
                    "rules": [dict(app_eval, applicability=True)],
                    "duration_ms": _elapsed_ms(started),
                }
            if app_result in (RESULT_ERR, RESULT_UNKNOWN):
                return {
                    "result": app_result,
                    "rules": [dict(app_eval, applicability=True)],
                    "duration_ms": _elapsed_ms(started),
                }

        rules = chk.get("rules") or []
        if not rules:
            return {"result": RESULT_NA, "rules": [], "duration_ms": _elapsed_ms(started)}

        evals: list[dict] = []
        for rule in rules:
            try:
                evals.append(self._eval_rule(rule))
            except Exception as exc:
                log.debug("SCA rule error [%s]: %s", rule, exc)
                evals.append({
                    "id": "",
                    "rule_type": "invalid",
                    "result": RESULT_ERR,
                    "return_code": None,
                    "duration_ms": 0,
                    "evidence": _safe_evidence(str(exc)),
                })

        results = [str(e.get("result") or RESULT_ERR) for e in evals]
        has_error = RESULT_ERR in results
        has_unknown = RESULT_UNKNOWN in results

        if condition == "all":
            if RESULT_FAIL in results:
                result = RESULT_FAIL
            elif has_error:
                result = RESULT_ERR
            elif has_unknown:
                result = RESULT_UNKNOWN
            else:
                result = RESULT_PASS
        elif condition == "any":
            if RESULT_PASS in results:
                result = RESULT_PASS
            elif has_error:
                result = RESULT_ERR
            elif has_unknown:
                result = RESULT_UNKNOWN
            else:
                result = RESULT_FAIL
        else:
            if RESULT_PASS in results:
                result = RESULT_FAIL
            elif has_error:
                result = RESULT_ERR
            elif has_unknown:
                result = RESULT_UNKNOWN
            else:
                result = RESULT_PASS

        return {"result": result, "rules": evals, "duration_ms": _elapsed_ms(started)}

    # ── rule evaluation ───────────────────────────────────────────────────────

    def _eval_rule(self, rule) -> dict:
        started = time.monotonic()
        metadata = rule if isinstance(rule, dict) else {}
        rule_id = str(metadata.get("id") or "")
        rule_text = metadata.get("rule") if isinstance(rule, dict) else rule
        rule_text = str(rule_text or "").strip()
        unknown_when = metadata.get("unknown_when") or []
        if isinstance(unknown_when, str):
            unknown_when = [unknown_when]

        negate = False
        if rule_text[:4].lower() == "not ":
            negate = True
            rule_text = rule_text[4:].strip()

        if rule_text.startswith("f:"):
            target = os.path.expandvars(rule_text[2:].strip())
            exists = os.path.exists(target)
            matched = (not exists) if negate else exists
            return {
                "id": rule_id,
                "rule_type": "file",
                "result": RESULT_PASS if matched else RESULT_FAIL,
                "return_code": 0,
                "duration_ms": _elapsed_ms(started),
                "evidence": _safe_evidence(f"path={target}; exists={exists}"),
            }

        if rule_text.startswith("c:"):
            cmd, matcher = _split_matcher(rule_text[2:])
            rc, out, err = _coerce_run_result(self._runner(cmd.strip(), self._rule_timeout))
            combined = "\n".join(v for v in (out, err) if v).strip()
            if rc is None:
                result = RESULT_ERR
            elif any(re.search(str(pattern), combined, re.IGNORECASE) for pattern in unknown_when):
                result = RESULT_UNKNOWN
            elif matcher is None:
                result = RESULT_PASS if rc == 0 else RESULT_FAIL
            else:
                matched = _apply_matcher(matcher, out)
                if matched is None:
                    result = RESULT_ERR
                else:
                    matched = (not matched) if negate else matched
                    result = RESULT_PASS if matched else RESULT_FAIL
            return {
                "id": rule_id,
                "rule_type": "command",
                "result": result,
                "return_code": rc,
                "duration_ms": _elapsed_ms(started),
                "evidence": _safe_evidence(combined),
            }

        # Unknown rule type — do not guess; report as error for the check.
        log.debug("SCA: unknown rule type: %r", rule_text)
        return {
            "id": rule_id,
            "rule_type": "invalid",
            "result": RESULT_ERR,
            "return_code": None,
            "duration_ms": _elapsed_ms(started),
            "evidence": "unsupported rule type",
        }


# ── matcher helpers ───────────────────────────────────────────────────────────

def _coerce_run_result(value) -> "tuple[Optional[int], str, str]":
    """Accept legacy two-tuples while allowing runners to return stderr."""
    if not isinstance(value, tuple):
        return None, "", "runner returned an invalid result"
    if len(value) == 2:
        rc, out = value
        return rc, str(out or ""), ""
    if len(value) >= 3:
        rc, out, err = value[:3]
        return rc, str(out or ""), str(err or "")
    return None, "", "runner returned an empty result"


def _safe_evidence(value) -> str:
    """Bound and redact command evidence before it enters telemetry or disk state."""
    text = str(value or "").replace("\x00", "").strip()
    text = _SENSITIVE_VALUE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
    if len(text) > _EVIDENCE_LIMIT:
        return text[:_EVIDENCE_LIMIT] + "...[truncated]"
    return text


def _elapsed_ms(started: float) -> int:
    return max(0, int(round((time.monotonic() - started) * 1000.0)))


def _summary_status(counts: dict) -> str:
    if int(counts.get(RESULT_ERR) or 0):
        return "error"
    if int(counts.get(RESULT_UNKNOWN) or 0):
        return "degraded"
    if int(counts.get(RESULT_FAIL) or 0):
        return "non_compliant"
    return "compliant"


def _split_matcher(body: str) -> "tuple[str, str | None]":
    """Split ``<command> -> <matcher>`` on the first ' -> '. Returns (cmd, matcher|None)."""
    idx = body.find(" -> ")
    if idx < 0:
        return body, None
    return body[:idx], body[idx + 4:]


def _apply_matcher(matcher: str, out: str) -> Optional[bool]:
    """Evaluate a matcher against command stdout. None when the matcher is malformed."""
    matcher = matcher.strip()
    negate = False
    if matcher.startswith("!"):
        negate = True
        matcher = matcher[1:].strip()

    if matcher.startswith("r:"):
        pat = matcher[2:]
        try:
            res = re.search(pat, out, re.IGNORECASE | re.MULTILINE) is not None
        except re.error:
            return None

    elif matcher.startswith("n:"):
        mm = re.match(r"^(.*?)\s+compare\s+(<=|>=|==|!=|<|>)\s+(-?\d+)\s*$", matcher[2:])
        if not mm:
            return None
        pat, op, num = mm.group(1), mm.group(2), int(mm.group(3))
        try:
            g = re.search(pat, out, re.IGNORECASE | re.MULTILINE)
        except re.error:
            return None
        if not g:
            res = False
        else:
            token = g.group(1) if g.groups() else g.group(0)
            try:
                res = _numeric_compare(int(str(token).strip(), 0), op, num)
            except (TypeError, ValueError):
                return None
    else:
        res = matcher.lower() in out.lower()

    return (not res) if negate else res


def _numeric_compare(val: int, op: str, num: int) -> bool:
    return {
        "<":  val < num,
        "<=": val <= num,
        ">":  val > num,
        ">=": val >= num,
        "==": val == num,
        "!=": val != num,
    }[op]


# ── policy loading ────────────────────────────────────────────────────────────

def load_policies(dirs: "list[str]", platform: str = "windows") -> "list[dict]":
    """
    Load operator drop-in policies from the given directories.

    Reads ``*.json`` with the stdlib (always available) and ``*.yaml``/``*.yml``
    only when PyYAML is importable. Malformed files are logged and skipped — a bad
    drop-in never breaks the scan. The bundled policy is supplied separately by the
    collector, so a fresh install with no drop-ins still assesses configuration.
    """
    policies: list[dict] = []
    yaml_mod = _maybe_yaml()
    for d in dirs or []:
        try:
            if not d or not os.path.isdir(d):
                continue
            for fname in sorted(os.listdir(d)):
                ext = os.path.splitext(fname)[1].lower()
                path = os.path.join(d, fname)
                try:
                    if ext == ".json":
                        with open(path, "r", encoding="utf-8", errors="replace") as fh:
                            loaded = json.load(fh)
                    elif ext in (".yaml", ".yml"):
                        if yaml_mod is None:
                            log.info("SCA: skipping %s — PyYAML not installed", fname)
                            continue
                        with open(path, "r", encoding="utf-8", errors="replace") as fh:
                            loaded = yaml_mod.safe_load(fh)
                    else:
                        continue
                except Exception as exc:
                    log.warning("SCA: failed to parse policy %s: %s", fname, exc)
                    continue
                policies.extend(_coerce_policy_list(loaded))
        except Exception as exc:
            log.debug("SCA: cannot read policy dir %s: %s", d, exc)
    return policies


def _coerce_policy_list(loaded) -> "list[dict]":
    if isinstance(loaded, dict):
        return [loaded]
    if isinstance(loaded, list):
        return [p for p in loaded if isinstance(p, dict)]
    return []


def _maybe_yaml():
    try:
        import yaml  # type: ignore
        return yaml
    except Exception:
        return None


# ── summary helpers ───────────────────────────────────────────────────────────

def _aggregate_summary(pol_results: "list[dict]") -> dict:
    agg = {
        "total": 0,
        "pass": 0,
        "fail": 0,
        "not_applicable": 0,
        "error": 0,
        "unknown": 0,
    }
    for pr in pol_results:
        s = pr.get("summary") or {}
        for k in agg:
            agg[k] += int(s.get(k) or 0)
    scored_pass = sum(int((pr.get("summary") or {}).get("scored_pass") or 0) for pr in pol_results)
    scored_fail = sum(int((pr.get("summary") or {}).get("scored_fail") or 0) for pr in pol_results)
    scored = scored_pass + scored_fail
    agg["scored_checks"] = scored
    agg["scored_pass"] = scored_pass
    agg["scored_fail"] = scored_fail
    agg["score_pct"] = round(100.0 * scored_pass / scored, 1) if scored else None
    assessed = scored + agg["not_applicable"]
    agg["coverage_pct"] = round(100.0 * assessed / agg["total"], 1) if agg["total"] else None
    agg["status"] = _summary_status(agg)
    agg["policies"] = len(pol_results)
    return agg


def _opt_str(v) -> "str | None":
    if v is None:
        return None
    s = str(v).strip()
    return s or None
