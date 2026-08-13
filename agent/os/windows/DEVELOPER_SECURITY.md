# Windows `developer_security` telemetry

The Windows agent emits a privacy-safe DeepMesh snapshot every 3,600 seconds.
It uses the existing durable outbox, encryption, retry, and ingest pipeline; no
manager endpoint or storage change is required.

## Wire contract

The section is `developer_security`, schema version `1`, platform `windows`.
The following capability and record-array names are fixed for manager/UI
compatibility:

| Capability | Record array | Windows source |
|---|---|---|
| `editor_extensions` | `items` | VS Code, Cursor, Windsurf extensions |
| `mcp_servers` | `servers` | Claude, Cursor, Windsurf, Continue, Cline/Roo, VS Code, Codex and bounded workspace configuration |
| `browser_extensions` | `items` | Chrome, Edge, Brave and Firefox manifests |
| `native_messaging` | `items` | Native-messaging registry and manifest metadata |
| `agent_cli_tools` | `items` | Trusted local PATH directories, without executing tools |
| `ai_applications` | `items` | Both Uninstall registry views and per-user Programs |
| `listening_ports` | `items` | `psutil` listeners |
| `processes` | `items` | Toolhelp32 process name/PID/PPID snapshot |
| `launchd` | `items` | Run/RunOnce, Startup folders and Winlogon; both WoW64 views |
| `cron` | `users` | Task Scheduler native metadata with bounded XML fallback |
| `shell_startup` | `files` | PowerShell profiles and `cmd.exe` AutoRun metadata |
| `node_packages` | `users` | npm, Yarn, pnpm and Bun global package directories |
| `python_packages` | `users` | Per-user and machine-wide interpreter/`.dist-info` metadata |
| `homebrew` | `formulae` | Chocolatey, Scoop and WinGet metadata (`casks` is empty) |
| `git` | `users` | Per-user/system global Git configuration metadata |
| `credential_locations` | `users` | Paths and filesystem metadata only |
| `docker` | `containers` | Docker Desktop/daemon state, images and containers |

Every successful capability includes `count`; a failed capability contains
only `error`, and the same type is recorded in `collection.errors`.

## Privacy and bounds

- Credential and secret-bearing file contents are never returned.
- MCP environment variable names may be returned; their values are never returned.
- Docker environment names may be returned; their values are never returned.
- Inline API keys, GitHub tokens, AWS access IDs, JWTs and assigned
  password/token/API-key values are redacted.
- Every list is capped at 500 records and every string at 2,048 characters.
- The complete JSON snapshot is capped at 6 MiB. Trimming sets
  `collection.payload_truncated=true` and keeps all 17 capabilities present.
- Each capability has a six-second isolation deadline. A blocked optional
  source cannot prevent the remaining data from being delivered.

## Source-mode verification (does not send data)

From the repository root:

```powershell
$env:PYTHONPATH = (Get-Location).Path
python -c "from agent.os.windows.collectors.developer_security import WinDeveloperSecurityCollector; import json; d=WinDeveloperSecurityCollector().collect(); print(json.dumps({k:{'count':v.get('count'),'error':v.get('error')} for k,v in d['capabilities'].items()}, indent=2))"
```

The healthy result has all 17 keys, no capability errors, and
`collection.partial=false`. Optional absent software is a successful zero
count, not an error.

Run the contract and delivery tests:

```powershell
python -m pytest agent/tests/unit/test_windows_developer_security.py -q
```

## Delivery verification after a future packaged deployment

This source change intentionally does not rebuild or replace the installed
agent. After it is included in a future signed package, verify:

```powershell
Select-String -Path 'C:\ProgramData\AttackLens\config\agent.toml' `
  -Pattern '^\[collection\.sections\.developer_security\]$','^interval_sec\s*=\s*3600$'

Select-String -Path 'C:\ProgramData\AttackLens\logs\agent.log' `
  -Pattern 'developer_security|unsupported section|HTTP 422'
```

The manager ingest path stores the decrypted `section` and `data` values
without platform-specific dispatch. A manager HTTP 422 means the deployed
manager is older than the stated contract; the agent retains/suppresses the
unsupported section according to its existing compatibility circuit.
