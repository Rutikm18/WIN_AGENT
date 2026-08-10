# Windows Release Trust and Distribution

> Release validation must include the startup scenarios and repair safety boundaries in [`advanced_support/`](advanced_support/README.md).

This document defines the production release gate for the AttackLens Windows
agent. It deliberately does not promise that an arbitrary new download will
never display a warning. Windows trust has three separate layers:

1. Authenticode proves publisher identity and file integrity.
2. Microsoft Defender and other antivirus engines inspect behavior/content.
3. Microsoft Defender SmartScreen evaluates publisher and file reputation.

Microsoft documents that even a correctly signed new binary can show an
"unrecognized app" warning until its file hash or signing identity accumulates
positive reputation. EV certificates no longer bypass that process. Microsoft
Store distribution is the only documented path that avoids SmartScreen download
warnings by using Microsoft's signing identity. See:

- https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation
- https://learn.microsoft.com/windows/win32/seccrypto/signtool
- https://learn.microsoft.com/defender-endpoint/command-line-arguments-microsoft-defender-antivirus

## Production certificate

Use a publicly trusted OV/EV code-signing certificate issued to the legal
AttackLens publisher identity, or Microsoft Artifact Signing. For the current
local release builder, import/provision the certificate in the CurrentUser or
LocalMachine Personal store and make its private key available to SignTool. The
certificate must:

- be currently valid;
- have the Code Signing EKU (`1.3.6.1.5.5.7.3.3`);
- have an accessible private key, preferably HSM or hardware-token protected;
- build a trusted chain with online revocation checking;
- use the same publisher identity consistently across releases.

Never export a production private key into this repository, an MSI, a build log,
or a general-purpose CI variable.

## Release command

Run from `agent\os\windows` in an elevated, network-connected Windows shell:

```powershell
.\build_windows_msi.ps1 `
  -Version 2.0.10 `
  -Release `
  -SignThumbprint "0123456789ABCDEF0123456789ABCDEF01234567"
```

Release mode cannot skip tests, reuse old executable output, or skip the
Defender scan. It performs these gates in order:

1. Validate the MSI version range, tools, signing certificate, private key,
   Code Signing EKU, trust chain, and revocation state.
2. Parse every Windows PowerShell build/installer script.
3. Run all `agent/tests/unit/test_windows_*.py` tests and all
   `agent/os/windows/tests` tests.
4. Regenerate GUI branding and confirm the RTF license is present.
5. Rebuild both frozen service executables.
6. Sign and RFC 3161 timestamp both executables.
7. Verify both signatures with SignTool and PowerShell, including signer
   thumbprint and timestamp presence.
8. Generate a SHA-256 manifest for every file in both frozen payload trees.
9. Build the MSI, then sign and timestamp it.
10. Scan both executables and the MSI with Microsoft Defender without adding
    exclusions or suppressing remediation policy.
11. Run WiX ICE validation and print the final SHA-256 hash and signature state.

Any signing, timestamping, trust, Defender, test, or ICE failure terminates the
release. The low-level `pkg\build_msi.ps1` remains available only for unsigned
development packages.

## Licensing and unattended installation

Interactive installation displays `pkg\assets\license.rtf` and gates Next on
acceptance. Reduced, basic, and silent deployments must explicitly accept the
same agreement:

```powershell
msiexec /i attacklens-agent-2.0.10-x64.msi /qn `
  ACCEPT_EULA=1 `
  MANAGER_URL="https://manager.example.com:443" `
  TLS_VERIFY=true `
  ENROLL_TOKEN="<one-time-token>" `
  /l*v install.log
```

The license text must receive legal review before public distribution. Do not
replace it with a generated or placeholder agreement during the build.

## Defender, antivirus, and firewall behavior

The installer does not disable Defender, create antivirus exclusions, disable
SmartScreen, change attack-surface-reduction policy, or weaken Windows Firewall.
Those behaviors are unsafe and commonly reduce product trust.

The agent is outbound-only. It does not require a listening port or inbound
firewall rule. Managed environments with default-deny outbound policy must
allow the signed `attacklens-agent.exe` service to reach the configured manager
over the selected HTTPS destination/port. Proxy and TLS policy remain under the
administrator's control.

If Microsoft Defender or SmartScreen reports a false positive, submit the exact
signed artifact and its SHA-256 hash through Microsoft's Security Intelligence
submission workflow. Do not work around a detection by obfuscating the binary,
changing publisher identity, disabling scanning, or creating broad exclusions.

## Distribution checklist

- Publish only the final, signed MSI; never modify it after signing.
- Serve it over HTTPS with the exact SHA-256 hash beside the download.
- Keep the same trusted publisher certificate across releases when possible.
- Test install, upgrade, repair, rollback, and uninstall on clean supported
  Windows client and server VMs.
- Test with SmartScreen, Smart App Control, Defender, and representative
  enterprise application-control policies enabled.
- Consider Microsoft Store distribution when a no-SmartScreen-prompt consumer
  download path is a hard requirement.
