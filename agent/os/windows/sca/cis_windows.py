"""
agent/os/windows/sca/cis_windows.py — bundled Windows security baseline policy.

Shipped as a Python module (not YAML) so the frozen PyInstaller EXE can assess
configuration with **no** parser dependency. Operators may add or override checks
by dropping ``*.json`` / ``*.yaml`` policies into ``C:\\ProgramData\\AttackLens\\sca\\``.

Every rule is a **read-only** query (reg query, sc query, netsh show, or a wrapped
Get-* cmdlet). PowerShell checks are wrapped in ``try/catch`` so unsupported
platforms (e.g. Secure Boot on a legacy BIOS host) yield a benign token rather
than a crash. Registry checks pass when the value equals the hardened setting.

Compliance references map each check to the relevant CIS Microsoft Windows
Benchmark control family for downstream reporting.

Quoting note: registry rules use single-quoted raw strings so the ``"`` around a
key path with spaces (e.g. "Windows NT", "Terminal Server") reaches cmd.exe as a
real double quote, while regex escapes (``\\b``, ``\\S``) and path backslashes stay
literal. ``reg query ... /v Name`` prints "    Name    REG_DWORD    0x1"; the
``0x1\\b`` matcher matches the value 1 without also matching 0x10 / 0x1a.
"""
from __future__ import annotations

POLICY: dict = {
    "id": "cis_windows",
    "name": "CIS-aligned Microsoft Windows Security Baseline",
    "platform": ["windows"],
    "version": "2.1.0",
    "benchmark": "CIS-aligned Windows 10/11 and Windows Server endpoint controls",
    "profile": ["level_1", "enterprise"],
    "checks": [
        # ── 1. Boot / disk / core defenses ────────────────────────────────────
        {
            "id": "W-1.1",
            "title": "Ensure Secure Boot is enabled",
            "condition": "any",
            "rules": [
                r'c:reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State" /v UEFISecureBootEnabled -> r:0x1\b',
                {
                    "id": "secure_boot_api",
                    "rule": r"c:try { Confirm-SecureBootUEFI } catch { 'Unknown:NotSupported' } -> r:True",
                    "unknown_when": r"Unknown:NotSupported",
                },
            ],
            "severity": "high",
            "rationale": "Secure Boot blocks unsigned bootloaders and rootkits from loading before the OS.",
            "remediation": "Enable Secure Boot in UEFI firmware settings and boot in UEFI (not legacy/CSM) mode.",
            "compliance": {"cis": ["1.1"], "family": "boot_integrity"},
        },
        {
            "id": "W-1.2",
            "title": "Ensure BitLocker protects the system drive (C:)",
            "condition": "any",
            "rules": [
                r"c:manage-bde -status C: -> r:Protection\s+On",
                {
                    "id": "bitlocker_api",
                    "rule": r"c:try { (Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus } catch { 'Unknown:Unavailable' } -> r:^On$",
                    "unknown_when": r"Unknown:Unavailable",
                },
            ],
            "severity": "high",
            "rationale": "Full-disk encryption protects data at rest if the device is lost or stolen.",
            "remediation": "Enable BitLocker on C: with a TPM protector: manage-bde -on C:",
            "compliance": {"cis": ["18.9.11"], "family": "data_protection"},
        },
        {
            "id": "W-1.3",
            "title": "Ensure User Account Control (UAC) is enabled",
            "condition": "all",
            "rules": [
                r'c:reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA -> r:0x1\b',
            ],
            "rationale": "UAC forces privileged actions through an elevation prompt, limiting silent privilege abuse.",
            "remediation": "Set HKLM\\...\\Policies\\System\\EnableLUA to 1 and reboot.",
            "compliance": {"cis": ["2.3.17"], "family": "privilege_control"},
        },
        {
            "id": "W-1.4",
            "title": "Ensure Microsoft Defender real-time protection is on",
            "condition": "all",
            "rules": [
                {
                    "id": "defender_realtime",
                    "rule": r"c:try { (Get-MpComputerStatus).RealTimeProtectionEnabled } catch { 'Unknown:Unavailable' } -> r:True",
                    "unknown_when": r"Unknown:Unavailable",
                },
            ],
            "severity": "critical",
            "rationale": "Real-time protection scans files and processes as they execute, blocking known malware.",
            "remediation": "Enable real-time protection: Set-MpPreference -DisableRealtimeMonitoring $false",
            "compliance": {"cis": ["18.9.47"], "family": "malware_defense"},
        },
        {
            "id": "W-1.5",
            "title": "Ensure Windows Firewall is on for all profiles",
            "condition": "none",
            "rules": [
                # 'none' passes when NO profile reports OFF.
                r"c:netsh advfirewall show allprofiles state -> r:State\s+OFF",
            ],
            "rationale": "A host firewall on every profile limits inbound exposure of listening services.",
            "remediation": "netsh advfirewall set allprofiles state on",
            "compliance": {"cis": ["9.1", "9.2", "9.3"], "family": "network_defense"},
        },

        # ── 2. SMB / name resolution hardening ────────────────────────────────
        {
            "id": "W-2.1",
            "title": "Ensure SMBv1 is disabled",
            "condition": "any",
            "rules": [
                {
                    "id": "smb1_api",
                    "rule": r"c:try { (Get-SmbServerConfiguration).EnableSMB1Protocol } catch { 'Unknown:Unavailable' } -> r:False",
                    "unknown_when": r"Unknown:Unavailable",
                },
                r'c:reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 -> r:0x0\b',
            ],
            "severity": "critical",
            "rationale": "SMBv1 is obsolete and exploited by wormable attacks (e.g. EternalBlue).",
            "remediation": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
            "compliance": {"cis": ["18.3.1"], "family": "network_defense"},
        },
        {
            "id": "W-2.2",
            "title": "Ensure SMB server signing is required",
            "condition": "any",
            "rules": [
                {
                    "id": "smb_signing_api",
                    "rule": r"c:try { (Get-SmbServerConfiguration).RequireSecuritySignature } catch { 'Unknown:Unavailable' } -> r:True",
                    "unknown_when": r"Unknown:Unavailable",
                },
                r'c:reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature -> r:0x1\b',
            ],
            "severity": "high",
            "rationale": "Required SMB signing prevents tampering and relay attacks on file-share traffic.",
            "remediation": "Set-SmbServerConfiguration -RequireSecuritySignature $true",
            "compliance": {"cis": ["2.3.9.2"], "family": "network_defense"},
        },
        {
            "id": "W-2.3",
            "title": "Ensure LLMNR (multicast name resolution) is disabled",
            "condition": "all",
            "rules": [
                r'c:reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast -> r:0x0\b',
            ],
            "rationale": "LLMNR can be abused for credential-harvesting spoofing (Responder-style attacks).",
            "remediation": "Set HKLM\\...\\DNSClient\\EnableMulticast to 0 via Group Policy.",
            "compliance": {"cis": ["18.5.4.2"], "family": "network_defense"},
        },
        {
            "id": "W-2.4",
            "title": "Ensure NetBIOS over TCP/IP is not left enabled by default",
            "condition": "none",
            "rules": [
                # TcpipNetbiosOptions: 0=default(via DHCP), 1=enabled, 2=disabled.
                # Count IP-enabled adapters with NetBIOS explicitly enabled (1).
                # 'none' fails when that count is > 0. CIM is used because wmic is
                # deprecated/absent on modern Windows 11 / Server 2025.
                r"c:try { @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Where-Object { $_.TcpipNetbiosOptions -eq 1 }).Count } catch { 0 } -> n:(\d+) compare > 0",
            ],
            "rationale": "NetBIOS name service is another spoofing/poisoning vector on local networks.",
            "remediation": "Set NetBIOS over TCP/IP to Disabled on each adapter (TcpipNetbiosOptions = 2).",
            "compliance": {"cis": ["18.5.9"], "family": "network_defense"},
        },

        # ── 3. Credential protection & accounts ───────────────────────────────
        {
            "id": "W-3.1",
            "title": "Ensure LSASS runs as a protected process (RunAsPPL)",
            "condition": "all",
            "rules": [
                r'c:reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL -> r:0x[12]\b',
            ],
            "rationale": "LSASS PPL blocks non-protected processes from reading credential memory (e.g. mimikatz).",
            "remediation": "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL to 1 and reboot.",
            "compliance": {"cis": ["18.3.7"], "family": "credential_protection"},
        },
        {
            "id": "W-3.2",
            "title": "Ensure Credential Guard / LSA configuration flags are set",
            "condition": "all",
            "rules": [
                r'c:reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags -> r:0x[12]\b',
            ],
            "rationale": "Credential Guard isolates secrets in virtualization-based security, blocking pass-the-hash.",
            "remediation": "Enable Virtualization Based Security and set LsaCfgFlags to 1 (with UEFI lock) or 2.",
            "compliance": {"cis": ["18.9.5"], "family": "credential_protection"},
        },
        {
            "id": "W-3.3",
            "title": "Ensure the built-in Guest account is disabled",
            "condition": "all",
            "rules": [
                {
                    "id": "guest_account",
                    "rule": r"c:try { (Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' }).Enabled } catch { 'Unknown:Unavailable' } -> r:False",
                    "unknown_when": r"Unknown:Unavailable",
                },
            ],
            "rationale": "An enabled Guest account provides an anonymous, low-friction foothold.",
            "remediation": "Disable-LocalUser -Name Guest",
            "compliance": {"cis": ["2.3.1.1"], "family": "account_policy"},
        },
        {
            "id": "W-3.4",
            "title": "Ensure the built-in Administrator account is disabled",
            "condition": "all",
            "rules": [
                {
                    "id": "administrator_account",
                    "rule": r"c:try { (Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }).Enabled } catch { 'Unknown:Unavailable' } -> r:False",
                    "unknown_when": r"Unknown:Unavailable",
                },
            ],
            "rationale": "The well-known Administrator SID is a prime target for brute force and lateral movement.",
            "remediation": "Disable or rename the built-in Administrator account and use named admin accounts.",
            "compliance": {"cis": ["2.3.1.5"], "family": "account_policy"},
        },

        # ── 4. Patching & auditing ────────────────────────────────────────────
        {
            "id": "W-4.1",
            "title": "Ensure automatic updates are not disabled by policy",
            "condition": "none",
            "rules": [
                r'c:reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate -> r:0x1\b',
            ],
            "rationale": "Disabling automatic updates leaves known-exploited vulnerabilities unpatched.",
            "remediation": "Remove the NoAutoUpdate=1 policy or configure WSUS/Windows Update for Business.",
            "compliance": {"cis": ["18.9.108"], "family": "patch_management"},
        },
        {
            "id": "W-4.2",
            "title": "Ensure a security update was installed recently",
            "condition": "all",
            "rules": [
                # Emit days-since-last-hotfix; pass when it is 45 days or fewer.
                r"c:try { [int]((Get-Date) - (Get-HotFix | Sort-Object InstalledOn | Select-Object -Last 1).InstalledOn).TotalDays } catch { 9999 } -> n:(\d+) compare <= 45",
            ],
            "rationale": "A long gap since the last patch indicates an unmaintained, exposed host.",
            "remediation": "Apply the latest cumulative update; investigate why patching has stalled.",
            "compliance": {"cis": ["18.9.108"], "family": "patch_management"},
        },
        {
            "id": "W-4.3",
            "title": "Ensure audit policy captures logon and account events",
            "condition": "none",
            "rules": [
                # 'none' fails if the Logon/Logoff category shows 'No Auditing'.
                r'c:auditpol /get /category:"Logon/Logoff" -> r:No Auditing',
            ],
            "rationale": "Without logon auditing there is no forensic trail for intrusion or account misuse.",
            "remediation": 'auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable',
            "compliance": {"cis": ["17.5"], "family": "audit_logging"},
        },

        # ── 5. Remote access surface ──────────────────────────────────────────
        {
            "id": "W-5.1",
            "title": "Ensure RDP requires Network Level Authentication (NLA)",
            "condition": "all",
            "applicability": r'c:reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections -> r:0x0\b',
            "rules": [
                r'c:reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication -> r:0x1\b',
            ],
            "rationale": "NLA authenticates users before a full RDP session, blunting pre-auth RDP exploits.",
            "remediation": "Set UserAuthentication to 1 under the RDP-Tcp WinStation key.",
            "compliance": {"cis": ["18.9.65"], "family": "remote_access"},
        },
        {
            "id": "W-5.2",
            "title": "Ensure the Remote Registry service is not running",
            "condition": "none",
            "rules": [
                r"c:sc query RemoteRegistry -> r:STATE\s*:\s*4\s+RUNNING",
            ],
            "rationale": "A running Remote Registry service widens the remote attack surface unnecessarily.",
            "remediation": "sc stop RemoteRegistry && sc config RemoteRegistry start= disabled",
            "compliance": {"cis": ["5.28"], "family": "attack_surface"},
        },
        {
            "id": "W-5.3",
            "title": "Ensure the Telnet server service is not running",
            "condition": "none",
            "rules": [
                r"c:sc query TlntSvr -> r:STATE\s*:\s*4\s+RUNNING",
            ],
            "rationale": "Telnet transmits credentials in cleartext and should never be installed or running.",
            "remediation": "Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer",
            "compliance": {"cis": ["18.4"], "family": "attack_surface"},
        },
        {
            "id": "W-1.6",
            "title": "Ensure Defender tamper protection is enabled",
            "condition": "all",
            "rules": [{
                "id": "defender_tamper",
                "rule": r"c:try { (Get-MpComputerStatus).IsTamperProtected } catch { 'Unknown:Unavailable' } -> r:True",
                "unknown_when": r"Unknown:Unavailable",
            }],
            "severity": "critical",
            "rationale": "Tamper protection prevents local changes from silently weakening malware defenses.",
            "remediation": "Enable Microsoft Defender tamper protection through the managed security portal or Windows Security.",
            "compliance": {"cis": ["18.10.43"], "family": "malware_defense"},
        },
        {
            "id": "W-1.7",
            "title": "Ensure Defender security intelligence is current",
            "condition": "all",
            "rules": [{
                "id": "defender_signature_age",
                "rule": r"c:try { (Get-MpComputerStatus).AntivirusSignatureAge } catch { 'Unknown:Unavailable' } -> n:(\d+) compare <= 7",
                "unknown_when": r"Unknown:Unavailable",
            }],
            "severity": "high",
            "rationale": "Stale security intelligence reduces protection against recently identified threats.",
            "remediation": "Update Defender security intelligence and repair update policy or network access if updates remain stale.",
            "compliance": {"cis": ["18.10.43"], "family": "malware_defense"},
        },
        {
            "id": "W-1.8",
            "title": "Ensure SmartScreen is enabled and cannot be bypassed",
            "condition": "all",
            "rules": [
                r'c:reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen -> r:0x1\b',
                r'c:reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel -> r:Block',
            ],
            "severity": "high",
            "rationale": "SmartScreen blocks low-reputation and malicious downloads before execution.",
            "remediation": "Configure Windows Defender SmartScreen as enabled with the blocking level through policy.",
            "compliance": {"cis": ["18.10.80"], "family": "malware_defense"},
        },
        {
            "id": "W-2.5",
            "title": "Ensure SMB client signing is always required",
            "condition": "all",
            "rules": [
                r'c:reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature -> r:0x1\b',
            ],
            "severity": "high",
            "rationale": "Client-side SMB signing reduces relay and in-transit tampering risk.",
            "remediation": "Set LanmanWorkstation\\Parameters\\RequireSecuritySignature to 1 through Group Policy.",
            "compliance": {"cis": ["2.3.8.2"], "family": "network_defense"},
        },
        {
            "id": "W-2.6",
            "title": "Ensure insecure SMB guest authentication is disabled",
            "condition": "none",
            "rules": [
                r'c:reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth -> r:0x1\b',
            ],
            "severity": "high",
            "rationale": "Unauthenticated SMB guest sessions enable spoofing and data exposure.",
            "remediation": "Set AllowInsecureGuestAuth to 0 in the Lanman Workstation policy.",
            "compliance": {"cis": ["18.5.8"], "family": "network_defense"},
        },
        {
            "id": "W-2.7",
            "title": "Ensure WDigest does not store reusable credentials",
            "condition": "all",
            "rules": [
                r"c:$v=(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential; if($null -eq $v){0}else{$v} -> r:^0$",
            ],
            "severity": "critical",
            "rationale": "WDigest reusable credentials expose plaintext-equivalent secrets in LSASS memory.",
            "remediation": "Set WDigest UseLogonCredential to 0 and restart the system.",
            "compliance": {"cis": ["18.3.6"], "family": "credential_protection"},
        },
        {
            "id": "W-2.8",
            "title": "Ensure LAN Manager authentication uses NTLMv2 only",
            "condition": "all",
            "rules": [
                r"c:$v=(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel; if($null -eq $v){-1}else{$v} -> n:(-?\d+) compare >= 5",
            ],
            "severity": "high",
            "rationale": "Older LM and NTLM response modes allow weaker credential challenge-response exchanges.",
            "remediation": "Set Network security: LAN Manager authentication level to Send NTLMv2 response only; refuse LM and NTLM.",
            "compliance": {"cis": ["2.3.11.7"], "family": "credential_protection"},
        },
        {
            "id": "W-2.9",
            "title": "Ensure anonymous enumeration is restricted",
            "condition": "all",
            "rules": [
                r"c:$v=(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -ErrorAction SilentlyContinue).RestrictAnonymous; if($null -eq $v){0}else{$v} -> n:(\d+) compare >= 1",
            ],
            "severity": "high",
            "rationale": "Anonymous account and share enumeration helps attackers map targets before authentication.",
            "remediation": "Set LSA RestrictAnonymous to at least 1 through security policy.",
            "compliance": {"cis": ["2.3.10"], "family": "access_control"},
        },
        {
            "id": "W-3.5",
            "title": "Ensure the local minimum password length is at least 14",
            "condition": "all",
            "rules": [{
                "id": "local_password_length",
                "rule": r"c:try { ([ADSI]('WinNT://' + $env:COMPUTERNAME)).MinPasswordLength.Value } catch { 'Unknown:Unavailable' } -> n:(\d+) compare >= 14",
                "unknown_when": r"Unknown:Unavailable",
            }],
            "severity": "high",
            "rationale": "Long passwords materially increase the cost of guessing and offline cracking.",
            "remediation": "Set the applicable account policy minimum password length to 14 or more.",
            "compliance": {"cis": ["1.1.4"], "family": "account_policy"},
        },
        {
            "id": "W-3.6",
            "title": "Ensure account lockout threshold is between 1 and 10 attempts",
            "condition": "all",
            "rules": [
                {
                    "id": "lockout_nonzero",
                    "rule": r"c:try { ([ADSI]('WinNT://' + $env:COMPUTERNAME)).MaxBadPasswords.Value } catch { 'Unknown:Unavailable' } -> n:(\d+) compare >= 1",
                    "unknown_when": r"Unknown:Unavailable",
                },
                {
                    "id": "lockout_upper_bound",
                    "rule": r"c:try { ([ADSI]('WinNT://' + $env:COMPUTERNAME)).MaxBadPasswords.Value } catch { 'Unknown:Unavailable' } -> n:(\d+) compare <= 10",
                    "unknown_when": r"Unknown:Unavailable",
                },
            ],
            "severity": "high",
            "rationale": "A bounded lockout threshold limits sustained online password guessing.",
            "remediation": "Set the applicable account lockout threshold to 10 or fewer invalid attempts.",
            "compliance": {"cis": ["1.2.1"], "family": "account_policy"},
        },
        {
            "id": "W-4.4",
            "title": "Ensure process creation events include command lines",
            "condition": "all",
            "rules": [
                r'c:reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled -> r:0x1\b',
            ],
            "severity": "high",
            "rationale": "Command-line auditing provides essential execution context for detection and investigation.",
            "remediation": "Enable Include command line in process creation events through Advanced Audit Policy.",
            "compliance": {"cis": ["18.9.3"], "family": "audit_logging"},
        },
        {
            "id": "W-4.5",
            "title": "Ensure PowerShell script block logging is enabled",
            "condition": "all",
            "rules": [
                r'c:reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging -> r:0x1\b',
            ],
            "severity": "high",
            "rationale": "Script block logs expose de-obfuscated PowerShell content used during attacks.",
            "remediation": "Enable PowerShell Script Block Logging through administrative templates.",
            "compliance": {"cis": ["18.9.95"], "family": "audit_logging"},
        },
        {
            "id": "W-4.6",
            "title": "Ensure the Security event log is at least 196608 KB",
            "condition": "all",
            "rules": [{
                "id": "security_log_size",
                "rule": r"c:try { (Get-WinEvent -ListLog Security).MaximumSizeInBytes } catch { 'Unknown:Unavailable' } -> n:(\d+) compare >= 201326592",
                "unknown_when": r"Unknown:Unavailable",
            }],
            "severity": "medium",
            "rationale": "Adequate log capacity reduces evidence loss during busy periods and attack bursts.",
            "remediation": "Set the Security log maximum size to at least 196608 KB.",
            "compliance": {"cis": ["18.9.27"], "family": "audit_logging"},
        },
        {
            "id": "W-5.4",
            "title": "Ensure WinRM does not allow Basic authentication",
            "condition": "all",
            "rules": [
                r"c:$v=(Get-Item -Path WSMan:\localhost\Service\Auth\Basic -ErrorAction SilentlyContinue).Value; if($null -eq $v){$false}else{$v} -> r:False",
            ],
            "severity": "high",
            "rationale": "WinRM Basic authentication exposes reusable credentials without stronger authentication.",
            "remediation": "Disable Basic authentication for the WinRM service through policy.",
            "compliance": {"cis": ["18.10.90"], "family": "remote_access"},
        },
        {
            "id": "W-5.5",
            "title": "Ensure WinRM unencrypted traffic is disabled",
            "condition": "all",
            "rules": [
                r"c:$v=(Get-Item -Path WSMan:\localhost\Service\AllowUnencrypted -ErrorAction SilentlyContinue).Value; if($null -eq $v){$false}else{$v} -> r:False",
            ],
            "severity": "critical",
            "rationale": "Unencrypted remote-management traffic can disclose commands and credentials.",
            "remediation": "Disable AllowUnencrypted for the WinRM service and use Kerberos or HTTPS.",
            "compliance": {"cis": ["18.10.90"], "family": "remote_access"},
        },
        {
            "id": "W-5.6",
            "title": "Ensure solicited Remote Assistance is disabled",
            "condition": "all",
            "rules": [
                r'c:reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp -> r:0x0\b',
            ],
            "severity": "medium",
            "rationale": "Disabling Remote Assistance removes an unnecessary interactive remote-access path.",
            "remediation": "Disable Configure Solicited Remote Assistance through policy.",
            "compliance": {"cis": ["18.9.65"], "family": "remote_access"},
        },
        {
            "id": "W-5.7",
            "title": "Ensure AutoPlay is disabled on all drives",
            "condition": "all",
            "rules": [
                r'c:reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun -> r:0xff\b',
            ],
            "severity": "medium",
            "rationale": "Disabling AutoPlay blocks automatic execution from removable and network media.",
            "remediation": "Set Turn off AutoPlay to Enabled for all drives.",
            "compliance": {"cis": ["18.9.8"], "family": "attack_surface"},
        },
        {
            "id": "W-1.9",
            "title": "Ensure Defender does not exclude high-risk system paths",
            "condition": "all",
            "rules": [{
                "id": "defender_dangerous_exclusions",
                "rule": r"c:try { $x=@((Get-MpPreference).ExclusionPath); if($x -match '^N/A:'){ 'Unknown:AccessDenied' } else { @($x | Where-Object { $_ -match '^(?i)[A-Z]:\\?$' -or $_ -match '^(?i)[A-Z]:\\(Windows|Program Files(?: \(x86\))?|ProgramData|Users)(\\|$)' }).Count } } catch { 'Unknown:Unavailable' } -> n:(\d+) compare == 0",
                "unknown_when": r"Unknown:(AccessDenied|Unavailable)",
            }],
            "severity": "critical",
            "rationale": "Broad exclusions of Windows, program, data, or user roots create an unscanned execution surface.",
            "remediation": "Remove broad Defender exclusions and retain only narrowly scoped, documented exceptions.",
            "compliance": {"cis": ["18.10.43"], "family": "malware_defense"},
        },
        {
            "id": "W-1.10",
            "title": "Ensure critical Defender Attack Surface Reduction rules block",
            "condition": "all",
            "rules": [{
                "id": "defender_asr_critical",
                "rule": r"c:try { $p=Get-MpPreference; $required=@('D4F940AB-401B-4EFC-AADC-AD5F3C50688A','3B576869-A4EC-4529-8536-B80A7769E899','75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84','D3E037E1-3EB8-44C8-A917-57927947596D'); $ids=@($p.AttackSurfaceReductionRules_Ids); $actions=@($p.AttackSurfaceReductionRules_Actions); @($required | Where-Object { $i=[Array]::IndexOf($ids,$_); $i -ge 0 -and [int]$actions[$i] -eq 1 }).Count } catch { 'Unknown:Unavailable' } -> n:(\d+) compare >= 4",
                "unknown_when": r"Unknown:Unavailable",
            }],
            "severity": "high",
            "rationale": "ASR block rules stop common Office and script-based initial-access techniques.",
            "remediation": "Configure the four critical Defender ASR rule GUIDs in Block mode through policy.",
            "compliance": {"cis": ["18.10.43"], "family": "malware_defense"},
        },
        {
            "id": "W-1.11",
            "title": "Ensure system exploit protection does not disable DEP",
            "condition": "all",
            "rules": [{
                "id": "system_dep",
                "rule": r"c:try { $v=[string](Get-ProcessMitigation -System).DEP.Enable; if([string]::IsNullOrWhiteSpace($v)){ 'Unknown:Unavailable' } else { $v } } catch { 'Unknown:Unavailable' } -> r:^(ON|NOTSET)$",
                "unknown_when": r"Unknown:Unavailable",
            }],
            "severity": "high",
            "rationale": "Data Execution Prevention raises the cost of memory-corruption exploitation.",
            "remediation": "Apply the Microsoft-recommended Exploit Protection system baseline and do not disable DEP.",
            "compliance": {"cis": ["18.10.24"], "family": "exploit_protection"},
        },
        {
            "id": "W-1.12",
            "title": "Ensure a TPM is present and ready",
            "condition": "all",
            "rules": [{
                "id": "tpm_ready",
                "rule": r"c:try { $t=Get-Tpm; if($null -eq $t){ 'Unknown:Unavailable' } else { [int]($t.TpmPresent -and $t.TpmReady) } } catch { 'Unknown:Unavailable' } -> n:(\d+) compare == 1",
                "unknown_when": r"Unknown:Unavailable",
            }],
            "severity": "high",
            "rationale": "A ready TPM protects BitLocker keys and measured-boot secrets against offline extraction.",
            "remediation": "Enable, initialize, and provision TPM 2.0 in firmware and Windows.",
            "compliance": {"cis": ["18.9.11"], "family": "hardware_security"},
        },
        {
            "id": "W-2.10",
            "title": "Ensure NTLM client and server require 128-bit session security",
            "condition": "all",
            "rules": [r"c:attacklens-native ntlm_session_security -> n:(\d+) compare == 1"],
            "severity": "high",
            "rationale": "Strong NTLM session security reduces downgrade exposure where NTLM cannot yet be removed.",
            "remediation": "Set NtlmMinClientSec and NtlmMinServerSec to at least 0x20080000 through policy.",
            "compliance": {"cis": ["2.3.11.9", "2.3.11.10"], "family": "credential_protection"},
        },
        {
            "id": "W-3.7",
            "title": "Ensure local password complexity is enabled",
            "condition": "all",
            "rules": [{
                "id": "password_complexity",
                "rule": r"c:attacklens-native password_complexity -> n:(\d+) compare == 1",
                "unknown_when": r"Unknown:Unavailable",
            }],
            "severity": "high",
            "rationale": "Password complexity blocks trivially weak local-account passwords.",
            "remediation": "Enable Password must meet complexity requirements in the applicable account policy.",
            "compliance": {"cis": ["1.1.5"], "family": "account_policy"},
        },
        {
            "id": "W-4.7",
            "title": "Ensure critical advanced audit subcategories are complete",
            "condition": "all",
            "rules": [{
                "id": "advanced_audit_coverage",
                "rule": r"c:attacklens-native audit_coverage -> n:(\d+) compare == 3",
                "unknown_when": r"Unknown:AccessDenied",
            }],
            "severity": "high",
            "rationale": "Logon, process creation, and account-management auditing are required for reliable detection and forensics.",
            "remediation": "Enable success/failure for Logon and User Account Management, and success for Process Creation.",
            "compliance": {"cis": ["17.2.6", "17.3.2", "17.5.1"], "family": "audit_logging"},
        },
        {
            "id": "W-4.8",
            "title": "Ensure the endpoint is not awaiting a reboot",
            "condition": "all",
            "rules": [r"c:attacklens-native pending_reboot -> n:(\d+) compare == 0"],
            "severity": "medium",
            "rationale": "Pending reboots can leave security updates and policy changes inactive.",
            "remediation": "Schedule and complete the required reboot, then verify update health.",
            "compliance": {"cis": ["18.9.108"], "family": "patch_management"},
        },
        {
            "id": "W-4.9",
            "title": "Ensure PowerShell is constrained when application control is enforced",
            "condition": "all",
            "applicability": r"c:try { $d=Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard; $ci=@($d.CodeIntegrityPolicyEnforcementStatus) -contains 2; $a=Get-AppLockerPolicy -Effective; $n=@($a.RuleCollections | ForEach-Object {$_.Count} | Measure-Object -Sum).Sum; [int]($ci -or $n -gt 0) } catch { 0 } -> n:(\d+) compare == 1",
            "rules": [r"c:$ExecutionContext.SessionState.LanguageMode -> r:^ConstrainedLanguage$"],
            "severity": "high",
            "rationale": "Constrained Language Mode limits PowerShell access to dangerous .NET and COM primitives under application control.",
            "remediation": "Enforce a WDAC or AppLocker policy that places untrusted PowerShell into Constrained Language Mode.",
            "compliance": {"cis": ["18.9.95"], "family": "script_control"},
        },
        {
            "id": "W-5.8",
            "title": "Ensure WDAC or AppLocker application control is enforced",
            "condition": "all",
            "rules": [{
                "id": "application_control",
                "rule": r"c:try { $d=Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard; $ci=@($d.CodeIntegrityPolicyEnforcementStatus) -contains 2; $a=Get-AppLockerPolicy -Effective; $n=@($a.RuleCollections | ForEach-Object {$_.Count} | Measure-Object -Sum).Sum; [int]($ci -or $n -gt 0) } catch { 'Unknown:Unavailable' } -> n:(\d+) compare == 1",
                "unknown_when": r"Unknown:Unavailable",
            }],
            "severity": "high",
            "rationale": "Application control prevents unauthorized executables, scripts, installers, and libraries from running.",
            "remediation": "Deploy and enforce a signed WDAC policy or complete AppLocker rule collections.",
            "compliance": {"cis": ["18.9.1"], "family": "application_control"},
        },
    ],
}

BUNDLED_POLICIES: list = [POLICY]
