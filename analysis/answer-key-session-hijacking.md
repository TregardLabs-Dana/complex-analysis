---
scenario: entra-session-hijacking-cookie-theft
dataset: logs/
generated: 2026-07-21
---

# Answer key: Session hijacking via browser cookie theft (Fabrikam lab)

**Do not read this before attempting the investigation in `logs/`** — it spoils the exercise.

## Ground-truth summary

An attacker stole Sarah Chen's (`sarah.chen@fabrikam.com`) Entra ID session cookie from her
workstation (`FABRIKAM-WKS042`) via a PowerShell-based stager, exfiltrated it to attacker
infrastructure, then replayed it to sign into Entra ID as her — without a fresh MFA challenge —
before establishing persistence.

## Full timeline (local endpoint time / UTC noted per event)

| # | Time | Source | Event | ATT&CK |
|---|---|---|---|---|
| 1 | 2026-07-16 11:47:52 local (16:47:52 UTC) | Sysmon `smon-006` / Security `sec-006` | Obfuscated PowerShell launched on `FABRIKAM-WKS042` under `schen` (base64 `-enc` payload) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell |
| 2 | 2026-07-16 11:48:05 local | Sysmon `smon-007` / Security `sec-007` | Child PowerShell process copies the Edge `Cookies` SQLite store to a staged file | [T1539](https://attack.mitre.org/techniques/T1539/) Steal Web Session Cookie |
| 3 | 2026-07-16 11:48:07 local | Security `sec-008` | Object access (4663) on the same `Cookies` file — corroborates step 2 | T1539 |
| 4 | 2026-07-16 11:48:09 local | Sysmon `smon-008` | Staged file `net_cache.dat` created in `%TEMP%` | T1539 (staging) |
| 5 | 2026-07-16 11:48:37 local (16:48:37 UTC) | Sysmon `smon-009` | Outbound connection from `FABRIKAM-WKS042` to `203.0.113.77:443` — cookie exfil | [T1041](https://attack.mitre.org/techniques/T1041/) Exfiltration Over C2 Channel |
| 6 | 2026-07-17T14:22:18Z | Azure AD sign-in `sig-008` | Sign-in as `sarah.chen@fabrikam.com` from `203.0.113.77` (Bucharest), unrecognized device/browser, `authenticationRequirement: singleFactorAuthentication` despite the tenant otherwise enforcing MFA (see `sig-001`/`sig-003`/`sig-005`/`sig-007` for her normal MFA-enforced baseline), `riskState: confirmedCompromised` | [T1550.004](https://attack.mitre.org/techniques/T1550/004/) Use Alternate Authentication Material: Web Session Cookie |
| 7 | 2026-07-17T14:24:02Z | Azure AD audit `aud-004` | Same session (`correlationId 8f2a1c4e-...`) registers a new MFA method (Authenticator app) on Sarah's account — attacker-controlled persistence that survives a password reset alone | [T1098.005](https://attack.mitre.org/techniques/T1098/005/) Account Manipulation: Device Registration / MFA registration |
| 8 | 2026-07-17T14:26:47Z | Azure AD audit `aud-005` | Same session grants OAuth consent to a third-party app ("Mail Sync Pro") for `Mail.Read, Mail.ReadWrite, offline_access` — durable mailbox access independent of the stolen cookie's lifetime | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) Account Manipulation: Additional Cloud Credentials (illicit consent grant) |

## The "impossible travel" tell

- `sec-010`: `schen` unlocks `FABRIKAM-WKS042` in Chicago at 2026-07-17 08:12:50 local (13:12:50 UTC).
- `sig-007`: her own legitimate, MFA-satisfied sign-in from Chicago at 13:10:03 UTC — consistent
  with her sitting at her desk.
- `sig-008`: ~70 minutes later, a sign-in on the *same account* from Bucharest, Romania, with no
  fresh MFA prompt. She did not travel; the cookie did.

## Identities and assets involved

- **Victim:** Sarah Chen — `sarah.chen@fabrikam.com` / `FABRIKAM\schen` / `FABRIKAM-WKS042`
- **Attacker infrastructure:** `203.0.113.77` (both the Sysmon exfil destination and the Azure AD
  sign-in source IP — the strongest single pivot in the dataset)
- **Malicious OAuth app:** "Mail Sync Pro" (fictional, attacker-controlled service principal)
- **Uninvolved (noise) identities:** James Okafor, Priya Nair, Thomas Ward — all events under these
  names/hosts are background activity, not part of the attack chain. `sig-011` (failed sign-in
  attempt against `james.okafor@fabrikam.com` from `192.0.2.55`) is a separate, unrelated
  credential-stuffing attempt — a common real-world red herring.

## What "solving" this looks like

A complete write-up should: (1) identify the cookie-theft-and-replay chain end to end, (2) name the
pivot IP `203.0.113.77` as the link between endpoint and cloud, (3) flag the MFA-bypass indicator
(`authenticationRequirement: singleFactorAuthentication` on an otherwise MFA-enforced account) as
the key cloud-side detection signal, and (4) call out both post-hijack persistence actions (new MFA
method + OAuth consent) as needing remediation beyond a simple password reset.
