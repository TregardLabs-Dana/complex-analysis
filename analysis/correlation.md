---
source: analysis/endpoint.md, analysis/cloud.md
analyst: correlation
generated: 2026-07-21
---

# Correlation Report: Endpoint × Cloud

## 1. Timeline Alignment

Normalizing everything to UTC (endpoint times are `America/Chicago`, +5h to convert):

| UTC Time | Source | Event |
|---|---|---|
| 07-16 16:47:52 | Endpoint | Encoded PowerShell launched on `FABRIKAM-WKS042` (schen) |
| 07-16 16:48:05–09 | Endpoint | Edge `Cookies` file copied → staged as `net_cache.dat` |
| 07-16 16:48:37 | Endpoint | Exfil connection: `powershell.exe` → `203.0.113.77:443` |
| *(21h 33m gap — no activity in either source tied to this chain)* | | |
| 07-17 13:10:03 | Cloud | schen's last legitimate MFA-satisfied sign-in (baseline) |
| 07-17 ~13:12:50 | Endpoint | schen unlocks `FABRIKAM-WKS042` locally (Chicago) |
| 07-17 14:22:18 | Cloud | **Hijacked sign-in** — schen from `203.0.113.77`, single-factor, `confirmedCompromised` |
| 07-17 14:24:02 | Cloud | New MFA method registered (persistence) |
| 07-17 14:26:47 | Cloud | OAuth consent granted to "Mail Sync Pro" |

The two sources slot together cleanly once normalized: theft happens Thursday afternoon, the stolen
cookie sits idle for about a day, then gets used Friday afternoon while the real Sarah Chen is
independently logged into her own workstation in Chicago — the endpoint and cloud sessions are
simultaneous but geographically impossible for one person.

## 2. User Correlation

| User | Endpoint activity | Cloud activity | Assessment |
|---|---|---|---|
| **schen** | Malicious PowerShell chain + routine logons | Routine MFA sign-ins + hijacked sign-in + persistence actions | **Center of the incident** — only user with anomalies on both sides, and they chain together |
| jokafor | One failed local logon (internal IP `10.20.30.117`) | One failed sign-in from `192.0.2.55` (Amsterdam), different timestamp | Same user, two unrelated-looking anomalies — likely coincidental (see Confidence), but not fully ruled out |
| pnair | Routine only | Routine only | No findings |
| tward (admin) | `Get-ADUser`/`Get-MsolUser` scripting | Group/role/password-reset admin actions | Routine admin, no direct tie to the schen chain |

## 3. IP Correlation

- **`203.0.113.77`** is the only IP shared across both sources: the Sysmon `NetworkConnect` destination
  on the endpoint side, and the sign-in/audit source IP on the cloud side. This is the single
  strongest pivot in the whole dataset — same infrastructure, both stages.
- `198.51.100.23` (corporate egress) appears only in cloud logs — endpoint `IpAddress` fields are
  mostly `-` (local console logons), so there's no direct endpoint-side equivalent to compare it
  against.
- jokafor's two anomalous IPs (`10.20.30.117` internal, `192.0.2.55` external) don't overlap with
  each other or with anything in the schen chain.

## 4. Attack Chain

- **Initial access: unknown — a gap, not a finding.** Neither source captures how the attacker got
  code execution on `FABRIKAM-WKS042` in the first place. The chain picks up already mid-execution at
  the encoded PowerShell launch.
- **Actions on endpoint:** obfuscated PowerShell stager → copies Edge's session-cookie database →
  stages it in `%TEMP%` → exfiltrates it to `203.0.113.77`.
- **Pivot to cloud:** ~21.5 hours later, the attacker replays the stolen cookie directly into Entra
  ID from the same IP, producing a valid, MFA-bypassing sign-in (the cookie already carries prior
  auth claims).
- **Ultimate objective:** durable access independent of the stolen cookie's lifetime — a new MFA
  method (survives a password reset alone) and an OAuth consent grant for
  `Mail.Read/Mail.ReadWrite/offline_access` (durable mailbox access, consistent with a BEC/mail-
  collection goal).

## 5. Confidence Assessment

**High confidence:**
- The theft → exfil → replay → persistence chain, anchored by the shared IP and the cloud-side
  `correlationId`.
- schen as the sole victim; the hijack is not a credential-based logon but a session/token replay.
- The persistence actions (MFA registration + OAuth consent) happened inside the hijacked session,
  not separately.

**Uncertain / unconfirmed:**
- Initial access vector — no evidence in either source.
- Whether jokafor's two anomalies are related to each other or to this incident (different IPs,
  different mechanisms, no shared correlationId or timing pattern).
- Whether "Mail Sync Pro" was actually used to read mail after consent (no mail-access telemetry
  available).
- Whether tward's admin activity (`Get-MsolUser`, group/role changes) is unrelated routine work or
  worth a second look — nothing ties it to the schen chain, but it also hasn't been positively
  cleared.

## 6. Gaps

Logs/telemetry that would materially help but aren't in this dataset:
- **Initial access telemetry** — email/phishing gateway logs, proxy/web logs, or an EDR detection
  prior to 07-16 16:47:52 to explain how the PowerShell got launched.
- **Network-layer detail** — DNS logs (did `203.0.113.77` resolve via a domain?) and full
  packet/proxy logs for the exfil connection and the later `s.ps1` download.
- **File hashes** — neither `net_cache.dat` nor the stager script has a hash in these sources,
  blocking threat-intel pivoting.
- **Mailbox/Exchange audit logs** (message trace, mailbox audit) — to confirm whether "Mail Sync
  Pro" actually accessed or exfiltrated mail after the consent grant.
- **Conditional Access policy configuration/logs** — to explain mechanically why
  `singleFactorAuthentication` was accepted despite an MFA-requiring policy (the sign-in log shows
  the *outcome*, not the policy evaluation).
- **Cloud App Security / OAuth app inventory** — to check whether "Mail Sync Pro" has been consented
  to elsewhere in the tenant or has other suspicious activity.
- **A second endpoint or identity for jokafor's cloud anomaly** — nothing here confirms or rules out
  whether his account is separately compromised.
