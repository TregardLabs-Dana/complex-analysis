# Plan: Investigate the `logs/` dataset (session hijacking lab)

## Context

The synthetic multi-source lab (`logs/`) built in the prior session is now populated with real
files. This plan replaces the earlier "build the lab" plan — that work is done and pushed
(commit `a562fd3`). The task now is the actual investigation: understanding what data is available
across the four sources before correlating them into a timeline. This directly answers the four
questions asked: what's in `logs/`, what event types exist per source, what fields support
correlation, and what a reasonable approach looks like.

Note: `analysis/answer-key-session-hijacking.md` exists but is intentionally not consulted here —
reading it before investigating defeats the purpose of the lab.

## 1. Log files and time ranges

| File | Source | Lines | Time range |
|---|---|---|---|
| `logs/sysmon.jsonl` | Sysmon (endpoint) | 15 | 2026-07-14 08:02:11 → 2026-07-18 13:20:44 (local, `America/Chicago`) |
| `logs/windows_security.jsonl` | Windows Security event log | 15 | 2026-07-14 07:58:03 → 2026-07-18 16:40:29 (local) |
| `logs/azuread_signin.jsonl` | Azure AD / Entra ID sign-in log | 12 | 2026-07-14T13:01:22Z → 2026-07-18T20:44:15Z (UTC) |
| `logs/azuread_audit.jsonl` | Azure AD / Entra ID audit log | 8 | 2026-07-14T15:30:00Z → 2026-07-18T18:15:02Z (UTC) |

All four sources cover the same rough calendar window (2026-07-14 through 2026-07-18), but two use
local host time and two use UTC — confirmed by inspecting the raw fields (`EventTime` vs
`createdDateTime`/`activityDateTime`), not assumed.

## 2. Event types present per source

- **Sysmon** (`EventID`): `1` ProcessCreate ×9, `3` NetworkConnect ×5, `11` FileCreate ×1
- **Windows Security** (`EventID`): `4624` successful logon ×9, `4625` failed logon ×2, `4663`
  object access ×1, `4672` special privileges assigned ×1, `4688` process creation ×2
- **Azure AD sign-in**: no discrete "type" field — every row is a sign-in attempt, differentiated by
  `status.errorCode` (0 = success), `conditionalAccessStatus`, `riskState`,
  `authenticationRequirement`, and `isInteractive`
- **Azure AD audit** (`activityDisplayName`): `Update user` ×2, and one each of `Reset password
  (self-service)`, `Reset password (by admin)`, `Add member to group`, `Add app role assignment to
  service principal`, `User registered security info`, `Consent to application`

The low counts of `4663`/`4688`/FileCreate/NetworkConnect relative to `4624`/ProcessCreate is itself
a signal worth noting — most activity is routine logons and normal process starts; the sparse event
types are where anomalies are more likely to cluster.

## 3. Correlation fields

- **Identity, no shared ID:** endpoint sources use `Computer`/`SubjectUserName`/`TargetUserName`/`User`
  (e.g. `FABRIKAM\schen`, `FABRIKAM-WKS042`); Azure AD sources use `userPrincipalName`
  (`sarah.chen@fabrikam.com`) and `deviceDetail.displayName`. There's no field that joins them
  directly — correlation has to go through the naming convention (`{first}.{last}@fabrikam.com` ↔
  `FABRIKAM\{first-initial}{last}`) plus matching hostnames in `deviceDetail`.
- **IP addresses:** present in `windows_security.jsonl` (`IpAddress`, mostly `-` for local console
  logons), `sysmon.jsonl` (`DestinationIp`, only on NetworkConnect events), and both Azure AD files
  (`ipAddress` on sign-in, `initiatedBy.user.ipAddress` on audit). IPs are the only field type that
  appears in all four sources and can bridge endpoint activity to cloud activity.
- **Timestamps:** usable for correlation only after normalizing — endpoint sources are local time,
  Azure AD sources are UTC (5-hour offset, `America/Chicago` in July/CDT).
- **`correlationId` (Azure AD only):** links a sign-in event to the audit events performed in that
  same session — the strongest correlation field available, but scoped to the two Azure AD files
  only.

## 4. Reasonable investigation approach

1. **Normalize time first.** Convert everything to one timezone (UTC recommended) before comparing
   across sources — a 5-hour Sysmon/Security-vs-Azure AD skew will misorder events otherwise.
2. **Scan the Azure AD sign-in log for outliers** — `riskState`, `riskLevelDuringSignIn`, and
   `authenticationRequirement` are the most legible anomaly signals in this dataset; a sign-in with
   an unexpected `authenticationRequirement` value relative to a user's other sign-ins is worth a
   closer look.
3. **Pivot on `correlationId`** from any flagged sign-in into `azuread_audit.jsonl` to see what
   actions were taken in that session.
4. **Pivot on IP address** from the flagged sign-in into `sysmon.jsonl`'s `DestinationIp` field —
   if the same IP shows up as a NetworkConnect destination on an endpoint, that's the bridge between
   cloud and endpoint activity.
5. **Walk backward on that endpoint** through `sysmon.jsonl` and `windows_security.jsonl` (by
   `Computer` + account, ordered by time) to find what preceded the network connection — this is
   where the sparse ProcessCreate/FileCreate/object-access events matter more than the common ones.
6. **Assemble one normalized, cross-source timeline** before drawing conclusions, rather than
   reasoning about each file in isolation.

## Verification

No code changes in this plan — verification is that the numbers above (line counts, EventID/
activityDisplayName counts, min/max timestamps) were pulled directly from the files with
grep/wc, not recalled from memory, so they reflect the actual current state of `logs/`.
