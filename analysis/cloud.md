---
source: logs/azuread_signin.jsonl, logs/azuread_audit.jsonl
analyst: cloud-analyst
generated: 2026-07-21
---

# Cloud Analysis (Azure AD Sign-in + Audit)

## Timeline

Times are UTC, matching the `createdDateTime`/`activityDateTime` fields in both source files.

| Time | Event | Detail |
|---|---|---|
| 07-14 13:01 – 07-17 13:10 | Routine MFA-satisfied sign-ins | schen, jokafor, pnair, tward — all from `198.51.100.23` (corporate egress), consistent devices, `authenticationRequirement: multiFactorAuthentication` throughout |
| 07-14 15:30 | aud-001 | pnair self-service password reset — noise |
| 07-15 16:02 | aud-002 | tward adds jokafor to `Finance-ReadOnly` group — privilege change, looks like routine admin |
| 07-16 21:10 | aud-003 | tward updates pnair's `UsageLocation` — noise |
| 07-17 13:10:03 | sig-007 | schen's last **normal** sign-in — Chicago, WKS042, MFA satisfied — baseline immediately before the hijack |
| **07-17 14:22:18** | **sig-008 — anomalous** | schen, from `203.0.113.77` (Bucharest, RO), device `"Unknown"`, browser Chrome 124.0 (vs. her normal Edge), **`authenticationRequirement: singleFactorAuthentication`** (every other sign-in of hers is `multiFactorAuthentication`), `riskState: confirmedCompromised`, `riskLevelDuringSignIn: high`, yet `conditionalAccessStatus: success` |
| **07-17 14:24:02** | **aud-004 — same correlationId as sig-008** | schen (from `203.0.113.77`) registers a new MFA method (`PhoneAppNotification`) — attacker-controlled authenticator added |
| **07-17 14:26:47** | **aud-005 — same correlationId** | schen (from `203.0.113.77`) grants OAuth consent to **"Mail Sync Pro"** for `Mail.Read, Mail.ReadWrite, offline_access` |
| 07-17 19:58 – 07-18 12:40 | Routine sign-ins/admin actions | jokafor, tward (app role assignment, password reset) — noise |
| **07-18 14:03:51** | **sig-011 — separate anomaly** | Failed sign-in for **jokafor** from `192.0.2.55` (Amsterdam), errorCode 50126, `clientAppUsed: "Other clients"`, UA `python-requests/2.31` — looks like scripted/automated credential-stuffing, different account/IP/correlationId from the schen chain |
| 07-18 18:15 – 20:44 | Routine noise | pnair profile update, schen normal sign-in (post-incident) |

## IOCs

- Victim UPN: `sarah.chen@fabrikam.com`
- Attacker IP: `203.0.113.77` (Bucharest, RO)
- Shared `correlationId`: `8f2a1c4e-9b3d-4a7f-8e21-5c6f9d2b7a10` (links sig-008 → aud-004 → aud-005)
- Malicious/unauthorized app: **"Mail Sync Pro"** (ServicePrincipal), scopes `Mail.Read, Mail.ReadWrite, offline_access`
- Attacker-added MFA method: `PhoneAppNotification`
- Unrelated secondary IOC: `192.0.2.55` (Amsterdam) targeting `james.okafor@fabrikam.com`
- Baseline corporate egress IP (for contrast): `198.51.100.23`

## ATT&CK Techniques

- **T1550.004** Use Alternate Authentication Material: Web Session Cookie — High (successful sign-in with `authenticationRequirement` downgraded to single-factor + `riskState: confirmedCompromised`, consistent with a replayed session token rather than a fresh credential logon)
- **T1078.004** Valid Accounts: Cloud Accounts — High (legitimate account, no new identity created)
- **T1098.005** Account Manipulation: Device Registration — High (aud-004, direct evidence)
- **T1098.001** Account Manipulation: Additional Cloud Credentials (illicit consent grant) — High (aud-005, direct evidence)
- **T1114.002** Email Collection: Remote Email Collection — Medium (scopes granted support ongoing mailbox access; no explicit read event logged here)
- Brute-force/credential-stuffing (sig-011) — Low/Medium, single failed attempt, no success observed

## Confidence

- Hijacked sign-in (sig-008) identification: **High**
- Persistence actions tied to the same session (aud-004/005): **High** — shared `correlationId`, same source IP, immediately following the hijack
- Impossible travel (sig-007 Chicago 13:10 UTC → sig-008 Bucharest 14:22 UTC, ~72 min apart): **High**
- sig-011 as unrelated noise: **Medium-high** — different account, IP, and correlationId, but worth confirming jokafor's own credentials weren't separately compromised
- aud-002/aud-006 admin actions: **Medium** — plausible routine admin work, not independently verified

## Correlation Hints

- Search endpoint sources for `203.0.113.77` as a network destination — if it shows up as a `DestinationIp`, that's the exfil path feeding the hijack.
- 14:22:18 UTC on 07-17 = **09:22:18 local** (`America/Chicago`) — check Sarah Chen's endpoint(s) around and before that time, keeping in mind stolen cookies can be replayed well after the actual theft.
- Map `sarah.chen@fabrikam.com` to her endpoint identity and look for browser cookie-store access or unusual outbound connections in the hours/days prior.
- Because persistence (new MFA method + mail-app consent) happened inside the hijacked session, a password reset alone won't remediate — endpoint findings should inform whether to revoke all sessions/refresh tokens and audit "Mail Sync Pro"'s actual usage.
