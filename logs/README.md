# Investigation lab dataset

Synthetic, multi-source log dataset for practicing the correlation workflow described in the repo's
`CLAUDE.md`. **All identities, hostnames, and IP addresses are fictional.** IP ranges are drawn from
RFC 5737 documentation blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 1918
private space (`10.20.30.0/24`) — none of it is real, routable infrastructure.

This is a lab, not a live incident. A background story and event chain are hidden in here somewhere;
finding it is the exercise. Ground truth lives in `analysis/answer-key-session-hijacking.md` — avoid
opening that until you've drawn your own conclusions.

## Files and time ranges

| File | Source | Events | Time range |
|---|---|---|---|
| `sysmon.jsonl` | Sysmon (endpoint) | 15 | 2026-07-14 08:02 – 2026-07-18 13:20 (local) |
| `windows_security.jsonl` | Windows Security event log | 15 | 2026-07-14 07:58 – 2026-07-18 16:40 (local) |
| `azuread_signin.jsonl` | Azure AD / Entra ID sign-in log | 12 | 2026-07-14T13:01Z – 2026-07-18T20:44Z (UTC) |
| `azuread_audit.jsonl` | Azure AD / Entra ID audit log | 8 | 2026-07-14T15:30Z – 2026-07-18T18:15Z (UTC) |

## Timestamp formats — deliberately inconsistent

- `sysmon.jsonl` and `windows_security.jsonl` use **local host time** (`America/Chicago`, CDT =
  UTC-5 in July), formatted `YYYY-MM-DD HH:mm:ss`, in an `EventTime` field.
- `azuread_signin.jsonl` and `azuread_audit.jsonl` use **UTC**, ISO 8601 with a `Z` suffix, in
  `createdDateTime` / `activityDateTime` fields.

To line up an endpoint event with a cloud event, add 5 hours to the local endpoint time. This mirrors
a real, common friction point: on-prem/endpoint tooling often logs in local host time while
Microsoft Graph/Entra APIs always return UTC.

## Identity and asset mapping

There is no shared ID between the endpoint sources and Azure AD — correlate by convention:

| Endpoint identity | Azure AD identity | Host |
|---|---|---|
| `FABRIKAM\schen` | `sarah.chen@fabrikam.com` | `FABRIKAM-WKS042` |
| `FABRIKAM\jokafor` | `james.okafor@fabrikam.com` | `FABRIKAM-WKS017` |
| `FABRIKAM\pnair` | `priya.nair@fabrikam.com` | `FABRIKAM-WKS029` |
| `FABRIKAM\adm-tward` | `thomas.ward@fabrikam.com` | `FABRIKAM-DC01` |

Convention used throughout: `{firstname}.{lastname}@fabrikam.com` in Azure AD ↔
`FABRIKAM\{first-initial}{lastname}` on endpoints.

## Other correlation fields

- **IP addresses:** `198.51.100.23` is Fabrikam's corporate internet egress — legitimate Azure AD
  sign-ins from any Fabrikam user should show this IP. Anything else in the sign-in log is either
  unrelated internet noise or worth a second look.
- **`correlationId` (Azure AD only):** sign-in and audit events that are part of the same session
  share a `correlationId` — use it to link a sign-in to the actions taken during it.
- Sysmon and Windows Security don't share a native ID with each other either; correlate by
  `Computer` + account name + close timestamps (within a second or two, since a single action often
  produces one event in each log).

## Schemas

**Sysmon** (`EventID` 1 = ProcessCreate, 3 = NetworkConnect, 11 = FileCreate):
`id, EventID, EventTime, Computer, User, Image, ParentImage, CommandLine, DestinationIp, DestinationPort, TargetFilename`
(unused fields are `null` per event type).

**Windows Security** (`EventID` 4624 = successful logon, 4625 = failed logon, 4663 = object access,
4672 = special privileges assigned, 4688 = process creation):
`id, EventID, EventTime, Computer, SubjectUserName, TargetUserName, LogonType, IpAddress, ProcessName, ObjectName`

**Azure AD sign-in log:**
`id, createdDateTime, userPrincipalName, ipAddress, location, deviceDetail{displayName, operatingSystem, browser}, status{errorCode, failureReason}, conditionalAccessStatus, riskState, riskLevelDuringSignIn, isInteractive, authenticationRequirement, correlationId, appDisplayName, clientAppUsed`

**Azure AD audit log:**
`id, activityDateTime, activityDisplayName, category, result, initiatedBy{user{userPrincipalName, ipAddress}}, targetResources[{type, displayName, modifiedProperties}], correlationId`

## Suggested investigation approach

1. Start wherever the earliest anomaly is easiest to spot — usually the Azure AD sign-in log, since
   `riskState`, `riskLevelDuringSignIn`, and `authenticationRequirement` are the most human-readable
   red flags in this dataset.
2. Pull the `correlationId` off any suspicious sign-in and check `azuread_audit.jsonl` for actions
   taken in that same session.
3. Map the sign-in's `ipAddress` back to `sysmon.jsonl` — does that IP show up anywhere as a
   `DestinationIp`? That's your endpoint-to-cloud pivot.
4. Once you have a candidate endpoint and account, walk `sysmon.jsonl` and `windows_security.jsonl`
   backward from that timestamp (remembering the UTC/local offset) to find how the attacker got the
   material they later used in the cloud.
5. Build a single timeline across all four sources, normalized to one timezone, before drawing
   conclusions.
