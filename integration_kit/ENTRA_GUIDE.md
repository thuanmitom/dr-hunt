# Checking exposed accounts in Entra ID sign-in logs

**Status: documentation only (D-69).** Nothing in this guide is part of a pack, a template or a test. The queries are
examples: field names depend on the integration and its version, so confirm them on your own data before relying on a
result.

## 1. Why this check exists

A credential-exposure pack (vector V1) tells you which of your accounts appeared in a leak. It carries
`affected_accounts` (HMAC refs, never the account names) and one hunting task: failed on-prem Windows logons (event 4625)
for those accounts. Packs no longer carry the cloud sign-in check, because it was written only in Defender KQL (D-63).
If your accounts sign in to Microsoft 365, the cloud sign-in log is where a leaked password is most likely to be tried.
This guide shows how to run that check yourself.

## 2. Prerequisites

- **Sign-in logs exported from Entra ID.** Exporting sign-in logs through Microsoft Graph or diagnostic settings
  requires an Entra ID P1 or P2 licence. The app registration that reads them needs `AuditLog.Read.All` and
  `Directory.Read.All`, read-only.
- **The logs in your SIEM:**
  - **Wazuh:** the Microsoft Graph module (`ms-graph`) with resource `auditLogs` and relationship `signIns`.
  - **Elastic:** the Microsoft Entra ID integration (sign-in logs).
  - **Splunk:** the Splunk Add-on for Microsoft Cloud Services or for Microsoft Azure, with the sign-in input.
- **A directory export** for the reference consumer (`HC_KIT_DIRECTORY_CSV`, columns `upn,sam,mail`), so that the refs
  can be resolved to user principal names on your side.

## 3. Get the list of exposed accounts (stays on your side)

The reference consumer already resolves the refs when it runs a pack. To print the UPNs of one pack:

```python
import json
from integration_kit.reference_consumer.accounts import load_directory, resolve

pack = json.load(open("pack.json", encoding="utf-8"))
res = resolve(pack["affected_accounts"], load_directory("directory.csv"), "<tenant HMAC secret>")
print(res.upns, f"({res.unresolved} ref(s) not in the directory)")
```

Never send these names, or anything you find in your logs, back to HuntCompiler. Feedback carries `sighting` and
`evaluable` only, and this check is not a pack task, so it does not change the feedback.

## 4. What to look for

Search the pack's lookback window (14 days by default) for sign-ins of those accounts with these error codes:

| Code | Meaning | What it tells you |
|---|---|---|
| `50126` | Invalid user name or password | Someone is trying the leaked password and it no longer works. Good, but watch for more attempts. |
| `50053` | Account locked by smart lockout, or sign-in from a blocked IP | Repeated guessing or password spraying. |
| `50074`, `50076` | Strong authentication (MFA) required | **The password was correct**; only MFA stopped the sign-in. Treat the account as compromised. |
| `500121` | Strong authentication failed or was denied | The attacker had the password and is pushing MFA (possible MFA fatigue). Treat as compromised. |
| `0` | Success | Check successful sign-ins after the leak date from unusual countries, IPs or devices. |

For `50074`, `50076`, `500121` or an unexpected success, a person should:
1. reset the password;
2. revoke the user's sessions and refresh tokens;
3. review the MFA methods registered on the account;
4. review mailbox rules and recent consent grants.

HuntCompiler never does any of this (no SOAR features).

## 5. Example queries

Replace the account list with your UPNs. Then confirm the field names first: in Elastic check the index mapping, in
Splunk run `| fieldsummary`, in Wazuh open one decoded sign-in event.

**Wazuh** (Discover, DQL). The module stores the Graph `signIn` object under `data.ms-graph`:

```
data.ms-graph.userPrincipalName : ("a.nguyen@example.com" or "b.tran@example.com")
and data.ms-graph.status.errorCode : (50126 or 50053 or 50074 or 50076 or 500121)
```

**Elastic** (Kibana, KQL). Older Filebeat-module data keeps a `properties` level; newer integration versions may not:

```
azure.signinlogs.properties.user_principal_name : ("a.nguyen@example.com" or "b.tran@example.com")
and azure.signinlogs.properties.status.error_code : (50126 or 50053 or 50074 or 50076 or 500121)
```

**Splunk** (SPL). The sourcetype depends on the add-on (`azure:aad:signin` in the Azure add-on; the Cloud Services
add-on uses its own names):

```
index=<your index> sourcetype="azure:aad:signin"
  userPrincipalName IN ("a.nguyen@example.com", "b.tran@example.com")
| search "status.errorCode" IN (50126, 50053, 50074, 50076, 500121)
| stats count min(_time) as first max(_time) as last values(ipAddress) as ips by userPrincipalName "status.errorCode"
```

## 6. Limits

- These queries are not run or tested by the HuntCompiler project.
- Without an Entra ID P1/P2 licence there is no exportable sign-in log; the on-prem 4625 task in the pack still runs.
- Session-token replay, device-code phishing and OAuth consent abuse need other signals. They are not covered (Q6).
