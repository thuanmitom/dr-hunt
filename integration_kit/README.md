# OutSight HuntCompiler — Integration Kit (Phase I)

Status: every piece is tested offline (fake platforms, real HuntCompiler API on PostgreSQL). **Wazuh** is tested
end to end on the official Wazuh indexer 4.14.7 ([sample run](wazuh/SAMPLE_RUN.md), 2026-11-08). **Elastic** and
**Splunk** each still need one run against a real instance.

HuntCompiler is an Internet-side API. It turns outside-in threat intelligence into signed **Hunting Pack v2.0**
documents: Sigma rules plus a ready-made Wazuh DSL query per task. It never runs hunts and never connects into your
network. This kit shows how a SIEM/SOAR consumes the packs:

```
HuntCompiler ──(pull: GET /api/v1/packs, or push webhook)──► reference consumer (your network)
                                                                │ 1. verify the HMAC signature
                                                                │ 2. re-validate the pack (JSON Schema + guardrails)
                                                                │ 3. substitute ${HC_*} placeholders from your own data
                                                                │ 4. run each task on Wazuh / Elastic / Splunk
                                                                │ 5. keep the hit details locally
HuntCompiler ◄──(POST /api/v1/feedback: pack_id, sighting, evaluable)──┘
```

**Supported platforms:** [Wazuh](wazuh/GUIDE.md), [Elastic](elastic/GUIDE.md), [Splunk](splunk/GUIDE.md).
Exposed accounts in Entra ID sign-in logs: [ENTRA_GUIDE.md](ENTRA_GUIDE.md) (documentation only, D-69).
Out of scope (owner decision, 2026-11-05): Zabbix, which cannot run log hunts, and Microsoft Defender XDR, whose own
integrations already cover it. Packs carry no KQL since D-63; a pack issued earlier may still hold `kql_defender`, and this kit never runs it.

## Security rules for every integration (not optional)

1. **Verify the signature** on the raw body: `sha256=HMAC_SHA256(secret, f"{timestamp}." + raw_body)`, timestamp
   within 300 s. For pulled items, the signed bytes are the canonical JSON of `pack`: keys sorted, no whitespace,
   UTF-8, non-ASCII characters kept. De-duplicate on `pack_id`.
2. **Re-validate every pack**, even with a valid signature, against `contracts/hunting_pack_v2.schema.json` plus the
   guardrails a schema cannot express (no `script`/`runtime_mappings` keys in DSL, size limits, declared placeholders,
   expiry). A compromised HuntCompiler host would sign anything (ARCHITECTURE.md §9, T4).
3. **Never block automatically.** `soar_playbook_hints.auto_block_pre_iocs` is a hint; blocking always needs a human
   decision. The reference consumer never blocks anything.
4. **Render AI text as plain text.** `threat_summary` lines starting `[AI-assisted summary]` and task descriptions
   starting `[AI-assisted]` come from an LLM that read attacker-controlled content.
5. **A huge hit count means a broken rule**, not a mass compromise. The consumer treats more than `HC_KIT_MAX_HITS`
   hits (default 1000) as broken: not a sighting, not evaluable, flagged for review.
6. **Send back only the two bits.** Hit counts, hosts, users and log lines stay in your network.

## Quick start (reference consumer)

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r integration_kit/requirements.txt
cp integration_kit/consumer.env.example consumer.env      # fill in, then:
set -a && . ./consumer.env && set +a
python -m integration_kit.reference_consumer cycle        # pull + hunt + feedback, once
python -m integration_kit.reference_consumer cycle --every 900   # or keep running
```

Run it from a host in your network that can reach both HuntCompiler (outbound HTTPS) and your SIEM API.
`python -m integration_kit.reference_consumer convert pack.json --platform splunk` prints the queries of a saved
pack without any network call.

## Settings (`HC_KIT_*`)

| Variable | Meaning |
|---|---|
| `HC_KIT_BASE_URL` | HuntCompiler URL, `https://`. Plain `http://` is accepted for `localhost` or a loopback address on the same machine (D-72); anywhere else only with `HC_KIT_ALLOW_HTTP=true`, for a lab |
| `HC_KIT_TENANT`, `HC_KIT_API_TOKEN`, `HC_KIT_HMAC_SECRET` | Your tenant slug, bearer token and HMAC secret (from the HuntCompiler operator) |
| `HC_KIT_CA_BUNDLE` | Optional CA bundle for HuntCompiler's TLS, e.g. Caddy's root certificate when HuntCompiler runs in a LAN with `HC_TLS_MODE=internal` |
| `HC_KIT_STATE_DIR` | Cursor, inbox, local reports (default `./hc-kit-state`) |
| `HC_KIT_PLATFORM` | `wazuh`, `elastic` or `splunk` |
| `HC_KIT_TELEMETRY` | Comma-separated telemetry you collect, e.g. `sysmon:1,sysmon:3,sysmon:13,sysmon:22,windows_security:4624,windows_security:4625,windows_system:7045` |
| `HC_KIT_PLACEHOLDERS_FILE` | JSON file with internal values, e.g. `{"EDGE_DEVICE_INTERNAL_IPS": ["10.0.0.1"]}` |
| `HC_KIT_DIRECTORY_CSV` | CSV export of your directory (`upn,sam,mail`) to resolve exposed accounts |
| `HC_KIT_MAX_HITS` | Above this, a task counts as a broken rule (default 1000) |
| `HC_KIT_<PLATFORM>_URL`, `_INDEX`, `_USER`, `_PASSWORD`, `_TOKEN` / `_API_KEY`, `_CA_BUNDLE` | Platform API access; see the guide |

## What the consumer does with each pack

* **Placeholders.** A task lists the placeholders it needs in `scope_placeholders`. Values come from
  `HC_KIT_PLACEHOLDERS_FILE`, except `AFFECTED_UPNS` and `AFFECTED_SAM_ACCOUNTS`, which come from resolving
  `affected_accounts[].ref` against your directory: `ref = HMAC_SHA256(HMAC_SHA256(secret, "account-ref/v1"),
  lower(account))`, tried for the UPN, the sAMAccountName and the mail of each user. A task whose placeholder has no
  value is not run and makes the pack not evaluable.
* **Telemetry.** A task is evaluable only if everything in its `required_telemetry` is in `HC_KIT_TELEMETRY`
  (`sysmon:<category>` from AI tasks counts as the matching Sysmon event id). Defender/Entra tags are ignored.
* **Feedback.** `sighting` is true if any task had hits. `evaluable` is true only if every task ran with its
  telemetry and none was broken. The local report in `<state_dir>/done/` keeps counts, the query sent and a few
  event ids for triage.

## Push instead of pull

Pull needs no inbound exposure and is the recommended path. If the operator configured `delivery.mode: push`:

```bash
python -m integration_kit.reference_consumer receive --host 127.0.0.1 --port 8088 --path /huntcompiler
python -m integration_kit.reference_consumer run          # from cron: hunts what arrived
```

Publish the receiver only through your TLS reverse proxy. It answers 202 (queued), 200 (duplicate), 401 (bad or
stale signature), 413 (over 1 MB) or 422 (pack refused by validation).

## Files

```
integration_kit/
  README.md                 this file
  consumer.env.example      settings template
  requirements.in / .txt    the consumer's own dependencies (hash-locked; independent of the HuntCompiler service)
  reference_consumer/       signing, validate, placeholders, accounts, convert, client, state, runner, receiver, adapters/
  wazuh/  elastic/  splunk/ platform guides
```
