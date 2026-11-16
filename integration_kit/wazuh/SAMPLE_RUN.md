# Wazuh: sample run (2026-11-08)

A full run of the reference consumer against the official Wazuh indexer: what was set up, the commands, the output,
and what HuntCompiler recorded. Use it to know what a good run looks like before you run your own (§7).

## 1. Setup

| Piece | What was used |
|---|---|
| Wazuh indexer | Official image `wazuh/wazuh-indexer:4.14.7` (OpenSearch **2.19.5**), single node, configuration from the `wazuh-docker` repository at tag `v4.14.7`. TLS certificates from the official generator (`wazuh/wazuh-certs-generator:0.0.4`), HTTPS with the root CA, basic authentication. |
| Index mapping | The official Wazuh template (`extensions/elasticsearch/7.x/wazuh-template.json`, tag `v4.14.7`), loaded as Filebeat loads it (`PUT _template/wazuh`). `data.win.eventdata.*` fields are `keyword`, `timestamp` is `date`. |
| Events | 22 Windows events in the index `wazuh-archives-4.x-2026.11.08`, in the format Wazuh's eventchannel decoder writes (example in §4): Sysmon 1, 3, 6, 7, 22, Security 4624/4625, System 7045. Each matching event has a near-miss twin that must **not** match. |
| HuntCompiler | Version 0.4.0, API on PostgreSQL 16, the sample tenant `tencongty` from `config/tenant_manifest.yaml`. Lab intelligence: one exposed account, one KEV CVE on FortiOS, and LOLDrivers, HijackLibs, LOLRMM and OSV entries with lab names. Result: **5 packs, 12 tasks** (V1, V2, V4, V5, V6). |
| Consumer | `python -m integration_kit.reference_consumer cycle` with the settings in §2. |

All names, hosts and hashes are lab values (`*.example`, RFC 5737 and private addresses, synthetic hashes). The lab
used the indexer's `admin` user from the official compose file; in production use the read-only user from
[GUIDE.md](GUIDE.md) §1.

## 2. Consumer settings

```bash
HC_KIT_BASE_URL=http://127.0.0.1:8099          # lab only; production is https://
HC_KIT_ALLOW_HTTP=true                         # lab only
HC_KIT_TENANT=tencongty
HC_KIT_API_TOKEN=<tenant API token>
HC_KIT_HMAC_SECRET=<tenant HMAC secret>
HC_KIT_STATE_DIR=./hc-kit-state
HC_KIT_PLATFORM=wazuh
HC_KIT_WAZUH_URL=https://127.0.0.1:9200
HC_KIT_WAZUH_INDEX=wazuh-archives-*
HC_KIT_WAZUH_USER=admin                        # lab only; use a read-only user
HC_KIT_WAZUH_PASSWORD=<password>
HC_KIT_WAZUH_CA_BUNDLE=./certs/root-ca.pem
HC_KIT_TELEMETRY=sysmon:1,sysmon:3,sysmon:6,sysmon:7,sysmon:13,sysmon:22,windows_security:4624,windows_security:4625,windows_system:7045
HC_KIT_PLACEHOLDERS_FILE=./placeholders.json   # {"EDGE_DEVICE_INTERNAL_IPS": ["10.20.0.1"]}
HC_KIT_DIRECTORY_CSV=./directory.csv           # upn,sam,mail — resolves the exposed account locally
```

## 3. Output

```text
$ python -m integration_kit.reference_consumer cycle
2026-11-08 19:03:26,198 INFO hc_kit pull: {'queued': 5, 'duplicate': 0, 'rejected': 0}
2026-11-08 19:03:26,273 INFO hc_kit.runner pack 0d6bf841-04a6-4c41-88b3-dd8d26739197: sighting=True evaluable=True feedback=recorded
2026-11-08 19:03:26,368 INFO hc_kit.runner pack 22524d37-4011-45e2-a8bc-9e85ad6ed563: sighting=True evaluable=True feedback=recorded
2026-11-08 19:03:26,389 INFO hc_kit.runner pack 4322b3a5-2f20-4254-8db0-c5cd0a65a377: sighting=True evaluable=True feedback=recorded
2026-11-08 19:03:26,427 INFO hc_kit.runner pack b17bef2a-bb14-45a3-af30-320df792b12b: sighting=True evaluable=True feedback=recorded
2026-11-08 19:03:26,506 INFO hc_kit.runner pack f89848a6-53c2-44d1-a608-ee33c0f3f39d: sighting=True evaluable=True feedback=recorded
```

Hits per task, against the events placed in the index:

| Task | Matching events | Must not match | Expected | Actual |
|---|---|---|---|---|
| `v4-tunnel-dns` | `hc-test.trycloudflare.com`; `HC-TEST2.TRYCLOUDFLARE.COM` (upper case) | `www.example.com` | 2 | 2 |
| `v4-script-host-bot-api` | `powershell.exe` resolving `api.telegram.org` | `chrome.exe` resolving it | 1 | 1 |
| `v4-unapproved-rmm-process` | `labrmm.exe` started | `AnyDesk.exe` (approved in the manifest) | 1 | 1 |
| `v4-unapproved-rmm-dns` | `relay.labrmm.example` | — | 1 | 1 |
| `v1-exposed-account-failed-logons` | 4625 for `anguyen` (the exposed account, resolved from the directory) | 4625 for `bthanh` | 1 | 1 |
| `v2-edge-network-logon` | 4624 type 3 from `10.20.0.1` (the edge appliance) | from `10.30.0.5` | 1 | 1 |
| `v2-edge-inbound-admin-ports` | port 445 accepted from `10.20.0.1` | — | 1 | 1 |
| `v5-loldrivers-hash-load` | known driver hash, upper case as Sysmon writes it | — | 1 | 1 |
| `v5-unsigned-driver-outside-drivers-dir` | unsigned driver in `AppData\Local\Temp` | unsigned driver in `System32\drivers` | 1 | 1 |
| `v5-kernel-service-unusual-path` | 7045 driver service in `ProgramData` | 7045 driver service in `System32\drivers` | 1 | 1 |
| `v5-hijacklibs-sideload` | unsigned `version.dll` in `Windows\Temp\lab` | signed `version.dll` in `System32` | 1 | 1 |
| `v6-malicious-package-install` | `npm install lab-evil-pkg` | `npm install express` | 1 | 1 |

Confirmed on this indexer version: `term` and `wildcard` with `case_insensitive: true`, placeholder substitution
(`${HC_EDGE_DEVICE_INTERNAL_IPS}`), local resolution of an exposed-account reference, and the time-range filter.

Report for the V4 pack (`hc-kit-state/done/<pack_id>.json`, first task, query omitted):

```json
{
  "pack_id": "22524d37-4011-45e2-a8bc-9e85ad6ed563",
  "attack_vector": "lots_rmm_tunnel", "severity": "high", "confidence_score": 65,
  "sighting": true, "evaluable": true, "feedback_status": "recorded",
  "auto_block_hint": false,
  "auto_block_note": "hint only: blocking needs a human decision; this consumer never blocks",
  "tasks": [{
    "task_id": "v4-tunnel-dns", "hits": 2, "evaluable": true, "broken": false, "notes": [],
    "samples": [
      {"_id": "gRcGu6EBnPHUDLmp8OBi", "agent": {"id": "002", "name": "lab-ws-02"}, "timestamp": "2026-11-08T10:00:16.440+0000"},
      {"_id": "gBcGu6EBnPHUDLmp8OBh", "agent": {"id": "001", "name": "lab-ws-01"}, "timestamp": "2026-11-08T09:59:16.440+0000"}
    ]
  }]
}
```

The report stays on the consumer side. HuntCompiler only received `sighting` and `evaluable` for each pack:

```text
seq=1 identity_aitm_infostealer  sighting=True evaluable=True  cluster sightings=1
seq=2 edge_device_exploit        sighting=True evaluable=True  cluster sightings=1
seq=3 byovd_dll_sideload         sighting=True evaluable=True  cluster sightings=1
seq=4 lots_rmm_tunnel            sighting=True evaluable=True  cluster sightings=1
seq=5 supply_chain_seo           sighting=True evaluable=True  cluster sightings=1
```

## 4. How Wazuh stores a Windows event

One of the 22 events, as indexed:

```json
{
  "timestamp": "2026-11-08T10:05:41.446+0000",
  "agent": {"id": "001", "name": "lab-ws-01"},
  "decoder": {"name": "windows_eventchannel"},
  "location": "EventChannel",
  "data": {"win": {
    "system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "22",
               "channel": "Microsoft-Windows-Sysmon/Operational"},
    "eventdata": {"queryName": "hc-test.trycloudflare.com",
                  "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"}
  }}
}
```

The decoder stores every backslash of an event value **doubled**: the value of `image` above is
`C:\\Windows\\System32\\...`. Wazuh's own ruleset matches paths that way (for example
`ruleset/rules/0800-sysmon_id_1.xml`).

## 5. What the first run found (fixed, D-53)

The first run, with the queries as shipped until then, got three tasks wrong:

| Task | Expected | First run | Effect |
|---|---|---|---|
| `v5-unsigned-driver-outside-drivers-dir` | 1 | 2 | false positive: a driver in `System32\drivers` was reported |
| `v5-kernel-service-unusual-path` | 1 | 2 | false positive: same for a 7045 service |
| `v5-hijacklibs-sideload` | 1 | 0 | missed detection: `Windows\Temp\` never matched |

Patterns with a single backslash cannot match a value that holds two. Single-segment patterns such as
`*\powershell.exe` still matched by chance, which is why only multi-segment paths failed. The same problem made the
V3 ClickFix task `v3-runmru-paste` (registry path `\Software\Microsoft\...\RunMRU`) unable to match on Wazuh.

Fix: the Wazuh DSL emitter doubles every literal backslash, and the test harness evaluates queries against values
stored the Wazuh way. The V5 part of the pack now carries:

```json
{"wildcard": {"data.win.eventdata.imageLoaded": {"case_insensitive": true,
  "value": "C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\drivers\\\\\\\\*"}}}
```

That is the wildcard for `C:\\Windows\\System32\\drivers\\*`, each stored backslash escaped once for the wildcard
syntax and once more for JSON. The second run (§3) has every task right. Splunk and Elastic queries are unchanged.
Packs built before the fix are re-issued with the corrected queries at the next pack build.

## 6. Feedback is first-answer-wins

HuntCompiler keeps the first feedback for each pack. If you run the consumer before the test event exists, the pack is
recorded as "nothing found" and a later run cannot change it. Create the event first, then run the consumer.

## 7. Run it on your Wazuh

1. Meet the prerequisites in [GUIDE.md](GUIDE.md) §1 (archives, Sysmon with DNS events, a read-only user).
2. On a Windows endpoint with Sysmon, create a harmless matching event: `Resolve-DnsName hc-test.trycloudflare.com`.
   The name does not exist, and that is fine: Sysmon still logs the DNS query (event 22).
3. Confirm it is indexed: in the dashboard, search `wazuh-archives-*` for
   `data.win.eventdata.queryName: hc-test.trycloudflare.com`.
4. Run `python -m integration_kit.reference_consumer cycle` and open the report for the V4 pack in
   `<state_dir>/done/`: `v4-tunnel-dns` should show `hits: 1` or more, and the console should say
   `sighting=True ... feedback=recorded`.
