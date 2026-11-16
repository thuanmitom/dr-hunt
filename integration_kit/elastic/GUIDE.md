# Elastic (Elasticsearch / Elastic Security)

Packs do not carry an Elastic query. The consumer converts each task's Sigma rule with pySigma's Elasticsearch
backend (owner decision IQ1, 2026-11-05), after substituting placeholders in the Sigma rule.

## 1. Query language

* **EQL (default, `HC_KIT_ELASTIC_LANGUAGE=eql`).** EQL's `:` and `like~` operators match case-insensitively, as Sigma
  requires. Sent as `POST <index>/_eql/search` with a `@timestamp` range filter. EQL needs `@timestamp` and
  `event.category` in the mapping; Elastic Agent and Winlogbeat data have both.
* **Lucene (`HC_KIT_ELASTIC_LANGUAGE=lucene`).** `query_string` wildcards are case-sensitive on keyword fields, so
  `*powershell*` misses `PowerShell` (the same problem HuntCompiler solved for Wazuh, DECISIONS.md D-25). Use it only
  where EQL is not available.

## 2. Field mapping

`HC_KIT_ELASTIC_PIPELINE` picks pySigma's ECS mapping:

* `ecs_windows` (default): current Elastic Agent / Winlogbeat ECS fields. Some process fields map to `.caseless`
  sub-fields (for example `process.executable.caseless`), which exist in Elastic Defend data. If your data lacks them,
  try `ecs_windows_old` or check the converted query against your data view.
* `ecs_windows_old`: older Winlogbeat field names.

Print the converted queries of a saved pack and run one in Kibana Dev Tools before enabling the consumer:

```bash
python -m integration_kit.reference_consumer convert pack.json --platform elastic
```

## 3. Settings

```bash
HC_KIT_PLATFORM=elastic
HC_KIT_ELASTIC_URL=https://es.internal:9200
HC_KIT_ELASTIC_INDEX=logs-*                 # or winlogbeat-*
HC_KIT_ELASTIC_API_KEY=<base64 id:key>      # an API key with read on that index pattern only
HC_KIT_ELASTIC_LANGUAGE=eql
HC_KIT_ELASTIC_PIPELINE=ecs_windows
HC_KIT_ELASTIC_CA_BUNDLE=/etc/ssl/es-ca.pem
HC_KIT_TELEMETRY=sysmon:1,sysmon:3,sysmon:6,sysmon:7,sysmon:11,sysmon:13,sysmon:22,windows_security:4624,windows_security:4625,windows_system:7045
```

EQL returns at most `size` events, so the consumer asks for `HC_KIT_MAX_HITS + 1` events (with sources filtered out)
to tell "many" from "too many".

## 4. Live check (to mark this guide Verified)

1. Convert a pack and run one query by hand in Dev Tools: it must parse and return the events you expect.
2. Generate a harmless matching event on a test endpoint, run `cycle`, and confirm `hits > 0` in the local report
   and the feedback recorded by HuntCompiler.
