# Wazuh

Packs carry a ready-made OpenSearch DSL query per task (`compiled_queries.wazuh_es_dsl`). The consumer sends it to
the Wazuh indexer unchanged, apart from placeholder substitution and a time-range filter.

## 1. Prerequisites (check these first)

1. **Archive every event.** By default Wazuh indexes only events that raised an alert (`wazuh-alerts-*`). Most raw
   Sysmon and Security events a hunt looks for never reach that index, so zero hits there means nothing.
   - Manager, `/var/ossec/etc/ossec.conf`: `<logall_json>yes</logall_json>` in `<global>`, then restart the manager.
   - Filebeat, `/etc/filebeat/filebeat.yml`: in the `wazuh` module set `archives: enabled: true`, then restart Filebeat.
   - Dashboard: create the index pattern `wazuh-archives-*`.
   Archiving every event costs disk; size the indexer for it.
2. **Sysmon on the endpoints**, forwarded through the Wazuh agent (`<localfile>` with
   `Microsoft-Windows-Sysmon/Operational`). Hunts use events 1, 3, 6, 7, 11, 13 and 22, and SHA256 hashing
   (`<HashAlgorithms>SHA256</HashAlgorithms>`) for events 1 and 6. Security 4624/4625 and System 7045 come from the
   Windows event channels.
3. **A read-only indexer user** for the consumer: a role with `indices:data/read/search` on `wazuh-archives-*`, mapped
   to a dedicated internal user. Never use `admin`.

## 2. Settings

```bash
HC_KIT_PLATFORM=wazuh
HC_KIT_WAZUH_URL=https://wazuh-indexer.internal:9200
HC_KIT_WAZUH_INDEX=wazuh-archives-*
HC_KIT_WAZUH_USER=hc-hunter
HC_KIT_WAZUH_PASSWORD=...
HC_KIT_WAZUH_CA_BUNDLE=/etc/ssl/wazuh-root-ca.pem     # the indexer's CA; TLS verification is never disabled
HC_KIT_TELEMETRY=sysmon:1,sysmon:3,sysmon:6,sysmon:7,sysmon:11,sysmon:13,sysmon:22,windows_security:4624,windows_security:4625,windows_system:7045
```

## 3. What is sent

`POST <url>/<index>/_search` with:

```json
{"query": {"bool": {"filter": [<task DSL query>, {"range": {"timestamp": {"gte": "now-<lookback>d"}}}]}},
 "size": 5, "sort": [{"timestamp": "desc"}], "track_total_hits": true,
 "_source": ["timestamp", "agent.id", "agent.name"]}
```

The DSL uses `term`/`wildcard` with `case_insensitive: true` on `data.win.eventdata.*` and pins
`data.win.system.channel` and `data.win.system.eventID`. `case_insensitive` needs OpenSearch 1.0 or later; it works
on Wazuh indexer 4.14.7 (OpenSearch 2.19.5).

Path values in the DSL use **doubled backslashes** (`C:\\Windows\\...`), because that is how Wazuh's eventchannel
decoder stores Windows event values (D-53). If you add your own placeholder values that contain a backslash, double it
the same way.

## 4. Tested run and your own check

[SAMPLE_RUN.md](SAMPLE_RUN.md) shows a complete run on Wazuh indexer 4.14.7: setup, commands, console output, hits
for all 12 tasks of 5 packs, the local report and the feedback HuntCompiler recorded. Its §7 is the short check to run
on your own Wazuh: a harmless DNS lookup of `hc-test.trycloudflare.com`, then one `cycle`.
