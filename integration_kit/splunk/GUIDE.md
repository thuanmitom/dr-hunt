# Splunk

Packs do not carry SPL. The consumer converts each task's Sigma rule with pySigma's Splunk backend
(`sysmon_pipeline()` + `splunk_windows_pipeline()`, owner decision IQ1, 2026-11-05), after substituting placeholders
in the Sigma rule, so a placeholder becomes a native `Field IN ("a", "b")`.

## 1. Prerequisites

* **Splunk Add-on for Sysmon** and **Splunk Add-on for Microsoft Windows** on the search head, so Sysmon fields keep
  their names (`Image`, `CommandLine`, `ParentImage`, `TargetObject`, `QueryName`...) and events carry `EventCode`.
* **Source naming.** The converted SPL filters on `source="WinEventLog:Microsoft-Windows-Sysmon/Operational"` (and
  `WinEventLog:Security`, `WinEventLog:System`). If your inputs use rendered XML (`renderXml = true`), set
  `HC_KIT_SPLUNK_SOURCE_STYLE=xml` to use `XmlWinEventLog:` instead.
* **A token for a dedicated role** with the `search` capability and access only to the Windows indexes.

## 2. Settings

```bash
HC_KIT_PLATFORM=splunk
HC_KIT_SPLUNK_URL=https://splunk.internal:8089      # management port (REST)
HC_KIT_SPLUNK_TOKEN=<authentication token>
HC_KIT_SPLUNK_INDEX=wineventlog                     # optional; empty = the role's default indexes
HC_KIT_SPLUNK_SOURCE_STYLE=classic                  # or xml
HC_KIT_SPLUNK_CA_BUNDLE=/etc/ssl/splunk-ca.pem
HC_KIT_TELEMETRY=sysmon:1,sysmon:3,sysmon:6,sysmon:7,sysmon:11,sysmon:13,sysmon:22,windows_security:4624,windows_security:4625,windows_system:7045
```

## 3. What is sent

`POST <url>/services/search/jobs/export` with `output_mode=json` and:

```
search earliest=-<lookback>d latest=now [index=<index>] (<converted SPL>) | stats count
```

The converted expression is wrapped in parentheses so the time and index terms cannot change its meaning. Splunk
matches field values case-insensitively in the `search` command, as Sigma requires.

## 4. Live check (to mark this guide Verified)

1. `python -m integration_kit.reference_consumer convert pack.json --platform splunk`, then paste one query into the
   Splunk search bar: it must run and return the events you expect.
2. Generate a harmless matching event on a test endpoint, run `cycle`, and confirm `hits > 0` in the local report and
   the feedback recorded by HuntCompiler.
