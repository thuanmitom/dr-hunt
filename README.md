# OutSight HuntCompiler

Outside-in threat intelligence compiled into **signed, actionable hunting packs**, served as an API to any SIEM/SOAR
(pull, push webhook, 1-bit feedback), plus a Telegram digest and command bot for people.

**Status:** Phase T built (Telegram digest and bot, SSRF guard), not yet verified live. Before it: Phase 2b + 3 — leak monitoring and reference datasets on top of the AI-assisted compiler, Sigma translation, scoring, packs, dispatch and tenant API (Phases 1–2: infrastructure, contracts, collectors, pivoting). Phase 4 (n8n/Wazuh SOAR) is cancelled; integrations will be documented in the Integration Kit (Phase I).

The AI threat model is in [`docs/AI_RISK_ASSESSMENT.md`](docs/AI_RISK_ASSESSMENT.md). A full Vietnamese overview is in [`README.vi.md`](README.vi.md).
Specification, decisions, architecture and the Telegram design: [`SPEC.md`](SPEC.md), [`DECISIONS.md`](DECISIONS.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), [`TELEGRAM.md`](TELEGRAM.md).

## Architecture

```
 INTERNET (HuntCompiler host)                                              ║  TENANT LAN
                                                                           ║
 L1 Collectors ──► L2 Pivot / Unpack / Guardrails ──► L3 AI + Sigma ──► L4 Store / API / Dispatch
 CertStream        JARM, favicon mmh3, stager          Gemini (structured   PostgreSQL, Redis,
 URLScan, KEV      unpacker, whitelist (Tranco,        output) → Sigma →    Celery, FastAPI
 GitHub, OSV ...   MISP warninglists)                  pySigma → DSL / KQL        │
                                                                                  │  Hunting Pack v2.0 (HMAC)
                   tenant_manifest.yaml  (public facts only)                      │  pull (default) or push
                                                                           ║      ▼
                                                                           ║  Consumer SIEM/SOAR (any vendor) runs the
                                                                           ║  hunts itself (Integration Kit, Phase I)
                                     1-bit feedback  ◄═════════════════════╝  sighting true/false (+ evaluable)
```

L4 also feeds a Telegram digest and command bot for people (Phase T, below).

## Repository layout (Phase 1)

```
app/
  core/        config.py (HC_* settings) · crypto.py (Fernet, token hashing) · signing.py (wire HMAC contract)
  schemas/     enums.py · validators.py · hunting_pack.py (v2.0) · manifest.py · feedback.py
  db/          base.py · types.py (EncryptedString) · session.py · models/ (4 core tables + link table)
  services/    tenant_registry.py (manifest → tenants upsert)
  api/         main.py (health/readiness probes; pull + feedback routes arrive in Phase 3)
  worker/      celery_app.py (queues: default, collectors, compiler, dispatch)
migrations/    Alembic (async) — initial schema, verified upgrade/downgrade on PostgreSQL 16
contracts/     JSON Schemas for pack / feedback / manifest + a real example pack (ClickFix)
config/        tenant_manifest.yaml (sample)
scripts/       load_manifest.py · export_contracts.py
tests/         contract, manifest, signing and PostgreSQL integration tests
```

## Key design decisions

| # | Decision | Why |
|---|----------|-----|
| 1 | **Pull delivery is the default**, push is supported | Push needs an Internet-reachable consumer webhook, i.e. an inbound hole into the LAN. With pull, the SOAR polls `GET /api/v1/packs` outbound-only; the contract and signing are identical in both modes. |
| 2 | **HMAC over `timestamp + "." + raw body`** | Replay protection on top of `sha256=<hmac>`. Receivers verify the raw body (for example the n8n Webhook node with *Raw Body* on) and de-duplicate on `X-HuntCompiler-Pack-Id`. |
| 3 | **Guardrails live in the contract** | Packs are built from attacker-controlled content via an LLM. Validation rejects: non-global or over-broad IPs (< /24, < /48), all-zero JARM, `script`/`runtime_mappings` in OpenSearch DSL, `externaldata`/`http_request`/control commands in KQL, undeclared placeholders, and `auto_block_pre_iocs` below confidence 80. |
| 4 | **Zero-Internal-Access enforced by schema** | The manifest rejects RFC1918/CGNAT/ULA ranges. Host groups are expressed as `target_scope`; internal values (e.g. the VPN appliance's inside IP) as `${HC_EDGE_DEVICE_INTERNAL_IPS}`, substituted by the SOAR. |
| 5 | **`required_telemetry` + `evaluable`** | Zero hits without Sysmon 13 is *unknown*, not *clean*. Feedback stays anonymous but distinguishes the two. |
| 6 | **`content_sha256` uniqueness per tenant** | Re-compiling the same intelligence never re-sends a pack; `version`/`supersedes_id` track real changes; `seq` is a stable pull cursor. |
| 7 | **VARCHAR + CHECK enums** (not native PG ENUM) | Adding an attack vector or source is a normal transactional migration. |
| 8 | **Secrets by env-var reference, Fernet at rest** | Manifests never contain secrets; HMAC keys are encrypted (MultiFernet rotation); API tokens are stored as SHA-256 only. |
| 9 | **`redacted` flag on raw events** | Stealer-log / leak content must be stripped of credential material before persisting (personal-data law, liability). Phase 2 collectors must redact first. |
| 10 | **Hash-locked dependencies** | `requirements.txt` is generated from `requirements.in` with `uv pip compile --generate-hashes` (85 packages); the image installs with `--require-hashes`. |

## Data contracts

* **Hunting Pack v2.0** — `contracts/hunting_pack_v2.schema.json`. Core fields as specified
  (`schema_version`, `pack_id`, `timestamp`, `attack_vector`, `severity`, `confidence_score`,
  `mitre_attack`, `threat_summary`, `prevention_blocklist`, `internal_hunting_tasks`,
  `soar_playbook_hints`) plus additive extensions: `expires_at`, and per task `target_scope`,
  `required_telemetry`, `scope_placeholders`. Example: `contracts/examples/clickfix_pack.example.json`
  (its Sigma rules were compiled with pySigma for real; the Wazuh field mapping is a prototype until Phase 3).
* **Sighting feedback v1** — `contracts/sighting_feedback_v1.schema.json`: `pack_id`, `sighting`, `evaluable`, `evaluated_at`. No counts, hosts, users or log lines leave the tenant.
* **Wire headers** — `X-HuntCompiler-Timestamp`, `X-HuntCompiler-Signature: sha256=<hex>`, `X-HuntCompiler-Pack-Id`, `X-HuntCompiler-Tenant` (feedback). Tolerance: 300 s.

Regenerate schemas after changing a model: `python -m scripts.export_contracts`.

## Quick start

```bash
cp .env.example .env                   # fill passwords, Fernet key, tenant secrets
docker compose up -d --build           # postgres, redis, migrate, api, worker, beat, certstream
docker compose run --rm api python -m scripts.load_manifest config/tenant_manifest.yaml
curl -s http://127.0.0.1:8000/readyz   # {"postgres":"ok","redis":"ok"}
```

## Development

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q                                                    # unit tests
HC_TEST_DATABASE_URL=postgresql+asyncpg://user:pass@127.0.0.1:5432/hc_test pytest -q   # + migration/DB tests
ruff check . && ruff format --check .
```

Test suite on 2026-11-02: 170 tests, all passing with the PostgreSQL 16 integration tests (Alembic upgrade → downgrade →
upgrade and `alembic check` included). Before Phase T the suite had 82 tests; earlier README counts were not reliable.
Also verified in Phase 1: API probes, a Celery round-trip and the manifest loader CLI.
Not yet verified: the Docker image build and compose stack.

## Phase 2 — collectors, pivot, unpacker, guardrails

```
app/processors/  whitelist_filter.py · stager_unpacker.py · pivot.py (JARM, favicon mmh3, Shodan, AiTM score) · brand_matcher.py
app/collectors/  base.py (IntelSignal, polite HTTP) · urlscan.py (V1 AiTM, V3 ClickFix) · edge_exploits.py (V2 KEV/EPSS/
                 GitHub PoC/Nuclei, V6 fake-PoC heuristics) · certstream_watcher.py (own container) · tasks.py (Celery + beat)
app/services/    intel_store.py (idempotent insert) · tenant_context.py
```

Flow: collectors emit `IntelSignal` → `collectors.ingest_signals` stores it once (`ON CONFLICT DO NOTHING`) →
`processors.enrich_event` runs the whitelist, then JARM and favicon probes on hosts that survived it, and writes
`raw_payload.enrichment`. Clustering and pack compilation consume these events in Phase 3.

**Whitelist finding.** Checked against the bundled MISP warninglists, a parent-domain lookup reports
`random-abc.trycloudflare.com`, `evil.pages.dev`, `attacker.github.io` and `evil.ngrok-free.app` as Tranco
Top-1M sites. "Drop everything in Tranco 1M" would therefore whitelist the infrastructure Vectors 3 and 4 hunt for.
The filter instead returns `block` / `hunt_only` / `drop` per hostname: customer subdomains on shared platforms
(PSL private suffixes, LOTS entries) are blocked as exact FQDNs only; shared roots (`api.telegram.org`, `pages.dev`)
and popular sites (likely compromised, a common ClickFix host) become hunt-only; CDN/anycast ranges, public
resolvers, core Microsoft/Google domains and Tranco Top-10K are dropped; cloud-compute ranges are hunt-only.

**Safety rules in the code.** Exploit code and stagers are handled as text only, never executed; downloads are
size-capped; gzip output is bounded (decompression bombs); repositories that look like fake PoCs are not
downloaded; active probes only touch hosts that already look malicious; sweeps take a Redis single-flight lock.

**Tested** (74 tests): unpacker layers (EncodedCommand, FromBase64String+gzip, concatenation, char codes, carets,
backticks, reversed strings, XOR, defanged IOCs, bomb limit); whitelist decisions on synthetic data and on the real
warninglists; brand matcher (homoglyph, IDN, edit distance); KEV↔tech-tag matching; fake-PoC heuristics; clipboard-
lure and AiTM detection; Retry-After handling; JARM against a local TLS server.
*Correction (2026-11-02):* the repository has no tests for the brand matcher, AiTM scoring, clipboard-lure detection,
KEV↔tech-tag matching, fake-PoC heuristics, Retry-After handling or JARM against a TLS server. They are listed as a gap in
`CLAUDE.md` §5. JARM and favicon probing are now tested through the SSRF guard (Phase T).
**Not yet exercised against live APIs** (the build sandbox cannot reach URLScan, GitHub, CISA, FIRST or Shodan).
URLScan query templates (`HC_URLSCAN_*_QUERY`) depend on your plan's search syntax and should be tuned on first run.

**Delivered later in Phase 2b (see below):** Telegram CTI (Telethon) and leak APIs with credential redaction, OSV, and the LOLRMM /
LOLDrivers / HijackLibs / MalwareBazaar syncs.

## Phase 3 — compiler, packs, delivery

```
app/compiler/  fields.py · wazuh_dsl.py (case-insensitive DSL from pySigma's parse tree) · translate.py (+ KQL lint)
               harness.py (runs DSL on sample events) · templates.py (deterministic per-vector hunts)
               draft.py · prompt.py · llm.py (Gemini / any provider) · ai_compiler.py (gates) · scoring.py · tasks.py
app/services/  cluster_builder.py · ai_service.py (evidence, cache, audit) · pack_builder.py
app/dispatch/  dispatcher.py (HMAC push, back-off, dead letter)
app/api/       routes.py — GET /api/v1/packs (bearer), POST /api/v1/feedback (HMAC)
```

Schedules: clustering every 5 min, pack building every 10 min, push dispatch every minute.
A new pack version is issued only when its substance changes (tasks, blocklist, severity), never for
confidence drift alone. A second migration adds the `ai_compilations` audit table.

**Pull response:** `{"items": [{"seq", "timestamp", "signature", "pack"}], "next_cursor"}`; each `signature`
is `sha256=HMAC(secret, f"{timestamp}." + canonical_json(pack))`, verified exactly like push.
**Placeholder substitution (SOAR side):** in DSL, an array element equal to `${HC_X}` is replaced by the
list of values; in KQL, `${HC_X}` is replaced by comma-separated double-quoted values.
**Feedback:** `POST /api/v1/feedback` with `X-HuntCompiler-Tenant`, timestamp and signature headers; first
answer per pack wins, repeats return `duplicate`.

Tested (86 tests total): DSL/harness agreement incl. case-insensitivity, placeholder handling, KQL lint, every
AI gate with a fake provider (injection, foreign/benign indicators, breadth, failing samples, schema violations,
budget, redaction, fence spoofing), scoring, and an end-to-end PostgreSQL run: signals → clusters → AI-assisted
packs for two tenants → no re-issue → push with retry → signed pull → feedback. Not run against the live
Gemini API or a real Wazuh indexer.

## Phase 2b — leak monitoring and reference datasets

```
app/processors/leak_redactor.py  passwords dropped at parse time; accounts -> HMAC refs + masked form
app/collectors/telegram_cti.py   Telethon, message TEXT only, per-channel cursors (scripts/telegram_login.py)
app/collectors/hibp.py           HIBP breached-domain search (verified domains)
app/collectors/reference_data.py LOLDrivers, LOLRMM, HijackLibs, OSV malicious packages, MalwareBazaar
app/collectors/tasks_2b.py       Celery tasks + schedules
```

* **Account refs:** `ref = HMAC_SHA256(HMAC_SHA256(tenant_secret, "account-ref/v1"), lower(account))`. Packs carry
  `affected_accounts[{ref, masked, host}]` (additive v2.0 field); the SOAR resolves refs against its own directory
  and substitutes `${HC_AFFECTED_UPNS}` / `${HC_AFFECTED_SAM_ACCOUNTS}`. Credential-exposure packs set
  `notify_only_on_sighting=false`: exposure is an incident even with zero hits.
* **Datasets** (parsers written against the real files, Oct 2026): LOLDrivers 713 entries / 2,325 SHA256; LOLRMM 358
  tools (262 binaries, 605 domains); HijackLibs 627 entries (537 side-loadable DLLs). Templates cap list sizes to stay
  under the 64 KB query limit (150 hashes, 250 RMM binaries/domains, 200 DLLs/packages), newest first.
* **Per-tenant tasks:** rogue-RMM hunts exclude the tenant's `approved_rmm_tools`; exposure hunts only go to the
  affected tenant.
* **MalwareBazaar:** metadata only (samples never downloaded); Telegram bot tokens and Discord webhooks are reduced to
  numeric IDs plus a hash.
* **OSV** is read through `<ecosystem>/modified_id.csv` plus one JSON per advisory: `npm/all.zip` (~220 MB) exceeds the
  64 MB cap, so the V6 dataset never loaded before Phase T (D-47).
* **Unverified:** live Telegram, HIBP and MalwareBazaar endpoints and the OSV advisory fetch (offline tests with mocks;
  the OSV index format and file sizes were checked on 2026-11-02).

## Findings carried into Phase 3 (from compiling the example pack) — all addressed

1. **Parse a fresh `SigmaCollection` per backend.** pySigma pipelines mutate rules in place; reusing one
   collection duplicated the `EventID` condition in the second output.
2. **Compiled queries need tests.** `TargetObject|contains: '...\RunMRU\'` (trailing backslash) compiled to
   `RegistryKey endswith "...RunMRU*"` in KQL, which never matches. Every compiled task should be checked
   against positive/negative sample events before it ships.
3. **Case sensitivity on Wazuh.** `data.win.eventdata.*` are keyword fields, so `query_string` wildcards are
   case-sensitive while Sigma `contains` is not (`*powershell*` misses `PowerShell`). Plan: emit DSL with
   `wildcard` + `case_insensitive: true` (to verify on the target Wazuh indexer version).
4. **Pin the channel.** The Sysmon pipeline adds only `EventID`; the Wazuh pipeline must also filter
   `data.win.system.channel: Microsoft-Windows-Sysmon/Operational`.

## Phase T — Telegram digest, command bot, SSRF guard

```
app/core/netguard.py          SSRF guard for active probes (public IPs only, ports 443/80, pinned IP, redirects re-checked)
app/integrations/telegram/    client.py (Bot API, token scrubbing) · format.py · digest.py · bot.py
app/worker/health.py          collector heartbeats in Redis (Health section)
```

* **Digest** (`notify.telegram_digest`, daily 08:00 Asia/Ho_Chi_Minh by default): one line per cluster that got a new
  pack, then credential exposure (masked accounts only), edge CVEs, dataset updates and collector health. An empty
  window sends a one-line heartbeat. A failed send does not move the cursor (`telegram_digests`).
* **Commands** (allowlisted chat **and** user; database only): `/status`, `/digest` (preview), `/latest [n]`,
  `/pack <id prefix>` (summary plus JSON, Sigma and query files), `/ioc <value>`, `/cve <id>`.
* **Content rules:** IOCs defanged, HTML escaped, AI text labelled `[AI]`, no link previews, token scrubbed from errors
  and logs. The bot uses its own BotFather token (`HC_TGBOT_*`), never the Telethon research account (`HC_TELEGRAM_*`).
* **Fixes shipped with Phase T:** OSV through its index (above); the V1 exposure KQL uses `EntraIdSignInEvents`
  (Microsoft replaced `AADSignInEventsBeta` on 2026-10-19); the IOC network task matches a host and its subdomains only
  (`notevil.com` no longer matches `evil.com`).

**Setup (manual, about 10 minutes):**

1. In Telegram, talk to **@BotFather**: `/newbot`, choose a name, copy the token. Keep privacy mode **on**.
2. In `.env`: `HC_TGBOT_ENABLED=true` and `HC_TGBOT_TOKEN=<token>`. Leave `HC_TGBOT_CHAT_IDS=[]` and
   `HC_TGBOT_ALLOWED_USER_IDS=[]` for now.
3. `docker compose up -d --build`, then `docker compose up -d telegram-bot` (the bot has its own compose profile).
4. Send `/start` to the bot, or in the SOC group. `docker compose logs telegram-bot` shows
   `ignored update from chat_id=… user_id=…`.
5. Set `HC_TGBOT_CHAT_IDS=[<chat_id>]` and `HC_TGBOT_ALLOWED_USER_IDS=[<user_id>]`, then
   `docker compose up -d --force-recreate worker beat telegram-bot`.
6. `/status`, `/digest` and `/latest` should answer. The scheduled digest arrives at `HC_TGBOT_DIGEST_TIMES`.

One destination at a time: your private chat **or** one SOC group. Status: **Built**, not Verified, until the manual
checklist in `TELEGRAM.md` §9 passes.

## Roadmap

* **Phase 4 (n8n/Wazuh SOAR) — cancelled on 2026-11-01.** HuntCompiler is an API service; consumers run the hunts.
* **Phase I — Integration Kit:** one guide plus examples per platform (Wazuh, Splunk, Elastic, Zabbix…): pull or receive
  packs, verify the HMAC, substitute placeholders, run the tasks, post `sighting` and `evaluable`. Waits for IQ1–IQ3 in
  `SPEC.md` §9.

