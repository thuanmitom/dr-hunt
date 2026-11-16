# OutSight HuntCompiler

Outside-in threat intelligence compiled into **signed, actionable hunting packs**, served as an API to any SIEM/SOAR
(pull, push webhook, 1-bit feedback), plus a Telegram digest and command bot for people.

**Status:** Phases 1, 2, 2b, 3, T (Telegram), I (Integration Kit), H (hardening), R (self-hosting) and the approved
Phase Q items are built; Phase H is also verified live. The Wazuh path is tested end to end on the official Wazuh
indexer 4.14.7; Elastic, Splunk and the rest of the Telegram checklist are not verified live yet. Phase 4 (n8n/Wazuh
SOAR) is cancelled; integrators use the Integration Kit ([`integration_kit/`](integration_kit/README.md)). Install on
one machine with [`docs/INSTALL.md`](docs/INSTALL.md).

The AI threat model is in [`docs/AI_RISK_ASSESSMENT.md`](docs/AI_RISK_ASSESSMENT.md). A full Vietnamese overview is in [`README.vi.md`](README.vi.md).
Specification, decisions, architecture and the Telegram design: [`SPEC.md`](SPEC.md), [`DECISIONS.md`](DECISIONS.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), [`TELEGRAM.md`](TELEGRAM.md).

## Architecture

```
 INTERNET (HuntCompiler host)                                              ║  TENANT LAN
                                                                           ║
 L1 Collectors ──► L2 Pivot / Unpack / Guardrails ──► L3 AI + Sigma ──► L4 Store / API / Dispatch
 CertStream        JARM, favicon mmh3, stager          Gemini (structured   PostgreSQL, Redis,
 URLScan, KEV      unpacker, whitelist (Tranco,        output) → Sigma →    Celery, FastAPI
 GitHub, OSV ...   MISP warninglists)                  pySigma → Wazuh DSL        │
                                                                                  │  Hunting Pack v2.0 (HMAC)
                   tenant_manifest.yaml  (public facts only)                      │  pull (default) or push
                                                                           ║      ▼
                                                                           ║  Consumer SIEM/SOAR (any vendor) runs the
                                                                           ║  hunts itself (Integration Kit, Phase I)
                                     1-bit feedback  ◄═════════════════════╝  sighting true/false (+ evaluable)
```

L4 also feeds a Telegram digest and command bot for people (Phase T, below).

## Key design decisions

| # | Decision | Why |
|---|----------|-----|
| 1 | **Pull delivery is the default**, push is supported | Push needs an Internet-reachable consumer webhook, i.e. an inbound hole into the LAN. With pull, the SOAR polls `GET /api/v1/packs` outbound-only; the contract and signing are identical in both modes. |
| 2 | **HMAC over `timestamp + "." + raw body`** | Replay protection on top of `sha256=<hmac>`. Receivers verify the raw body (for example the n8n Webhook node with *Raw Body* on) and de-duplicate on `X-HuntCompiler-Pack-Id`. |
| 3 | **Guardrails live in the contract** | Packs are built from attacker-controlled content via an LLM. Validation rejects: non-global or over-broad IPs (< /24, < /48), all-zero JARM, `script`/`runtime_mappings` in OpenSearch DSL, `externaldata`/`http_request`/control commands in KQL (older packs only, D-63), undeclared placeholders, and `auto_block_pre_iocs` below confidence 80. |
| 4 | **Zero-Internal-Access enforced by schema** | The manifest rejects RFC1918/CGNAT/ULA ranges. Host groups are expressed as `target_scope`; internal values (e.g. the VPN appliance's inside IP) as `${HC_EDGE_DEVICE_INTERNAL_IPS}`, substituted by the SOAR. |
| 5 | **`required_telemetry` + `evaluable`** | Zero hits without Sysmon 13 is *unknown*, not *clean*. Feedback stays anonymous but distinguishes the two. |
| 6 | **`content_sha256` uniqueness per tenant** | Re-compiling the same intelligence never re-sends a pack; `version`/`supersedes_id` track real changes; `seq` is a stable pull cursor. |
| 7 | **VARCHAR + CHECK enums** (not native PG ENUM) | Adding an attack vector or source is a normal transactional migration. |
| 8 | **Secrets by env-var reference, Fernet at rest** | Manifests never contain secrets; HMAC keys are encrypted (MultiFernet rotation); API tokens are stored as SHA-256 only. |
| 9 | **`redacted` flag on raw events** | Stealer-log / leak content must be stripped of credential material before persisting (personal-data law, liability). Phase 2 collectors must redact first. |
| 10 | **Hash-locked dependencies** | `requirements.txt` is generated from `requirements.in` with `uv pip compile --generate-hashes`; the image installs with `--require-hashes`. |

## Data contracts

* **Hunting Pack v2.0** — `contracts/hunting_pack_v2.schema.json`. Core fields as specified
  (`schema_version`, `pack_id`, `timestamp`, `attack_vector`, `severity`, `confidence_score`,
  `mitre_attack`, `threat_summary`, `prevention_blocklist`, `internal_hunting_tasks`,
  `soar_playbook_hints`) plus additive extensions: `expires_at`, and per task `target_scope`,
  `required_telemetry`, `scope_placeholders`. Example: `contracts/examples/clickfix_pack.example.json`.
* **Sighting feedback v1** — `contracts/sighting_feedback_v1.schema.json`: `pack_id`, `sighting`, `evaluable`, `evaluated_at`. No counts, hosts, users or log lines leave the tenant.
* **Wire headers** — `X-HuntCompiler-Timestamp`, `X-HuntCompiler-Signature: sha256=<hex>`, `X-HuntCompiler-Pack-Id`, `X-HuntCompiler-Tenant` (feedback). Tolerance: 300 s.

Regenerate schemas after changing a model: `python -m scripts.export_contracts`.

## Quick start

Full installation guide for one machine (sizing, HTTPS in a LAN, updates, uninstall): `docs/INSTALL.md`.

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

Test suite on 2026-11-15: 349 tests, all passing with the PostgreSQL 16 integration tests (Alembic upgrade → downgrade →
upgrade and `alembic check` included).
In a test deployment (2026-11-08) the compose stack reaches healthy on every health check and `/readyz` returns 200.

## Phase 2 — collectors, pivot, unpacker, guardrails

```
app/processors/  whitelist_filter.py · stager_unpacker.py · pivot.py (JARM, favicon mmh3, AiTM score) · brand_matcher.py
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

**Tested:** unpacker layers (EncodedCommand, FromBase64String+gzip, concatenation, char codes, carets, backticks,
reversed strings, XOR, defanged IOCs, bomb limit); whitelist decisions on synthetic data and on the real warninglists;
brand matcher (homoglyph, IDN, edit distance); KEV↔tech-tag matching; fake-PoC heuristics; clipboard-lure and AiTM
detection; Retry-After handling; JARM against a local TLS server. CISA KEV, FIRST EPSS and GitHub repository search
ran live on 2026-11-14 and 2026-11-15. URLScan has not run live yet; its query templates (`HC_URLSCAN_*_QUERY`)
depend on your plan's search syntax and should be tuned on first run.

## Phase 3 — compiler, packs, delivery

```
app/compiler/  fields.py · wazuh_dsl.py (case-insensitive DSL from pySigma's parse tree) · translate.py (Sigma → Wazuh DSL)
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
list of values. (Packs issued before D-63 also carried KQL, where `${HC_X}` became comma-separated quoted values.)
**Feedback:** `POST /api/v1/feedback` with `X-HuntCompiler-Tenant`, timestamp and signature headers; first
answer per pack wins, repeats return `duplicate`.

Tested: DSL/harness agreement incl. case-insensitivity, placeholder handling, every
AI gate with a fake provider (injection, foreign/benign indicators, breadth, failing samples, schema violations,
budget, redaction, fence spoofing), scoring, and an end-to-end PostgreSQL run: signals → clusters → AI-assisted
packs for two tenants → no re-issue → push with retry → signed pull → feedback. Not run against the live
Gemini API. The Wazuh DSL runs on the official Wazuh indexer 4.14.7 (`integration_kit/wazuh/SAMPLE_RUN.md`).

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
* **Live status:** the reference datasets, including the OSV index and advisory fetch, were collected live on
  2026-11-14 and 2026-11-15. Telegram CTI, HIBP and MalwareBazaar have not run live yet (offline tests with mocks).

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
* **Fixes shipped with Phase T:** OSV through its index (above); the IOC network task matches a host and its
  subdomains only (`notevil.com` no longer matches `evil.com`).

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

## Phase I — Integration Kit

Everything an integrator needs is in [`integration_kit/`](integration_kit/README.md): the security rules every
consumer must follow, guides for [Wazuh](integration_kit/wazuh/GUIDE.md), [Elastic](integration_kit/elastic/GUIDE.md)
and [Splunk](integration_kit/splunk/GUIDE.md), and a reference consumer in Python that runs on the integrator's side.

* **Flow:** pull (or receive by push) → verify the HMAC → re-validate the pack against the JSON Schema and guardrails →
  substitute placeholders from local data and resolve exposed accounts against a local directory export → run each task →
  post `sighting` and `evaluable` only. Hit details stay in a local report.
* **Queries:** Wazuh runs the pack's DSL. Elastic (EQL by default) and Splunk run the Sigma rule converted with pySigma
  (D-49). Zabbix and Microsoft Defender XDR are out of scope (D-50).
* **Safety:** a valid signature is not enough, the pack is always re-validated; more than `HC_KIT_MAX_HITS` hits marks a
  broken rule; `auto_block_pre_iocs` is a hint and the consumer never blocks (D-51).
* **Separate:** the kit never imports `app`, is not in the Docker image, and has its own hash-locked
  `integration_kit/requirements.txt`.

Status: **Built**. Offline tests cover every module; an end-to-end test runs the consumer against the real
HuntCompiler API on PostgreSQL. Wazuh is tested end to end on the official Wazuh indexer 4.14.7: 12 tasks in 5 packs
all give the expected hits ([sample run](integration_kit/wazuh/SAMPLE_RUN.md)); that run found and fixed the
doubled-backslash bug (D-53). Elastic and Splunk each still need one live run.

## Phase H — production hardening

Decisions D-54 to D-62; completion criteria and live checks in `SPEC.md` §6.

* **Missing keys never break a sweep.** A blank value in `.env` means "not set", so a collector without its key reports
  `not_configured` (D-62). GitHub only enriches KEV alerts: without a token, or when GitHub fails, the alert still ships
  without PoC/Nuclei details and `/status` names the reason (D-54). The token is still recommended: a credible PoC and a
  Nuclei template add up to 20 confidence points, which can decide whether a KEV with low EPSS reaches a tenant.
* **Tenant API limits (D-56).** 60 calls per minute per tenant; after 20 failed authentications in 10 minutes an IP gets
  429 until the window ends. An unknown tenant slug fails exactly like a wrong signature. Settings:
  `HC_API_RATE_LIMIT_PER_MINUTE`, `HC_API_AUTH_FAILURES_PER_IP`, `HC_API_AUTH_FAILURE_WINDOW_SECONDS`.
* **Retention (D-57).** Daily at 02:45 UTC: raw events older than 90 days (unless their cluster is still active) and AI
  audit rows older than 180 days are deleted. `HC_RETENTION_RAW_EVENT_DAYS`, `HC_RETENTION_AI_COMPILATION_DAYS`; 0 keeps
  forever.
* **Logs (D-58).** `HC_LOG_FORMAT=json` for one JSON object per line. HTTP client request lines appear only at
  `HC_LOG_LEVEL=DEBUG` (Phase R).
* **No more Defender KQL (D-63, 2026-11-10).** Packs carry Sigma and the Wazuh DSL only; Elastic and Splunk convert
  the Sigma rule (D-49). The `kql_defender` field stays empty so older packs remain valid.
* **Deployment profiles (D-59 to D-61).** Every image is pinned by digest.

```bash
# HTTPS for tenants: HC_TLS_MODE=public (Let's Encrypt for HC_PUBLIC_HOSTNAME, ports 80/443 open) or
# HC_TLS_MODE=internal (Caddy's local CA for a LAN name or IP; see docs/INSTALL.md)
docker compose --profile edge up -d caddy
# Daily backups into the pg_backups volume, newest HC_BACKUP_KEEP (14) kept
docker compose --profile backup up -d backup
# Self-hosted CertStream; then set HC_CERTSTREAM_URL=ws://certstream-server:8080/ and recreate the watcher
docker compose --profile certstream up -d certstream-server
docker compose up -d --force-recreate certstream
```

### Backups

Restore a dump into the stack (stop the writers first):

```bash
docker compose stop api worker beat certstream telegram-bot
docker compose run --rm backup ls -1 /backups
docker compose run --rm --entrypoint pg_restore backup --clean --if-exists --no-owner -d huntcompiler /backups/huntcompiler-<timestamp>.dump
docker compose start api worker beat certstream
```

The volume lives on the same host: copy the dumps elsewhere for disaster recovery.

Status: **Built and Verified** (2026-11-15). Unit tests and PostgreSQL integration tests cover each piece; the compose file validates with every
profile. Live checks on 2026-11-09 passed: a restore from a dump, the self-hosted CertStream stream feeding the
watcher, and HTTPS through Caddy with a local certificate (TLS, routing, signed pull, per-IP lockout, JSON logs).
HTTPS with a public hostname and a Let's Encrypt certificate is optional since D-72; on 2026-11-15 a consumer pulled
packs through Caddy in LAN mode (`HC_TLS_MODE=internal`), trusting only Caddy's root certificate.

## Phase Q — quality (in progress)

Plan: `docs/plans/KE_HOACH_PHASE_Q.md` (Vietnamese). Approved and built on 2026-11-13:

* **KEV alone is enough (D-64).** "In KEV" is worth 70 points instead of 50, so a CVE CISA confirms as exploited reaches
  the default delivery threshold (60) for the 7-day KEV window, even with a low EPSS and no PoC yet.
* **Ops alerts, opt-in (D-65).** `HC_TGBOT_OPS_ALERTS=true` sends a Telegram message when a job fails 3 runs in a row or
  stops reporting, at most every 6 hours, and another when it recovers. No intelligence in these messages.
* **No spoofed client IPs (D-66).** The API trusts `X-Forwarded-For` only from Caddy's fixed address on the internal
  `edge` network (`HC_EDGE_SUBNET`, `HC_EDGE_CADDY_IP`).

Q2 (CI) and Q4 (GitHub retry) were built in Phase R. Waiting for the owner: Q3 (detection check on a real Windows
host), Q7 (off-host backups), Q8 (Wazuh archive filtering).

## Phase R — ready for self-hosting

Plan and results: `docs/plans/KE_HOACH_PHASE_R.md` (Vietnamese). Decisions D-70 to D-74. Installation on one machine,
with measured resource needs: `docs/INSTALL.md`.

* **KEV entries are classified (D-70).** Edge appliances and internet-facing servers (VPN, firewall, mail gateway,
  Exchange, vCenter, file transfer...) keep the V2 pack with the edge hunts. OS and desktop software (Windows, Office,
  browsers...) get no edge hunts and, without other tasks, no pack: the digest lists them under "Exploited CVEs to
  patch". A product listed in a tenant's `login_portals` counts as internet-facing for that tenant. The table lives in
  code and was checked against the whole KEV catalog.
* **Quieter logs (D-58).** HTTP client request lines only at `HC_LOG_LEVEL=DEBUG`; with `HC_LOG_FORMAT=json` uvicorn's
  startup lines are JSON too.
* **Missed GitHub data is retried daily (D-71).** 04:15 UTC, at most `HC_KEV_REENRICH_MAX_ATTEMPTS` (5) runs per KEV
  entry inside the KEV window; failures show on the health page.
* **Local deployment (D-72).** `HC_TLS_MODE=internal` makes Caddy issue certificates from its own CA for a LAN; the
  reference consumer accepts `http://` to `localhost` or loopback addresses on the same machine without
  `HC_KIT_ALLOW_HTTP`. A public hostname with Let's Encrypt is optional.
* **Telegram CTI and HIBP policy (D-73).** Public channels only, read-only, from a separate research account; HIBP only
  for domains you own and have verified.
* **CI (D-74).** `.github/workflows/ci.yml` (actions pinned by commit SHA, read-only token) runs lint, the full suite with
  PostgreSQL, `alembic check`, the contract diff and `pip-audit`. `requirements-dev.txt` is now hash-locked from
  `requirements-dev.in`. CI starts once the repository is pushed.

Status: **Built**, not Verified: CI has not run on GitHub yet, and R6 (the first Gemini run) waits for a key.

## Roadmap

* **Phase 4 (n8n/Wazuh SOAR) — cancelled on 2026-11-01.** HuntCompiler is an API service; consumers run the hunts.
* **Phase I — Integration Kit:** built (above). Wazuh tested; Elastic and Splunk each need one live run.
* **Phase H — production hardening:** built and verified (above).
* **Phase R — ready for self-hosting:** built (above). Waiting: CI on GitHub after a push; R6 Gemini run.
* **Phase Q — quality:** Q1, Q5, Q6 built (Q2, Q4 in Phase R); Q3, Q7, Q8 waiting for the owner.
* **Next:** the open live checks in `SPEC.md` §6 (Telegram checklist, Elastic and Splunk runs, Q3, R6) and the open
  questions in `SPEC.md` §9.

