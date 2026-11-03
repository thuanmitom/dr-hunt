# OutSight HuntCompiler — Architecture

Code version 0.4.0 · status date 2026-11-02 · Phase 4 (SOAR) cancelled; Phase T (Telegram) built, not yet verified live (`TELEGRAM.md`). Open questions are referenced as (Qn / TQn / IQn); the list is in §10.

## 1. System context

```
                    ┌──────────────────────────── INTERNET ─────────────────────────────┐
  Intel sources ───►│                       OutSight HuntCompiler                        │
  CertStream, URLScan, CISA KEV,       ┌────────┐  ┌────────────┐  ┌──────────┐  ┌──────┐ │
  FIRST EPSS, GitHub, Shodan,          │ L1     │─►│ L2 pivot / │─►│ L3       │─►│ L4   │ │
  Telegram (CTI, read-only),           │collect │  │ unpack /   │  │ compile  │  │ store│ │
  HIBP, MalwareBazaar, LOLDrivers,     └────────┘  │ guardrails │  │ (+ LLM)  │  │ API  │ │
  LOLRMM, HijackLibs, OSV                          └────────────┘  └────┬─────┘  └──┬───┘ │
  LLM provider (Gemini / local) ◄────── redacted cluster evidence ──────┘           │     │
                    │  Telegram bot (Phase T) ◄── digest + DB-only commands ────────┤     │
                    └───────────────┬────────────────────────────────────────────────┼─────┘
                                    │ Bot API (long polling)                         │ signed packs (pull default / push)
                         Owner chat or SOC group                                     │ ▲ 1-bit feedback
                                                                    ┌────────────────▼─┴──────────────────┐
                                                                    │ Consumer SIEM/SOAR (any vendor)      │
                                                                    │ runs the hunts itself — Integration │
                                                                    │ Kit (Phase I) documents how          │
                                                                    └──────────────────────────────────────┘
  Only tenant input to HuntCompiler: tenant_manifest.yaml (public facts + env-var names of secrets)
```

## 2. Components

| Layer | Module | Responsibility |
|---|---|---|
| Core | `app/core/config.py` | `HC_*` settings (pydantic-settings) |
| | `app/core/crypto.py` | Fernet/MultiFernet for secrets at rest, token hashing |
| | `app/core/signing.py` | Canonical JSON, HMAC sign/verify, header names |
| | `app/core/netguard.py` | SSRF guard for active probes: public IPs only, ports 443/80, pinned IP, redirects re-validated (D-46) |
| Contracts | `app/schemas/` | Hunting Pack v2.0, manifest, feedback, enums, observable validators |
| L1 Collectors | `collectors/urlscan.py` | V1 AiTM candidates, V3 clipboard lures (DOM) |
| | `collectors/edge_exploits.py` | V2: KEV + EPSS + GitHub PoCs (fake-PoC heuristics) + Nuclei |
| | `collectors/certstream_watcher.py` | V1 lookalike certificates (own container) |
| | `collectors/telegram_cti.py`, `hibp.py` | V1 credential exposure (pseudonymous) |
| | `collectors/reference_data.py` | LOLDrivers, LOLRMM, HijackLibs, OSV MAL (index + per-advisory, D-47), MalwareBazaar |
| | `collectors/tasks.py`, `tasks_2b.py` | Celery tasks, schedules, ingestion |
| L2 Processors | `processors/whitelist_filter.py` | `block` / `hunt_only` / `drop` per hostname or IP |
| | `processors/stager_unpacker.py` | Static recursive de-obfuscation + IOC extraction |
| | `processors/pivot.py` | JARM and favicon mmh3 through `netguard` (pinned IP), Shodan pivot (not wired yet), AiTM scoring |
| | `processors/brand_matcher.py` | Homoglyph / IDN / edit-distance lookalikes |
| | `processors/leak_redactor.py` | Account refs (HMAC), masking, passwords dropped |
| L3 Compiler | `compiler/wazuh_dsl.py` | pySigma tree → case-insensitive OpenSearch DSL |
| | `compiler/translate.py` | DSL + Defender KQL (pySigma Kusto), KQL lint |
| | `compiler/harness.py` | Executes the emitted DSL subset on sample events |
| | `compiler/templates.py` | Deterministic hunts per vector (+ per-tenant) |
| | `compiler/draft.py`, `prompt.py`, `llm.py`, `ai_compiler.py` | Constrained LLM output, redaction/fencing, provider, 6 gates |
| | `compiler/scoring.py` | Base score, half-life decay, feedback, severity |
| Services | `services/cluster_builder.py` | Events → clusters (deterministic keys, merged observables) |
| | `services/ai_service.py` | Evidence inventory, cache, audit rows |
| | `services/pack_builder.py` | Cluster × tenant → pack, versioning, blocklist, hints |
| | `services/tenant_registry.py`, `tenant_context.py`, `intel_store.py` | Manifest upsert, tenant loading, idempotent inserts |
| L4 Delivery | `dispatch/dispatcher.py` | Push with HMAC, back-off, dead letter |
| | `api/routes.py`, `api/main.py` | `GET /api/v1/packs`, `POST /api/v1/feedback`, `/healthz`, `/readyz` |
| Human interface (Phase T) | `app/integrations/telegram/` — `client.py`, `format.py`, `digest.py`, `bot.py` | Digest task `notify.telegram_digest`, long-polling bot, DB-only commands (see `TELEGRAM.md`) |
| | `app/worker/health.py` | Collector heartbeats in Redis for the Health section (D-48) |
| Consumers (Phase I) | Integration Kit docs and examples | Pull or receive packs, verify HMAC, substitute placeholders, run hunts, post feedback. Phase 4 SOAR is cancelled |

## 3. Data model (PostgreSQL 16, 4 Alembic revisions)

| Table | Key columns | Constraints and indexes |
|---|---|---|
| `tenants` | `slug`, `manifest` (JSONB, no secrets), `manifest_sha256`, `tech_stack_tags[]`, `delivery_mode`, `webhook_url`, `webhook_secret` (Fernet), `api_token_sha256` | push ⇒ webhook, pull ⇒ token; GIN on tags |
| `raw_intel_events` | `source`, `external_id`, `dedup_sha256`, `tenant_id?`, `attack_vector?`, `raw_payload`, `observables` (JSONB), `redacted`, `status` | UNIQUE(source, dedup_sha256); partial index on pending; GIN on observables |
| `pivoted_clusters` | `cluster_key` (unique), `attack_vector`, `tenant_id?`, `base/current_confidence`, `decay_half_life_hours`, `first/last_seen_at`, `observables`, `pivot_graph` (features, edges, AI summary), `cve_ids[]`, `tech_stack_tags[]`, `sighting_count`, `clean_count` | CHECK ranges; GIN on arrays and observables |
| `cluster_event_links` | `cluster_id`, `event_id` | composite PK |
| `hunting_packs` | `id` (= pack_id), `seq` (identity, pull cursor), `tenant_id`, `cluster_id`, `version`, `supersedes_id`, `payload` (exact wire JSON), `content_sha256`, `expires_at`, delivery fields, `sighting`, `evaluable` | UNIQUE(tenant, cluster, version), UNIQUE(tenant, content_sha256); dispatch partial index |
| `ai_compilations` | `cluster_id`, `provider`, `model`, `prompt_version`, `input_sha256`, `input_chars`, `redactions`, `status`, tokens, `raw_output`, `verdicts`, `accepted_tasks` | UNIQUE(cluster, input, prompt_version, model) = cache key |
| `reference_datasets` | `name` (unique), `version`, `record_count`, `records` (JSONB) | — |
| `telegram_digests` | `scheduled_for`, `window_start`, `window_end`, `max_pack_seq`, `max_link_at`, `status` (sending, sent, failed, preview), `message_ids[]`, `error` (token-scrubbed) | index (status, created_at); the newest `sent` row starts the next window |

Enums are VARCHAR + CHECK, and their values are append-only.

## 4. Data flows

### 4.1 Intel → pack

1. A collector emits an `IntelSignal`.
2. `collectors.ingest_signals` inserts it with `ON CONFLICT DO NOTHING`.
3. `processors.enrich_event` adds the whitelist verdicts, then JARM and favicon for `block` domains (at most 10), through the SSRF guard (`app/core/netguard.py`).
4. `compiler.cluster_events` (every 5 min) merges events into clusters by deterministic key:

   | Source | Cluster key |
   |---|---|
   | CISA KEV | `v2:cve:<CVE>` |
   | ClickFix lure | `v3:c2:<first C2>` or `v3:lure:<host>` |
   | AiTM | `v1:<tenant>:<registrable host>` |
   | Credential exposure | `v1:<tenant>:credential-exposure` |
   | MalwareBazaar | `v1:mb:<tag>` |
   | Reference datasets | `v4:reference`, `v5:reference`, `v6:reference` |

   The base score is computed when events are merged.
5. `compiler.build_packs` (every 10 min) runs once per active cluster:
   1. Decay the score, then add feedback.
   2. Select eligible tenants: enabled vector, the confidence threshold, and either a tech-tag match (V2) or ownership of the cluster (tenant-scoped clusters).
   3. Build the common tasks: templates plus AI tasks.
   4. Per tenant, add tenant-specific tasks (RMM exclusions, exposure).
   5. Build the blocklist from `block` observables.
   6. Build the hints; auto-block requires opt-in.
   7. Validate against the contract.
   8. Skip the pack if its content hash already exists or its substance is unchanged; otherwise insert a new version.

### 4.2 Delivery

- **Pull (default):** the consumer calls `GET /api/v1/packs?after=<seq>&limit≤100` with a bearer token. Each item is `{seq, timestamp, signature, pack}`. Its status moves from `awaiting_pull` to `pulled`.
- **Push:** `dispatch.deliver_due` (every minute) selects due packs with `FOR UPDATE SKIP LOCKED` and POSTs canonical JSON with signed headers. Outcomes:
  - 2xx → `delivered`.
  - 408/425/429/5xx or a network error → `retrying`, back-off `30·2^(n-1)` s ±20 %, capped at 1 h.
  - Any other 4xx, or `max_attempts` reached → `dead_letter`.
  - Expired → `skipped`.

### 4.3 Feedback

`POST /api/v1/feedback` (tenant header + HMAC over the raw body) carries `{pack_id, sighting, evaluable, evaluated_at}`.

- The first answer wins.
- A sighting increments `sighting_count`.
- An evaluable clean result increments `clean_count`.
- Confidence only ever rises from feedback.

### 4.4 AI compilation (optional)

1. Applies only to V2/V3 clusters that reached delivery and carry untrusted evidence.
2. Inputs are KEV facts, Nuclei paths, PoC files from non-fake repos, clipboard payloads, technique names and cluster indicators. They are redacted, fenced and capped at 40k characters.
3. Check the cache. Reserve tokens from the daily budget.
4. Call the provider with a JSON schema and temperature 0.
5. Validate the output strictly with `CompilationDraft`.
6. Pass each rule through the 6 gates.
7. Write an audit row. Return the accepted `HuntingTask`s.

### 4.5 Credential exposure

1. Telegram text or HIBP domain data is parsed by `leak_redactor`. Passwords are dropped there.
2. Each account becomes `ref = HMAC(HMAC(tenant_secret, "account-ref/v1"), lower(account))` plus a masked form.
3. Events go into a tenant cluster.
4. The pack carries `affected_accounts`, `notify_only_on_sighting=false`, and a task using `${HC_AFFECTED_UPNS}` / `${HC_AFFECTED_SAM_ACCOUNTS}`.
5. The consumer resolves the refs against its own directory (documented in the Integration Kit).

### 4.6 Telegram digest (Phase T)

1. `notify.telegram_digest` runs at `HC_TGBOT_DIGEST_TIMES`, converted to UTC crontabs when beat starts.
2. The window starts at the newest `sent` row's marks: packs with a higher `seq` (shown tenants only) and dataset events linked later.
3. A `sending` row is committed, the messages are sent, then the row becomes `sent`. On any failure it becomes `failed` and the marks stay, so the next run covers the same window.
4. `/digest` renders the same window into a `preview` row, which never counts as a mark.

## 5. Deployment (docker-compose)

| Service | Command | Networks | Notes |
|---|---|---|---|
| `postgres` | postgres:16-alpine | `backend` (internal) | volume `pg_data` |
| `redis` | redis:7-alpine, `requirepass`, AOF, `noeviction` | `backend` | Celery broker (db 0), results (db 1), cache and locks (db 2) |
| `migrate` | `alembic upgrade head` | `backend` | one-shot; other app services wait for it |
| `api` | uvicorn :8000 | `backend`, `egress` | published on 127.0.0.1 only; put a TLS reverse proxy in front (Q3) |
| `worker` | celery worker, queues `default,collectors,compiler,dispatch` | `backend`, `egress` | |
| `beat` | celery beat, schedule in `/tmp` | `backend`, `egress` | |
| `certstream` | `python -m app.collectors.certstream_watcher` | `backend`, `egress` | self-hosted CertStream server recommended |
| `telegram-bot` *(Phase T)* | `python -m app.integrations.telegram.bot` | `backend`, `egress` | compose profile `telegram` (start with `docker compose up -d telegram-bot`); `restart: on-failure`, exits 0 when disabled; long polling; Bot API identity separate from the Telethon CTI account |

All app containers run from one image:
- non-root uid 10001;
- read-only root filesystem with a `/tmp` tmpfs;
- `cap_drop: ALL` and `no-new-privileges`;
- config mounted read-only.

**Schedules:**

| Task | Interval |
|---|---|
| URLScan, edge exploits, Telegram | 30 min |
| MalwareBazaar | 2 h |
| Reference datasets | 6 h |
| HIBP | daily |
| Clustering | 5 min |
| Pack building | 10 min |
| Push dispatch | 1 min |
| Telegram digest | `HC_TGBOT_DIGEST_TIMES` (default 08:00 Asia/Ho_Chi_Minh) |

## 6. Technology stack (pinned)

| Area | Choice |
|---|---|
| Runtime | Python 3.12, `python:3.12-slim-bookworm` |
| API | FastAPI 0.162.0, Uvicorn 0.54.0, Pydantic 2.14.2, pydantic-settings 2.16.2 |
| Data | PostgreSQL 16, SQLAlchemy 2.1.6 (async) + asyncpg 0.32.0, Alembic 1.20.1 |
| Jobs | Celery 5.6.3, Redis 7, redis-py 6.4.0 |
| HTTP / crypto | httpx 0.28.1, cryptography 50.0.2 |
| Detection | pySigma 1.5.1, backend-elasticsearch 2.1.1 (unused for output), backend-kusto 1.0.1, pipeline-sysmon 2.0.0, pipeline-windows 2.0.1 |
| Intel / pivot | certstream 1.12, Telethon 1.45.0, pyjarm 0.0.5, mmh3 5.3.1, pymispwarninglists 1.7.0, tldextract 5.4.0 (offline PSL) |
| AI | google-genai 2.34.0 behind the `LLMProvider` protocol |
| Quality | pytest 9.2, pytest-asyncio 1.4, ruff; 170 tests (2026-11-02) |
| Supply chain | `requirements.in` → `uv pip compile --generate-hashes` → `--require-hashes` |

## 7. External dependencies

| Dependency | Auth | Used for | Live-verified |
|---|---|---|---|
| URLScan.io search / result / DOM | API key | V1, V3 | No (query syntax depends on plan) |
| CISA KEV JSON, FIRST EPSS | none | V2 | No |
| GitHub search, trees, raw | token recommended | V2 PoCs, Nuclei, V6 | Partly (raw/codeload reachable) |
| Shodan host search | paid key for filters | JARM/favicon pivot | No |
| CertStream websocket | none | V1 | No |
| Telegram MTProto (Telethon) | API id/hash + StringSession | V1 | No |
| HIBP breacheddomain | key + verified domain | V1 | No |
| MalwareBazaar API | Auth-Key | V1 | No |
| OSV ecosystem index (`modified_id.csv`) + per-advisory JSON | none | V6 | Partly (index format and file sizes checked 2026-11-02) |
| LOLDrivers / LOLRMM raw JSON, HijackLibs archive | none | V4, V5 | **Yes** (formats verified 2026-10-31) |
| Gemini API | API key | AI compiler | No |
| Telegram Bot API (Phase T) | BotFather token | Digest and commands | No |
| MISP warninglists (bundled) | — | Whitelist | **Yes** |

## 8. Wire contract (summary)

- **Pack:** Hunting Pack v2.0 (`contracts/hunting_pack_v2.schema.json`), with additive optional fields: `expires_at`, `affected_accounts`, and per task `target_scope`, `required_telemetry`, `scope_placeholders` (Q13).
- **Signature:** `sha256=HMAC_SHA256(secret, f"{timestamp}." + raw_body)`. Tolerance is 300 s; de-duplicate on `pack_id`.
- **Placeholders:**
  - DSL: an array element equal to `${HC_X}` is expanded into the list of values.
  - KQL: `${HC_X}` is replaced by quoted, comma-separated values.

## 9. Threat model of HuntCompiler itself

### Assets

| Asset | Why it matters |
|---|---|
| Tenant HMAC secrets and API tokens | They authenticate packs and feedback |
| Integrity of packs | Tenants execute them automatically |
| Third-party API keys and the Telegram StringSession | The session gives full control of the research account |
| Account refs and masked forms | Pseudonymous personal data |
| Tenant manifests | They map each tenant's attack surface |
| The LLM audit trail | Records what the model read and returned |

### Trust boundaries

1. Internet intel to collectors: **untrusted, possibly adversarial**.
2. HuntCompiler to the LLM provider: data leaves our control.
3. HuntCompiler to the tenant SOAR: authenticated and integrity-protected.
4. Operator to the host: environment variables and manifests.

### Threats and mitigations

| # | Threat | Mitigations in place | Residual / gap |
|---|---|---|---|
| T1 | Poisoned intel produces harmful packs (block legit infrastructure, flood alerts) | Whitelist; deterministic blocklist; contract guardrails; breadth and provenance gates; auto-block opt-in at confidence ≥ 80 | Over-blocking is possible for exact FQDNs that a poisoner chooses |
| T2 | Prompt injection via PoC or ClickFix content | Schema-only output; nonce fences; 6 gates; no tenant data in prompts; audit | The AI summary can mislead an analyst. Telegram escapes it and labels it `[AI]` (Phase T); consumers must render it as plain text |
| T3 | Poisoned evidence makes AI hunts miss | Fake-PoC heuristics; templates ship regardless | **High:** zero hits on an AI task never proves absence |
| T4 | **HuntCompiler host compromise** → malicious packs to every tenant | Per-tenant secrets; read-only queries; contract limits; auto-block off by default | **High impact:** the Integration Kit must tell consumers to re-validate packs against the JSON Schema and guardrails, and to require approval for blocking |
| T5 | **SSRF through active probes**: a "malicious" domain resolving to 127.0.0.1, RFC1918 or 169.254.169.254; favicon fetch follows redirects | Probes run only on `block`-class domains. `app/core/netguard.py` resolves first, refuses any non-global address and ports other than 443/80, pins the validated IP (favicon: `Host` + SNI; JARM: hellos for the hostname sent to the IP) and re-validates each redirect (max 3). Size and time caps | JARM pinning relies on pyjarm 0.0.5 internals (hash-pinned, tested) |
| T6 | Secret leakage | Env references, Fernet at rest, token hashes, `.env` excluded from image and git | No secret manager; rotation is manual; logs are not scrubbed systematically |
| T7 | Cross-tenant inference | LLM evidence is tenant-agnostic; feedback is content-minimal | Shared `sighting_count` raises confidence for other tenants (implies "someone was hit"); KEV prompts imply some tenant runs that vendor |
| T8 | Data sent to the LLM provider | Redaction; evidence inventory; LLM off by default; provider swappable | Provider terms differ by tier (Q12) |
| T9 | Cost or resource exhaustion (fake CVE repos, huge archives, decompression bombs) | Token budget; cache; download caps (64 MB archives, 64 KB files and OSV advisories, 512 KB favicon pages and icons); bounded inflate; single-flight locks | No API rate limiting yet |
| T10 | Replay or forgery on the API | HMAC with timestamp; pack-id de-duplication; bearer tokens hashed | Feedback returns different errors for an unknown tenant and a bad signature, so tenant slugs can be enumerated |
| T11 | Handling stolen data (legal) | Text only; passwords dropped; refs only; no attachments or samples | Legal clearance for monitored channels (Q11) |
| T12 | Supply-chain compromise of dependencies | Hash-locked requirements; minimal image | Base image not pinned by digest; no SBOM yet |
| T13 | Telegram bot abuse or leakage: stolen token, strangers issuing commands, data leaking to group members or Telegram's cloud | In place (Phase T, tested): chat and user allowlist (deny by default); DB-only commands; rate limit; defanged IOCs; masked accounts; files only on request; token scrubbed from logs; separate identity from the CTI account | Messages persist in Telegram history beyond our control; group membership must be managed by the owner |

## 10. Open questions affecting the architecture

### General

| ID | Question |
|---|---|
| Q1 | Who is the target: lab, employer, or SME service? |
| Q2 | Is pull confirmed as the default for integrators? |
| Q3 | Where does it run, and how do integrators reach it? |
| Q7 | Are Linux hunts in scope? |
| Q8 | What does `auto_block_pre_iocs` mean for integrators? |
| Q12 | Which LLM provider and tier? |
| Q13 | Does the contract version stay 2.0? |

### Telegram

| ID | Question |
|---|---|
| TQ1 | Digest schedule. Answered 2026-11-02: daily 08:00 Asia/Ho_Chi_Minh. |
| TQ2 | Should credential exposure be sent immediately? |
| TQ3 | Feedback buttons. |
| TQ4 | Bot language. Answered 2026-11-02: English. |

### Integration Kit

| ID | Question |
|---|---|
| IQ1 | More query languages in packs (SPL, ECS), or Sigma conversion by integrators? |
| IQ2 | What should the Zabbix integration do? |
| IQ3 | Platform order. |
