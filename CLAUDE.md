# CLAUDE.md — OutSight HuntCompiler

Internet-side **API service** that turns external threat intelligence into signed **Hunting Pack v2.0** JSON. Any
SIEM/SOAR consumes the packs (Integration Kit). People use a Telegram digest and command bot.

- Version 0.4.0. Phases 1, 2, 2b, 3, **T** (Telegram, see `TELEGRAM.md`), **I** (Integration Kit, see
  `integration_kit/README.md`), **H** (hardening, D-54 to D-62; also Verified on 2026-11-15),
  the approved items of **Q** and **R** (self-hosting, see `docs/plans/KE_HOACH_PHASE_R.md`) are built. Neither T nor I
  is *Verified* yet: T waits for the rest of the owner's manual
  checklist in `TELEGRAM.md` §9; in I, Wazuh is tested on the official Wazuh indexer 4.14.7
  (`integration_kit/wazuh/SAMPLE_RUN.md`), Elastic and Splunk each wait for one live run.
- **Deployment (D-67):** self-hosted on the user's or a small business's own machine; one tenant per installation is
  the normal case. LAN HTTPS uses Caddy's internal CA (`HC_TLS_MODE=internal`, D-72); install guide:
  `docs/INSTALL.md`. AI provider: paid Gemini, still off by default (D-68).
- **Phase 4 (n8n/Wazuh SOAR) is cancelled.** Zabbix and Microsoft Defender XDR are out of the kit's scope (owner,
  2026-11-05).
- Read `SPEC.md`, `DECISIONS.md`, `ARCHITECTURE.md` and `TELEGRAM.md` before non-trivial work.
- The owner writes in Vietnamese. Code, comments and docs are in English. `README.vi.md` is the Vietnamese overview.
  Plans for the owner's approval live in `docs/plans/` and are written in Vietnamese.

## 0. When something is unclear: ask, never guess

If a task touches an open question (Q*, TQ*, IQ* in `SPEC.md` §9), conflicts with a decision in `DECISIONS.md`, or would
need a new assumption about the tenant environment: **stop and ask the owner.**

Do not "temporarily" change these defaults:
- pull delivery;
- LLM off;
- Windows-only hunts;
- schema `2.0`;
- auto-block off;
- Telegram digest-only for intelligence (ops alerts are opt-in and carry no intelligence, D-65);
- no extra query languages in packs.

## 1. Mandatory constraints (never break)

1. **Zero-Internal-Access.** Never add code that connects into a tenant network or stores tenant-internal data (internal IPs, hostnames, agent groups, log lines, hit counts). Internal values travel only as `target_scope` or `${HC_*}` placeholders from `ScopePlaceholder`. The manifest must keep rejecting private ranges.
2. **The LLM only proposes detection logic.** Blocklists, confidence, severity, hints, TTL, lookback and task IDs are computed by code. Every LLM rule passes all gates in `app/compiler/ai_compiler.py`. Every call writes an `ai_compilations` row. The output schema (`compiler/draft.py`) may only be *narrowed*, never widened, without updating `docs/AI_RISK_ASSESSMENT.md`.
3. **No tenant data in prompts.** Evidence is built only from cluster data (`services/ai_service.build_evidence`). Keep the assertion in `tests/test_phase3_integration.py`.
4. **No credentials at rest.**
   - Leak parsing drops passwords immediately.
   - Accounts become `ref = HMAC(HMAC(secret, "account-ref/v1"), lower(account))` plus a masked form.
   - Never persist Telegram message text or attachments, MalwareBazaar samples, or full bot tokens or webhooks.
   - Never use attacker credentials.
5. **Never execute or detonate** PoCs, stagers or samples. Treat them as text, with size caps (archives 64 MB, files and OSV advisories 64 KB, favicon pages and icons 512 KB, decompression 2 MB).
6. **Whitelist per hostname** (`block` / `hunt_only` / `drop`). Never whitelist by parent domain on shared platforms (PSL private suffixes, LOTS entries). Never auto-block a parent domain.
7. **Wire contract.**
   - The signature is `sha256=HMAC(secret, f"{ts}." + raw_body)`; tolerance 300 s.
   - Contract changes are additive and optional only.
   - After any change in `app/schemas/`, regenerate `contracts/`.
   - Contract guardrails may be tightened, never loosened.
8. **Queries must be testable.** The Wazuh DSL is emitted only by `compiler/wazuh_dsl.py` and must be evaluable by `compiler/harness.py`. Packs carry no KQL (D-63); `kql_defender` stays in the schema only for older packs, with its guardrails. Every query is ≤ 64 KB.
9. **Determinism.** No randomness in pack content. Lists are sorted. Re-issue a pack only when its substance changes.
10. **Telegram bot (Phase T).**
    - Bot API identity (`HC_TGBOT_*`), never the Telethon CTI account (`HC_TELEGRAM_*`).
    - Allowlist on chat **and** user; deny by default, never reply to strangers.
    - Commands read the DB only — no network requests to user input.
    - IOCs defanged, accounts masked, all dynamic text HTML-escaped, AI text labelled `[AI]`.
    - The token is scrubbed from every error and log.
11. **No SOAR features.** HuntCompiler never runs hunts or response actions. Integrations are docs and examples, not vendor code. The reference consumer in `integration_kit/` runs on the integrator's side: it never imports `app`, never ships in the image, and HuntCompiler never runs it.
12. **Secrets.** They live only in the environment, referenced by name. Tenant secrets are Fernet-encrypted in the DB; tokens are stored as SHA-256. Never log secrets, tokens, the Telegram session or raw leak text.
13. **Active probes go through `app/core/netguard.py`** (D-46): resolve first, public addresses only, ports 443/80, connect to the validated IP, re-validate every redirect. Never open a connection to an attacker-supplied host any other way.

## 2. Code conventions

- **Python 3.12** with full type hints. `from __future__ import annotations` in modules.
- **Pydantic v2.** Contracts use `extra="forbid"`. Normalise in validators (lower-case, IDNA, sort, dedup).
- **Enums** are `StrEnum` and append-only. In the DB they use `str_enum()` (VARCHAR + CHECK), never a native PG ENUM.
- **Async SQLAlchemy 2.** Celery tasks run async code via `worker.runtime.run_with_engine` (NullPool, fresh loop) and use `single_flight` locks for sweeps.
- **External I/O**:
  - goes through `collectors.base.http_client()` / `get_json()` (User-Agent, Retry-After);
  - has explicit size caps and timeouts;
  - is isolated so one failing source never aborts the others.
- **Parsers are pure functions** separate from fetchers, and are tested on fixtures shaped like the real data.
- **Templates** are built with `_rule()` / `_task()` and wrapped in `safe()`, so one broken template cannot stop pack building.
- **Lint and format:** `ruff` (line length 120; `# fmt: skip` only for data tables). The test files and three data-heavy modules have per-file E501 ignores in `ruff.toml`.
- **Examples** use `.example` / `example.com` domains and RFC 5737 IPs. Never use real victim or tenant data in fixtures.
- **Lure and malware-like fixtures are assembled at runtime** (string pieces joined in the test, see `tests/test_phase2_detectors.py`). Windows Defender and other AV products quarantine source files that contain a literal ClickFix lure.

## 3. Commands

```bash
# environment
python3.12 -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt

# tests (unit) and with PostgreSQL integration (disposable DB)
pytest -q
HC_TEST_DATABASE_URL=postgresql+asyncpg://user:pass@127.0.0.1:5432/hc_test pytest -q

# lint / format
ruff check . && ruff format --check .

# migrations
alembic revision --autogenerate -m "<change>"
alembic upgrade head && alembic check

# regenerate JSON Schemas after schema changes
python -m scripts.export_contracts

# dependencies (edit requirements.in, then lock with hashes)
uv pip compile --generate-hashes --python-version 3.12 --python-platform x86_64-manylinux_2_28 -o requirements.txt requirements.in

# stack
cp .env.example .env
docker compose up -d --build
docker compose run --rm api python -m scripts.load_manifest config/tenant_manifest.yaml
curl -s http://127.0.0.1:8000/readyz

# Telegram bot (Phase T): not started by a plain `up` (compose profile); setup in TELEGRAM.md §8
docker compose up -d telegram-bot

# Phase H profiles: HTTPS (needs HC_PUBLIC_HOSTNAME), daily backups, self-hosted CertStream
docker compose --profile edge up -d caddy
docker compose --profile backup up -d backup
docker compose --profile certstream up -d certstream-server

# one-time Telegram research-account session
python -m scripts.telegram_login

# Integration Kit (integrator side, own dependencies; see integration_kit/README.md)
uv pip compile --generate-hashes --python-version 3.12 --python-platform x86_64-manylinux_2_28 -o integration_kit/requirements.txt integration_kit/requirements.in
python -m integration_kit.reference_consumer convert pack.json --platform splunk
```

## 4. Definition of done

### For any change, all of these hold

- [ ] `pytest -q` passes **with** `HC_TEST_DATABASE_URL` set (integration included).
- [ ] `ruff check .` and `ruff format --check .` are clean.
- [ ] If models changed: a new Alembic revision exists, and `alembic upgrade head && alembic check` reports no drift.
- [ ] If schemas changed: `contracts/` is regenerated and the example pack still validates.
- [ ] New behaviour has tests, including a negative test for every new guardrail.
- [ ] No constraint in §1 is weakened; no secret or real personal data appears in code, fixtures or logs.
- [ ] Docs are updated:
  - `README.md` for user-visible changes, plus the matching section of `README.vi.md`;
  - `DECISIONS.md` for any new decision (with the rejected alternatives);
  - `docs/AI_RISK_ASSESSMENT.md` for anything the LLM reads or returns.

### Additionally for new features

- [ ] **New external source:**
  - pure parser with real-shaped fixtures;
  - size caps and fail isolation;
  - a dedup key;
  - setting(s) in `config.py` and `.env.example`;
  - an entry in the external-dependencies table in `ARCHITECTURE.md`.
- [ ] **New hunting template:**
  - compiles to DSL and is harness-testable;
  - ≤ 64 KB;
  - declares `required_telemetry` and placeholders.
- [ ] **New AI input or output:** the risk register is updated, and a fake-provider test covers the new path.

### For a phase

- It is **Built** when the criteria in `SPEC.md` §6 are ticked.
- It is **Verified** only when the *Live* checks pass. Whether that is required is Q14 — report both states, never round "Built" up to "Verified".

## 5. Known gaps (do not paper over; fix or ask)

- **Never run against the live service:** URLScan, GitHub code search (needs a token), Gemini, Telegram CTI
  (Telethon), HIBP and MalwareBazaar. **Run live** (2026-11-14/15): the Docker image build, CISA KEV, FIRST EPSS,
  GitHub repository search without a token, the reference datasets including the OSV per-advisory fetch, and Caddy's
  internal-CA HTTPS. The Bot API answered `/status`, `/digest` and `/latest` for the owner (2026-11-05). The Wazuh DSL
  is tested on the official Wazuh indexer 4.14.7, OpenSearch 2.19.5, including `case_insensitive`, on 2026-11-08.
- **JARM pinning uses pyjarm 0.0.5 internals** (`processors/pivot.py::_pinned_jarm`). Re-run `tests/test_netguard.py` after any pyjarm upgrade.
- **Wazuh stores Windows event values with doubled backslashes** (D-53). The DSL emitter and the harness account for
  it; any new Wazuh-side value or test document must too.
- **Integration Kit:** Wazuh tested end to end (2026-11-08); no run yet against a real Elasticsearch or Splunk. pySigma's `ecs_windows` mapping uses `.caseless` process fields that exist in Elastic Defend data; other Elastic sources may need `ecs_windows_old`.
- **Collectors run only on schedule.** After a fresh start, reference datasets arrive at the next 6-hourly slot and HIBP at 03:30 UTC; trigger a first run by hand (`celery -A app.worker.celery_app:celery_app call collectors.reference_sync`).
- **The default public CertStream endpoint delivers nothing:** `wss://certstream.calidog.io/` accepted a connection but sent no certificate within 20 s (2026-11-05). Self-host certstream-server-go and set `HC_CERTSTREAM_URL` (profile `certstream`, verified 2026-11-09).
- **Phase H closed the 2026-11-02 review findings** (dispatcher `assert`, Shodan pivot, LICENSE, CRLF contracts) and the
  hardening gaps (retention, JSON logs, rate limits, tenant enumeration, image pins). Still open: no metrics endpoint
  (D-58) and backups stay on the same host (D-60). HTTPS with a public hostname is optional since D-72. The restore
  and the self-hosted CertStream stream passed on 2026-11-09; HTTPS was checked with Caddy's local CA.
- **Worker memory:** about 650 MiB. The MISP warninglists (~300 MiB) are loaded once before the pool forks and
  shared by the 4 task processes (D-75, measured 2026-11-15). Keep that preload when changing the worker start-up.
- **`pip-audit` flags `diskcache` 5.6.3** (PYSEC-2026-2447, pickle in the cache directory; no fixed version). It comes
  with pySigma, which uses it only to cache MITRE data that HuntCompiler never loads. CI ignores that one ID (owner,
  2026-11-15, D-74); drop the exception once a fixed version is locked.
- **A blank `.env` value means "not set"** (D-62). Never test a key with `is None` alone in new code paths that read
  the environment some other way.
- **Coverage gaps:** V1 token replay, device code and OAuth consent (Q6); V2 WAF export (Q9); V3 process+network correlation; V6 SEO installers; Linux (Q7).

## 6. Where things are

```
app/core        settings, crypto, signing, netguard (SSRF)   app/schemas   contracts, enums, validators
app/collectors  L1 sources + Celery tasks          app/processors   L2 whitelist, unpacker, pivot, matcher, leak redactor
app/compiler    L3 DSL, harness, templates, AI, scoring
app/services    clustering, packs, AI evidence     app/dispatch     push      app/api   pull, feedback, health
app/integrations/telegram   (Phase T) Bot API client, formatting, digest, bot
app/worker      Celery app, runtime, health heartbeats (Redis)
migrations/     4 revisions                        contracts/       JSON Schemas + example pack
config/         sample tenant manifest             scripts/         load_manifest, export_contracts, telegram_login
docs/           AI_RISK_ASSESSMENT.md, plans/ (Vietnamese)   tests/   349 tests (unit + PostgreSQL integration)
integration_kit/  Phase I: README, guides (Wazuh, Elastic, Splunk), reference consumer (integrator side, own deps)
```
