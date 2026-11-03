# CLAUDE.md — OutSight HuntCompiler

Internet-side **API service** that turns external threat intelligence into signed **Hunting Pack v2.0** JSON. Any
SIEM/SOAR consumes the packs (Integration Kit). People use a Telegram digest and command bot.

- Version 0.4.0. Phases 1, 2, 2b, 3 and **T** (Telegram, see `TELEGRAM.md`) are built. Phase T is *Built*, not
  *Verified*, until the owner's manual checklist in `TELEGRAM.md` §9 passes.
- **Phase 4 (n8n/Wazuh SOAR) is cancelled.**
- Next: **Phase I** (Integration Kit), which waits for IQ1–IQ3.
- Read `SPEC.md`, `DECISIONS.md`, `ARCHITECTURE.md` and `TELEGRAM.md` before non-trivial work.
- The owner writes in Vietnamese. Code, comments and docs are in English. `README.vi.md` is the Vietnamese overview.

## 0. When something is unclear: ask, never guess

If a task touches an open question (Q*, TQ*, IQ* in `SPEC.md` §9), conflicts with a decision in `DECISIONS.md`, or would
need a new assumption about the tenant environment: **stop and ask the owner.**

Do not "temporarily" change these defaults:
- pull delivery;
- LLM off;
- Windows-only hunts;
- schema `2.0`;
- auto-block off;
- Telegram digest-only;
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
8. **Queries must be testable.** The Wazuh DSL is emitted only by `compiler/wazuh_dsl.py` and must be evaluable by `compiler/harness.py`. KQL must pass `translate.lint_kql`. Every query is ≤ 64 KB.
9. **Determinism.** No randomness in pack content. Lists are sorted. Re-issue a pack only when its substance changes.
10. **Telegram bot (Phase T).**
    - Bot API identity (`HC_TGBOT_*`), never the Telethon CTI account (`HC_TELEGRAM_*`).
    - Allowlist on chat **and** user; deny by default, never reply to strangers.
    - Commands read the DB only — no network requests to user input.
    - IOCs defanged, accounts masked, all dynamic text HTML-escaped, AI text labelled `[AI]`.
    - The token is scrubbed from every error and log.
11. **No SOAR features.** HuntCompiler never runs hunts or response actions. Integrations are docs and examples, not vendor code.
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

# one-time Telegram research-account session
python -m scripts.telegram_login
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
  - KQL passes lint (or is `None`);
  - ≤ 64 KB;
  - declares `required_telemetry` and placeholders.
- [ ] **New AI input or output:** the risk register is updated, and a fake-provider test covers the new path.

### For a phase

- It is **Built** when the criteria in `SPEC.md` §6 are ticked.
- It is **Verified** only when the *Live* checks pass. Whether that is required is Q14 — report both states, never round "Built" up to "Verified".

## 5. Known gaps (do not paper over; fix or ask)

- **Never run against the live service:** URLScan, GitHub search, CISA/FIRST, Shodan, Gemini, Telegram (Telethon and the Bot API), HIBP, MalwareBazaar, the OSV per-advisory fetch (index format and file sizes checked 2026-11-02), the Docker image build, and a real Wazuh indexer (including `case_insensitive` support).
- **JARM pinning uses pyjarm 0.0.5 internals** (`processors/pivot.py::_pinned_jarm`). Re-run `tests/test_netguard.py` after any pyjarm upgrade.
- **Phase 2 tests claimed earlier but missing from the repository:** brand matcher, AiTM scoring, clipboard-lure detection, KEV↔tech-tag matching, fake-PoC heuristics, Retry-After handling, JARM against a real TLS server.
- **Review findings not fixed yet (2026-11-02):** `assert` in `dispatch/dispatcher.py` (vanishes under `python -O`); `ShodanPivot` and the cluster states `merged`/`suppressed` are never used; no LICENSE file; `scripts/export_contracts.py` writes platform line endings (CRLF on Windows), so regenerate contracts on Linux or normalise to LF.
- **No retention job** for `raw_intel_events` and `ai_compilations`. No structured logging or metrics. No API rate limiting. Feedback errors allow tenant-slug enumeration. The base image is not pinned by digest.
- **Coverage gaps:** V1 token replay, device code and OAuth consent (Q6); V2 WAF export (Q9); V3 process+network correlation; V6 SEO installers; Linux (Q7).

## 6. Where things are

```
app/core        settings, crypto, signing, netguard (SSRF)   app/schemas   contracts, enums, validators
app/collectors  L1 sources + Celery tasks          app/processors   L2 whitelist, unpacker, pivot, matcher, leak redactor
app/compiler    L3 DSL, KQL, harness, templates, AI, scoring
app/services    clustering, packs, AI evidence     app/dispatch     push      app/api   pull, feedback, health
app/integrations/telegram   (Phase T) Bot API client, formatting, digest, bot
app/worker      Celery app, runtime, health heartbeats (Redis)
migrations/     4 revisions                        contracts/       JSON Schemas + example pack
config/         sample tenant manifest             scripts/         load_manifest, export_contracts, telegram_login
docs/           AI_RISK_ASSESSMENT.md              tests/           170 tests (unit + PostgreSQL integration)
```
