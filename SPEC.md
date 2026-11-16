# OutSight HuntCompiler — Specification

| | |
|---|---|
| Code version | 0.4.0 (Phases 1, 2, 2b, 3, T, I, H, R and the approved Q items built; H verified live on 2026-11-15; T and I not yet fully verified live, Wazuh tested on 2026-11-08; Phase 4 cancelled on 2026-11-01) |
| Status date | 2026-11-16 |
| Owner | The project owner |
| Companion docs | DECISIONS.md · ARCHITECTURE.md · CLAUDE.md · TELEGRAM.md |

Items marked **(Qn)** depend on an open question in §9. Until it is answered, the current behaviour stands and
must not be changed by guesswork.

---

## 1. Purpose

OutSight HuntCompiler is an **Internet-side API service** for automated threat intelligence (TI) and threat hunting
(TH), assisted by AI.

1. It watches external signals: certificate transparency, URLScan, CISA KEV/EPSS, GitHub PoCs, Telegram CTI, breach data, LOLDrivers, LOLRMM, HijackLibs, OSV and MalwareBazaar.
2. It pivots on attacker infrastructure and de-obfuscates payloads.
3. It **compiles the results into signed "Actionable Hunting Packs v2.0"**: Sigma rules plus a ready-made Wazuh OpenSearch DSL query (Defender KQL removed by D-63).

**Who uses it:**
- **Machines** — any SIEM/SOAR (the Integration Kit covers Wazuh, Elastic and Splunk) pulls packs over the API or receives them by webhook, then runs the hunts itself. HuntCompiler never runs hunts and never touches a consumer network. Integrations are documented in the **Integration Kit** (guides plus examples), not shipped as vendor code.
- **People** — a **Telegram digest and command bot** (see `TELEGRAM.md`).

### Goals

1. Turn outside-in intelligence into **executable hunts**, not news feeds or raw IOC lists.
2. Never touch a consumer network. The only tenant input is a static, public-facts manifest.
3. Keep machine output executable and portable (Sigma plus compiled queries). Keep human output low-noise (periodic digest only).
4. Keep every output safe to execute automatically, even when the intelligence (or the LLM) is hostile.

### Success measures (proposed — not yet agreed)

- Every pack validates against the contract, and its queries execute without errors on the target platforms.
- An integrator can consume packs on at least one SIEM by following the Integration Kit alone, without changes to HuntCompiler.
- The owner receives a correct daily digest and can retrieve any pack's Sigma and query files from Telegram.
- No output ever contains consumer-internal data, plaintext credentials or an indicator the whitelist drops.

---

## 2. Users and roles

| Role | Who | Interacts through |
|---|---|---|
| HuntCompiler operator | Owner of the service. Manages API keys, tenant manifests and secrets; reviews AI audits | `.env`, `config/tenant_manifest.yaml`, `scripts/*`, PostgreSQL |
| API consumer | Any SIEM/SOAR integration built by a tenant | Pull API, push webhook, feedback API, Integration Kit |
| SOC analyst / owner | A person reading intelligence | Telegram digest and commands (one private chat or one SOC group) |

The target deployment (personal lab and portfolio, the employer's environment, or a multi-tenant service for SMEs) is
**not settled (Q1)**. The data model is multi-tenant; the sample configuration has a single tenant.

---

## 3. Scope

### In scope

- External collection for the six attack vectors in §4.
- Pivoting (JARM, favicon MurmurHash3, URLScan), static stager de-obfuscation, and per-hostname whitelisting.
- Detection compilation:
  - Sigma → Wazuh DSL (case-insensitive); no Defender KQL (D-63);
  - deterministic templates;
  - optional LLM assistance behind validation gates.
- Deterministic confidence scoring with time decay; clustering; per-tenant pack building and versioning.
- Delivery to consumers: pull (default) or push, HMAC-signed, plus a 1-bit feedback API.
- Pseudonymous credential-exposure reporting: HMAC account refs, never passwords.
- **Phase T:** Telegram digest and command bot for humans.
- **Phase I:** Integration Kit — documentation and examples for SIEM/SOAR platforms.

### Explicitly out of scope (will not be built)

- Any connection into a consumer network, agent installation, or reading of consumer logs.
- **Running hunts or acting as a SOAR.** The n8n/Wazuh reference workflow (former Phase 4) is cancelled.
- Vendor connectors maintained as code. Consumers own their integrations; we ship docs and examples.
- Storing consumer-internal data: internal IPs, hostnames, agent groups, log lines, hit counts.
- Executing, detonating or downloading malware, PoCs, stealer-log archives, Telegram attachments or MalwareBazaar samples.
- Storing or forwarding leaked passwords, or storing leaked account identities in clear.
- Using attacker credentials found in intel (Telegram bot tokens, Discord webhooks).
- LLM-decided blocklists, scores, severities or auto-response hints.
- Response actions (blocking, killing, isolation).
- Instant Telegram alerts about intelligence — the owner chose digest only (see TQ2). Opt-in ops alerts about broken jobs carry no intelligence (D-65).
- A HuntCompiler web UI or dashboard.
- Integration Kit guides for Zabbix (it cannot run log hunts) and Microsoft Defender XDR (its own integrations cover it); owner, 2026-11-05.
- Extra compiled query languages in packs: integrators convert the included Sigma (IQ1, owner, 2026-11-05).

### Not decided (neither in nor out yet)

- Linux and edge-server hunts (Q7)
- WAF virtual-patching export (Q9)
- VirusTotal checks (Q10)
- V1 hunts based on Entra logs (Q6)
- Telegram feedback buttons (TQ3)

---

## 4. Attack-vector coverage

| Vector | External intelligence | Hunting tasks today | Not yet covered |
|---|---|---|---|
| V1 AiTM, infostealer, OAuth / device code | CertStream lookalikes, URLScan AiTM path scoring, Telegram CTI, HIBP, MalwareBazaar | IOC DNS/network sightings, SHA256 execution, failed on-prem logons of exposed accounts (4625; the Entra check left with the KQL, D-63) | Session-token replay, device-code sign-in, OAuth consent (Q6) |
| V2 Edge 0/N-day | CISA KEV, EPSS, GitHub PoCs (fake-PoC heuristics), Nuclei templates | Network logon (4624/3) and admin-port connections from the edge appliance's inside IP, plus AI tasks from PoC code | WAF rule export (Q9); Linux post-exploitation (Q7) |
| V3 ClickFix / fake CAPTCHA | URLScan DOM clipboard-lure detection, recursive unpacking | RunMRU (Sysmon 13), Explorer → script host (Sysmon 1), IOC sightings, AI tasks | Process + network correlation (Sysmon 1 → 3) |
| V4 LOTS, rogue RMM, tunnels | LOLRMM | Unapproved RMM process/DNS (per-tenant exclusion), tunnel DNS, script hosts resolving Telegram/Discord APIs | — |
| V5 BYOVD, DLL side-loading | LOLDrivers, HijackLibs | Driver load by hash, unsigned driver outside `System32\drivers`, 7045 driver service from unusual path, side-loadable DLL from user-writable path | Same-folder-as-signed-EXE correlation |
| V6 Supply chain, fake PoC, SEO | OSV MAL-*, fake-PoC heuristics | Malicious package install (pip/npm/yarn/pnpm) on developer machines | SEO-poisoned installers (PuTTY, WinSCP, Advanced IP Scanner...) |

---

## 5. Features by phase

Status legend:
- **Built**: code complete with offline tests.
- **Verified**: also exercised against the live dependency.

### Phase 1 — Core infrastructure, data model, contracts · Built
- Repository layout, Dockerfile (non-root, read-only), docker-compose (PostgreSQL, Redis, migrate, api, worker, beat). Internal-only network for data stores.
- Hash-locked dependencies (85 packages).
- Tables `tenants`, `raw_intel_events`, `pivoted_clusters`, `hunting_packs` plus the link table `cluster_event_links`, created by an Alembic migration.
- Pydantic contracts: Hunting Pack v2.0, tenant manifest, sighting feedback. JSON Schemas and an example pack.
- HMAC-SHA256 signing with a timestamp window. Fernet-encrypted tenant secrets. Manifest loader CLI. Health and readiness probes.

### Phase 2 — Collectors, pivot, unpacker, guardrails · Built
- Whitelist with `block` / `hunt_only` / `drop` decided per hostname (MISP warninglists, PSL-aware).
- Static recursive stager unpacker. JARM, favicon hash, AiTM scoring. Brand lookalike matcher.
- URLScan (V1, V3), KEV/EPSS/GitHub/Nuclei (V2). CertStream watcher service. Idempotent ingestion and enrichment.

### Phase 3 — Compiler, AI, scoring, delivery · Built
- Wazuh DSL emitter (case-insensitive), query harness (KQL and its lint removed by D-63). Deterministic templates for every vector.
- Optional LLM compiler: constrained draft, 6 validation gates, audit table, cache, daily token budget.
- Deterministic scoring with per-vector half-life. Clustering. Per-tenant pack building that re-issues only when the substance changes.
- Push dispatcher (retry, back-off, dead letter). Pull API and feedback API. AI risk assessment.

### Phase 2b — Leak monitoring and reference datasets · Built
- Leak redactor that produces HMAC account refs and drops passwords. Telegram CTI (text only). HIBP domain search.
- LOLDrivers, LOLRMM, HijackLibs, OSV MAL-* and MalwareBazaar (metadata only). Templates for V1, V4, V5 and V6.
- `affected_accounts` in packs. Credential-exposure packs notify even with zero hits.

### Phase 4 — Tenant SOAR integration · **Cancelled (2026-11-01)**

HuntCompiler is an API service; consumers run hunts with their own tooling. The integration surface (pull API, push
webhook, feedback API, placeholders, `required_telemetry`, `evaluable`) stays and is documented by Phase I.

### Phase T — Telegram digest and command bot · Built, not Verified (see `TELEGRAM.md`)

- **SSRF guard for active probes** (`app/core/netguard.py`, D-46): public addresses only, ports 443/80, the validated IP pinned for the connection, redirects re-validated.
- Bot API client: separate identity from the Telethon CTI account; allowlist on chat and user; token scrubbed from errors and logs.
- Periodic digest only:
  - grouped by cluster; only clusters with a new pack in the window are listed;
  - sections for credential exposure, edge CVEs, dataset updates and health;
  - idempotent cursor (pack `seq` and event link time) stored in `telegram_digests`;
  - collector health from Redis heartbeats (D-48).
- Commands: `/status`, `/digest` (preview), `/latest`, `/pack` (JSON, Sigma and query files), `/ioc`, `/cve`. Commands read the database only. `HC_TGBOT_TENANTS` limits the digest and every command.
- Fixes shipped with Phase T: OSV is read through its ecosystem index (D-47; the V6 dataset never loaded before), the V1 exposure KQL uses `EntraIdSignInEvents` (all KQL removed later, D-63), and the IOC network task matches a host and its subdomains only.

### Phase I — Integration Kit · Built, not Verified (see `integration_kit/README.md`)

- Platforms, in this order: **Wazuh**, **Elastic**, **Splunk** (owner, 2026-11-05). Zabbix and Microsoft Defender XDR are out of scope.
- A reference consumer in Python (`integration_kit/reference_consumer/`), standalone, with its own hash-locked dependencies:
  - pull (recommended) or a push receiver; HMAC verified on the raw body, 300 s window, de-duplication on `pack_id`;
  - every pack re-validated against the published JSON Schema and the guardrails, even with a valid signature;
  - placeholders substituted from local values; exposed-account refs resolved against a local directory export;
  - Wazuh runs the pack's DSL; Elastic (EQL by default) and Splunk run the Sigma rule converted with pySigma (IQ1);
  - feedback limited to `sighting` and `evaluable`; tasks over a hit cap count as broken rules; nothing is ever blocked.
- One guide per platform: prerequisites (Wazuh archives, Sysmon events, read-only accounts), settings, what is sent, and the live check.
- Live status: Wazuh tested end to end on the official Wazuh indexer 4.14.7 (2026-11-08, 12 of 12 tasks right after D-53). Elastic and Splunk: not yet.

### Phase H — Production hardening · Built and Verified (2026-11-15; decisions D-54 to D-62)

- Missing keys never break a sweep: a blank setting means "not set" (D-62); GitHub only enriches KEV signals (D-54).
- Tenant API: per-tenant rate limit, per-IP lockout after failed authentications, identical errors for unknown tenants (D-56).
- Daily retention of raw events and AI audit rows (D-57). JSON logs on demand (D-58).
- Deployment profiles: `edge` (Caddy, HTTPS from Let's Encrypt or, for a LAN, Caddy's internal CA, D-72), `backup` (daily `pg_dump`, 14 kept), `certstream` (self-hosted CertStream); every image pinned by digest (D-59 to D-61).
- Small debt: the dispatcher `assert` became a real check (a push pack whose tenant moved to pull goes to the pull API), the unused Shodan pivot is removed (D-55), contracts are written with LF, a proprietary LICENSE.

### Phase Q — Quality · in progress (plan: `docs/plans/KE_HOACH_PHASE_Q.md`)

- Approved and built on 2026-11-13: Q1 a KEV entry alone reaches the delivery threshold (D-64); Q5 opt-in ops alerts
  in Telegram (D-65); Q6 forwarded client IPs trusted from Caddy only (D-66).
- Q2 CI and Q4 GitHub re-enrichment were built in Phase R (D-74, D-71).
- Waiting for the owner: Q3 detection check on a real Windows host, Q7 off-host backups, Q8 Wazuh archive filtering.

### Phase R — Ready for self-hosting · Built, not Verified (plan: `docs/plans/KE_HOACH_PHASE_R.md`)

- R1 KEV classification (D-70): edge and internet-facing products keep the V2 pack with edge hunts; OS and desktop
  software get no edge hunts and appear in the digest section "Exploited CVEs to patch"; a product listed in a tenant's
  `login_portals` counts as internet-facing for that tenant.
- R2 quieter logs (D-58): HTTP client request lines only at DEBUG; with `HC_LOG_FORMAT=json` uvicorn's startup lines
  are JSON too.
- R3 CI (D-74): GitHub Actions workflow file and a hash-locked `requirements-dev.txt` with `pip-audit`. Runs once the
  owner pushes.
- R4 daily retry of missed GitHub data for KEV entries (D-71).
- R5 self-hosting (D-72): Caddy `HC_TLS_MODE=internal` for a LAN, loopback HTTP for a consumer on the same machine,
  `docs/INSTALL.md` with measured resource needs; the public-hostname check of Phase H becomes optional.
- Q11 policy (D-73): Telegram CTI on public channels only, HIBP for own verified domains only.
- Waiting: R6, the first live Gemini run (needs the owner's key, D-68).

### Backlog (not scheduled)

1. V1 Entra-log hunts (Q6). V2 WAF export (Q9). V3 process+network correlation. V6 SEO installers.
2. A metrics endpoint (D-58). Off-host copies of the backups.

---

## 6. Phase completion criteria

A phase is **Built** when all of these hold:
- Its features are implemented.
- The whole test suite passes, including the PostgreSQL integration tests.
- `ruff check` is clean and `alembic check` reports no drift.
- JSON Schemas are regenerated.
- The documentation is updated.

A phase is **Verified** when its live checks below also pass. Whether "Verified" is required to close a phase is **Q14**.

### Phase 1
- [x] All tables are created by migration; upgrade → downgrade → upgrade works on PostgreSQL 16.
- [x] The example pack validates; every guardrail has a negative test.
- [x] Manifest loader: validate-only, create and update paths, missing-secret error.
- [x] *Live:* `docker compose up -d --build` reaches healthy for all services, and `/readyz` returns 200: observed in a
  test deployment on 2026-11-08 (every health check green, `/readyz` 200). If a published port stays unbound after a
  Docker restart, `docker compose up -d --force-recreate api` restores it.

### Phase 2
- [x] Whitelist decisions are tested on the real MISP warninglists, including the shared-platform cases.
- [x] The unpacker resolves ≥ 3 nested layers; decompression is bounded.
- [x] JARM against a real TLS server: a local self-signed server, driven through the pinned scanner (`tests/test_phase2_detectors.py`, 2026-11-05).
- [ ] *Live:* each collector runs once with real keys (URLScan query syntax tuned to the plan, GitHub, CISA, FIRST).
- [x] *Live:* CertStream receives certificates from the chosen endpoint: the self-hosted certstream-server-go v1.10.1
  (profile `certstream`) fed the real watcher within seconds, heartbeat refreshed every minute (2026-11-09).

### Phase 3
- [x] The harness proves positive samples match and negative samples do not, including case-insensitivity.
- [x] Every AI gate has a test with a fake provider.
- [x] End-to-end on PostgreSQL: signals → clusters → packs for two tenants → no re-issue → push with retry → signed pull → feedback.
- [ ] *Live:* one Gemini run on a real KEV PoC and on a real ClickFix sample, with the audit rows reviewed by a human.
- [x] *Live:* the compiled DSL executes on the Wazuh indexer, and `case_insensitive` is confirmed on that version: official
  Wazuh indexer 4.14.7 (OpenSearch 2.19.5) with the official index template, 2026-11-08 (`integration_kit/wazuh/SAMPLE_RUN.md`).
  The run found the doubled-backslash bug fixed by D-53. Re-check if your deployment runs another major version.

### Phase 2b
- [x] Dataset parsers are validated on the real LOLDrivers, LOLRMM and HijackLibs files; every template stays under 64 KB.
- [x] No password or clear account identity appears in any signal, row or pack (asserted in tests).
- [ ] *Live:* Telegram (research account, Q11), HIBP (verified domain), MalwareBazaar and OSV index plus advisory runs (index format and file sizes checked 2026-11-02).
  Progress 2026-11-08 (test deployment): the reference sync, OSV included, runs and builds the V4, V5 and V6 clusters.
  Telegram CTI, HIBP and MalwareBazaar are not configured yet.

### Phase T (criteria in `TELEGRAM.md` §9)
- [x] SSRF guard merged, with tests for the loopback, RFC1918, metadata-address and redirect cases.
- [x] All automated criteria in `TELEGRAM.md` §9 pass (2026-11-02, 170 tests with PostgreSQL).
- [ ] *Live:* the owner's manual checklist in `TELEGRAM.md` §9 passes in the private chat and in the SOC group.

### Phase I
- [x] For Wazuh, Elastic and Splunk, a guide and the reference consumer take an integrator from zero to an executed hunt task and posted feedback (tested with fake platform APIs, and end-to-end through the real HuntCompiler API on PostgreSQL).
- [x] The consumer verifies the HMAC on the raw body, rejects a stale or replayed pack, and re-validates every pack.
- [ ] *Live:* each guide is run once against a real instance of the platform. Wazuh: done on the official Wazuh
  indexer 4.14.7, 2026-11-08 (`integration_kit/wazuh/SAMPLE_RUN.md`). Elastic, Splunk: not yet.

### Phase H
- [x] A blank key reports `not_configured`; a GitHub failure or missing token keeps the KEV signal (tests, with a negative test that a KEV feed failure still fails the sweep).
- [x] Rate limits, the per-IP lockout and identical unknown-tenant errors, through the real API on PostgreSQL.
- [x] Retention keeps events of active clusters and purges the rest, on PostgreSQL; `0` keeps everything.
- [x] JSON log lines parse and still scrub the bot token. A push pack whose tenant switched to pull goes to the pull API.
- [x] The compose file validates with every profile.
- [x] *Live:* a tenant pulls a pack over HTTPS through Caddy. 2026-11-15 with `HC_TLS_MODE=internal` and the LAN name
  `huntcompiler.lan`: Caddy issued the certificate from its local CA; the reference consumer, trusting only Caddy's
  root certificate, pulled 3 packs with valid signatures and re-validated them; a wrong HMAC secret dropped all 3;
  without the root certificate or under another name the TLS handshake failed; an unknown mode stops Caddy.
  Earlier, 2026-11-09, with `localhost`
  and Caddy's local CA: TLS 1.3 verified; only `/healthz` and `/api/v1/*` reachable (`/readyz`, `/docs`, `/` answer
  404); HSTS set, no `Server` header; a pack pulled with a valid HMAC signature; the per-IP lockout applied to the
  real client IP taken from `X-Forwarded-For`; API logs in JSON. A public hostname with a Let's Encrypt certificate
  is **optional** since D-72 (self-hosted installations use Caddy's internal CA).
- [x] *Live:* a restore from a `backup` dump (2026-11-09): three runs kept the newest two; after `hunting_packs` was
  dropped (pull answered 500), the README steps restored every row and the pack pulled again with a valid signature.
- [x] *Live:* the self-hosted CertStream server delivers certificates to the watcher (2026-11-09).

### Phase Q (approved items)
- [x] Q1: a KEV-only CVE scores 70, stays deliverable for the 7-day KEV window, and reaches only tenants whose tech tags match (unit test and PostgreSQL test, with negatives).
- [x] Q5: ops alerts are off by default; on, they fire after N consecutive failures or when stale, once per cooldown, then "recovered"; unknown and not-configured jobs never alert; text is escaped.
- [x] Q6: the compose file trusts forwarded headers from Caddy's fixed `edge` address only (no wildcard); uvicorn's middleware ignores the header from any other peer.
- [x] *Live (Docker, 2026-11-13):* Q6 on a real `edge` network, with the API started first as in production: a stand-in at Caddy's fixed address was trusted; a container on `edge`, a container on `egress` and a direct call through the published port all sent a spoofed `X-Forwarded-For` and were logged with their real address. The run found that the API's dynamic address could take Caddy's; fixed with `ip_range` (D-66).
- [ ] *Live:* Q5 alerts seen in the owner's Telegram chat; Q6 with the real Caddy (a public hostname is optional, D-72).

### Phase R
- [x] R1: `classify_kev` sorts known edge products, OS and desktop software and unknown products (unknown means patch
  reminder only); on PostgreSQL a Windows KEV entry gives no pack but a digest patch reminder, a tenant whose login
  portal runs the product gets the edge hunts, the tenant filter applies, and an edge KEV entry is never a reminder.
- [x] R2: HTTP client loggers are held at WARNING unless DEBUG (API, worker, beat, watcher, bot); uvicorn's handlers
  get the JSON formatter before its startup lines; text format leaves them alone.
- [x] R3: the workflow pins every action by commit SHA and the PostgreSQL image by digest, has a read-only token and
  no triggers for untrusted code; the dev lock carries hashes and every runtime pin unchanged.
- [x] R4: on PostgreSQL a KEV entry that missed GitHub data is retried, its score rises, and the pack follows when the
  tenant's threshold is reached; no code search without a token; entries over the attempt cap or out of the window are
  left alone; a failed retry keeps earlier data.
- [x] R5: Caddy accepts only `public` and `internal` (checked with the real Caddy image); the consumer allows
  `http://` to loopback only (negative tests for LAN addresses, lookalike names and user info).
- [x] *Live (Docker, 2026-11-15):* R1 on the real KEV catalog (edge entries got packs, Office and Chromium became
  patch reminders); R2 (no httpx lines, every API line JSON); R4 (a GitHub 403 kept the data and reported
  `failing`; after the rate limit reset 4 entries gained PoC data and scored 80 instead of 70); R5.1 HTTPS in a
  LAN through Caddy's internal CA; resource needs measured (`docs/INSTALL.md`). D-75 cut the worker from 1.5 GiB
  to about 650 MiB.
- [ ] *Live:* CI green on GitHub after the owner's push; R6 Gemini run.

---

## 7. Non-functional requirements

| Area | Requirement |
|---|---|
| Safety of outputs | Packs pass the contract guardrails: no `script`/`runtime_mappings` in DSL; no `externaldata`/`http_request`/control commands in KQL (field retired by D-63, guardrail kept for older packs); ≤ 64 KB per query; ≤ 25 tasks; IPs global and ≥ /24 (IPv4) or ≥ /48 (IPv6). |
| Privacy | No tenant-internal data, no plaintext credentials, no clear account identities. The LLM never receives tenant data. |
| Idempotency | Signals are unique on (source, dedup hash). Packs are unique on (tenant, content hash). Feedback: the first answer wins. |
| Reliability | Push retries with back-off, then dead letter. Sweeps use a single-flight lock. One failing source never blocks the others. |
| Cost control | LLM is off by default, with a daily token budget, a cache keyed on evidence hash + prompt version + model, and at most 4 rules per call. |
| Auditability | Every LLM call is stored with input hash and size, redaction count, raw output and per-rule verdicts. |
| Supply chain | Hash-locked dependencies; slim non-root image; data stores without Internet egress. |

---

## 8. Contradictions found in the original concept

| # | Contradiction | Current handling | Needs |
|---|---|---|---|
| C1 | "Never connect to the tenant LAN" vs "push the pack to the SOAR webhook" | Pull is the default; push is optional for integrators | Confirmation (Q2) |
| C2 | "Drop all Tranco Top-1M domains" vs hunting tunnel and shared-hosting infrastructure | Per-hostname `block` / `hunt_only` / `drop` | Confirmation |
| C3 | "The LLM generates Sigma YAML" vs output safety | The LLM fills a constrained draft; code renders Sigma, DSL and KQL | Confirmation |
| C4 | V2 lists Linux post-exploitation vs Windows-only templates | Windows-only templates | Decision (Q7) |
| C5 | "Zero-noise retro-hunt" vs Wazuh indexing only alert-generating events | **Moved to consumers** since Phase 4 was cancelled. The Integration Kit must state the archive requirement for Wazuh | Phase I documentation |
| C6 | "Notify only on sighting" vs credential exposure being an incident in itself | The pack still sets `notify_only_on_sighting=false` for consumers. Telegram is digest-only, so exposure waits for the digest | Decision (TQ2) |
| C7 | "Anonymous 1-bit feedback" vs authenticated feedback with a second bit | Read as content-minimal, not anonymous | Confirmation |
| C8 | "Local-first" philosophy vs a cloud LLM | LLM off by default; provider abstraction | Decision (Q12) |
| C9 | Defender KQL in the contract vs no defined execution path | KQL generated and linted; the Integration Kit does not run it (Defender XDR out of scope, 2026-11-05) | **Answered 2026-11-10:** no; packs carry no KQL (D-63) |
| C10 | Confidence grows with sightings vs no SOAR feedback loop after Phase 4 was cancelled | Confidence is evidence-only unless consumers send feedback | Decision (TQ3) |

---

## 9. Open questions

Nothing below is guessed into the code beyond the stated default.

### General

| ID | Question | Blocks | Current default |
|---|---|---|---|
| Q1 | Who is this for: personal lab and portfolio, the employer's environment, or a hosted multi-tenant service for SMEs? | Legal review, hosting, multi-tenancy effort, Telegram sourcing | **Answered 2026-11-14:** personal use, research, or small businesses only (D-67) |
| Q2 | Confirm pull as the default for integrators. Is push also documented in the Integration Kit? | Phase I guides | **Answered 2026-11-05:** pull is the main path; the kit adds a short push receiver example |
| Q3 | Where does HuntCompiler run (public VPS behind TLS, or a lab)? How do integrators reach it? | Live checks | **Answered 2026-11-14:** self-hosted on the user's or the business's own machine (D-67) |
| Q6 | Should V1 identity hunts (token replay, device code, OAuth consent) be built for consumers that have Entra sign-in logs? | V1 coverage | **Answered 2026-11-14:** documentation only, not built or tested (`integration_kit/ENTRA_GUIDE.md`, D-69) |
| Q7 | Are Linux and edge-server hunts in scope? | V2 coverage | Windows only |
| Q8 | What should `auto_block_pre_iocs` mean for integrators (which kinds of control)? | Integration Kit wording | **Answered 2026-11-05:** a hint only; blocking always needs a human decision; the reference consumer never blocks |
| Q9 | WAF virtual patching: which WAF, which format, which contract field? | V2 completeness | Not built |
| Q10 | Is a VirusTotal check required? Are a key and quota available? | V3 confidence features | Not built |
| Q11 | Telegram CTI and HIBP: which channels may legally be monitored? Is a research account available? Is the domain verified in HIBP? | Phase 2b live checks | **Answered 2026-11-14:** public channels only, read-only, from a separate research account; HIBP only for domains the user owns and has verified (D-73). Both stay off until configured |
| Q12 | LLM provider: paid Gemini key or a local model? | Enabling AI | **Answered 2026-11-14:** a paid Gemini key (D-68). AI stays off until the key and a budget are set |
| Q13 | Do additive fields stay in `2.0`, or bump to `2.1`? | Integrator validation | `2.0` |
| Q14 | Does closing a phase require its *Live* checks? | Status reporting | Reported as Built, not Verified |

Q4 (Wazuh archives), Q5 (Defender execution) and Q15 (Telegram content) are no longer blockers:
- Q4 and Q5 become Integration Kit notes.
- Q15 is answered by the content rules in `TELEGRAM.md` §2, pending the owner's confirmation.

### Telegram (Phase T)

| ID | Question | Default until answered |
|---|---|---|
| TQ1 | Is a daily 08:00 digest right, or another frequency or time? | **Answered 2026-11-02:** daily 08:00 Asia/Ho_Chi_Minh |
| TQ2 | Should credential exposure be sent immediately, as an exception to digest-only? | No |
| TQ3 | Should pack details carry feedback buttons, to keep a confidence feedback loop? | Not built |
| TQ4 | Bot language: English, Vietnamese, or configurable? | **Answered 2026-11-02:** English |

### Integration Kit (Phase I)

| ID | Question | Default until answered |
|---|---|---|
| IQ1 | Should packs carry more compiled languages (Splunk SPL, Elastic ECS DSL/ES\|QL), or should integrators convert the included Sigma themselves (sigma-cli/pySigma)? | **Answered 2026-11-05:** integrators convert the included Sigma with pySigma; the reference consumer does it; packs unchanged |
| IQ2 | What should the Zabbix integration do? Zabbix cannot run hunting queries — IOC watchlists, an alert feed, or digest-like triggers? | **Answered 2026-11-05:** Zabbix is out of scope |
| IQ3 | Which platforms, in which order? | **Answered 2026-11-05:** shared reference consumer, then Wazuh, Elastic, Splunk |
