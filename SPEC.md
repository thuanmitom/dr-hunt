# OutSight HuntCompiler — Specification

| | |
|---|---|
| Code version | 0.4.0 (Phases 1, 2, 2b, 3 and T built; Phase T not yet verified live; Phase 4 cancelled on 2026-11-01) |
| Status date | 2026-11-02 |
| Owner | Lethuan |
| Companion docs | DECISIONS.md · ARCHITECTURE.md · CLAUDE.md · TELEGRAM.md |

Items marked **(Qn)** depend on an open question in §9. Until it is answered, the current behaviour stands and
must not be changed by guesswork.

---

## 1. Purpose

OutSight HuntCompiler is an **Internet-side API service** for automated threat intelligence (TI) and threat hunting
(TH), assisted by AI.

1. It watches external signals: certificate transparency, URLScan, CISA KEV/EPSS, GitHub PoCs, Telegram CTI, breach data, LOLDrivers, LOLRMM, HijackLibs, OSV and MalwareBazaar.
2. It pivots on attacker infrastructure and de-obfuscates payloads.
3. It **compiles the results into signed "Actionable Hunting Packs v2.0"**: Sigma rules plus ready-made Wazuh OpenSearch DSL and Microsoft Defender KQL.

**Who uses it:**
- **Machines** — any SIEM/SOAR (Splunk, Wazuh, Elastic, Zabbix…) pulls packs over the API or receives them by webhook, then runs the hunts itself. HuntCompiler never runs hunts and never touches a consumer network. Integrations are documented in the **Integration Kit** (guides plus examples), not shipped as vendor code.
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
- Pivoting (JARM, favicon MurmurHash3, Shodan, URLScan), static stager de-obfuscation, and per-hostname whitelisting.
- Detection compilation:
  - Sigma → Wazuh DSL (case-insensitive) and Defender KQL;
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
- Instant Telegram alerts — the owner chose digest only (see TQ2).
- A HuntCompiler web UI or dashboard.

### Not decided (neither in nor out yet)

- Linux and edge-server hunts (Q7)
- WAF virtual-patching export (Q9)
- VirusTotal checks (Q10)
- V1 hunts based on Entra logs (Q6)
- Additional query languages in packs (IQ1)
- Telegram feedback buttons (TQ3)

---

## 4. Attack-vector coverage

| Vector | External intelligence | Hunting tasks today | Not yet covered |
|---|---|---|---|
| V1 AiTM, infostealer, OAuth / device code | CertStream lookalikes, URLScan AiTM path scoring, Telegram CTI, HIBP, MalwareBazaar | IOC DNS/network sightings, SHA256 execution, failed logons of exposed accounts (4625 + Entra) | Session-token replay, device-code sign-in, OAuth consent (Q6) |
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
- Static recursive stager unpacker. JARM, favicon hash, Shodan pivot, AiTM scoring. Brand lookalike matcher.
- URLScan (V1, V3), KEV/EPSS/GitHub/Nuclei (V2). CertStream watcher service. Idempotent ingestion and enrichment.

### Phase 3 — Compiler, AI, scoring, delivery · Built
- Wazuh DSL emitter (case-insensitive), query harness, KQL lint. Deterministic templates for every vector.
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
- Fixes shipped with Phase T: OSV is read through its ecosystem index (D-47; the V6 dataset never loaded before), the V1 exposure KQL uses `EntraIdSignInEvents`, and the IOC network task matches a host and its subdomains only.

### Phase I — Integration Kit · Not started (waits for IQ1–IQ3)

- One guide per platform, each showing:
  - how to pull or receive packs and verify the HMAC signature;
  - how to substitute placeholders;
  - how to run the tasks;
  - how to report `sighting` and `evaluable`.
- Examples per platform (scripts or config snippets), plus a generic reference consumer in Python.
- Platform notes:
  - **Wazuh** — the archives index is required.
  - **Splunk** — needs SPL (IQ1).
  - **Elastic** — needs an ECS field mapping (IQ1).
  - **Zabbix** — role to be defined (IQ2).

### Backlog (not scheduled)

1. V1 Entra-log hunts (Q6). V2 WAF export (Q9). V3 process+network correlation. V6 SEO installers.
2. Retention job for `raw_intel_events` and `ai_compilations`. Structured logging and metrics. API rate limiting.
3. Phase 2 tests that the README used to claim: brand matcher, AiTM scoring, clipboard-lure detection, KEV↔tech-tag matching, fake-PoC heuristics, Retry-After handling.
4. Review findings kept as known gaps (`CLAUDE.md` §5): dispatcher `assert`, unused `ShodanPivot` and cluster states `merged`/`suppressed`, no LICENSE.

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
- [ ] *Live:* `docker compose up -d --build` reaches healthy for all services, and `/readyz` returns 200.

### Phase 2
- [x] Whitelist decisions are tested on the real MISP warninglists, including the shared-platform cases.
- [x] The unpacker resolves ≥ 3 nested layers; decompression is bounded.
- [ ] JARM against a real TLS server. No such test exists in the repository; the pinned connection path is covered with a fake in `tests/test_netguard.py` (Phase T).
- [ ] *Live:* each collector runs once with real keys (URLScan query syntax tuned to the plan, GitHub, CISA, FIRST, Shodan).
- [ ] *Live:* CertStream receives certificates from the chosen endpoint.

### Phase 3
- [x] The harness proves positive samples match and negative samples do not, including case-insensitivity.
- [x] Every AI gate has a test with a fake provider.
- [x] End-to-end on PostgreSQL: signals → clusters → packs for two tenants → no re-issue → push with retry → signed pull → feedback.
- [ ] *Live:* one Gemini run on a real KEV PoC and on a real ClickFix sample, with the audit rows reviewed by a human.
- [ ] *Live:* the compiled DSL executes on the deployed Wazuh indexer, and `case_insensitive` is confirmed on that version.

### Phase 2b
- [x] Dataset parsers are validated on the real LOLDrivers, LOLRMM and HijackLibs files; every template stays under 64 KB.
- [x] No password or clear account identity appears in any signal, row or pack (asserted in tests).
- [ ] *Live:* Telegram (research account, Q11), HIBP (verified domain), MalwareBazaar and OSV index plus advisory runs (index format and file sizes checked 2026-11-02).

### Phase T (criteria in `TELEGRAM.md` §9)
- [x] SSRF guard merged, with tests for the loopback, RFC1918, metadata-address and redirect cases.
- [x] All automated criteria in `TELEGRAM.md` §9 pass (2026-11-02, 170 tests with PostgreSQL).
- [ ] *Live:* the owner's manual checklist in `TELEGRAM.md` §9 passes in the private chat and in the SOC group.

### Phase I (proposed criteria)
- [ ] For each chosen platform, a guide and example take an integrator from zero to an executed hunt task and posted feedback.
- [ ] Every example verifies the HMAC on the raw body and rejects a stale or replayed pack.
- [ ] *Live:* each example is run once against a real instance of the platform.

---

## 7. Non-functional requirements

| Area | Requirement |
|---|---|
| Safety of outputs | Packs pass the contract guardrails: no `script`/`runtime_mappings` in DSL; no `externaldata`/`http_request`/control commands in KQL; ≤ 64 KB per query; ≤ 25 tasks; IPs global and ≥ /24 (IPv4) or ≥ /48 (IPv6). |
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
| C9 | Defender KQL in the contract vs no defined execution path | KQL generated and linted; consumers execute it | Integration Kit note |
| C10 | Confidence grows with sightings vs no SOAR feedback loop after Phase 4 was cancelled | Confidence is evidence-only unless consumers send feedback | Decision (TQ3) |

---

## 9. Open questions

Nothing below is guessed into the code beyond the stated default.

### General

| ID | Question | Blocks | Current default |
|---|---|---|---|
| Q1 | Who is this for: personal lab and portfolio, the employer's environment, or a hosted multi-tenant service for SMEs? | Legal review, hosting, multi-tenancy effort, Telegram sourcing | Multi-tenant data model, one sample tenant |
| Q2 | Confirm pull as the default for integrators. Is push also documented in the Integration Kit? | Phase I guides | Pull |
| Q3 | Where does HuntCompiler run (public VPS behind TLS, or a lab)? How do integrators reach it? | Live checks | API on 127.0.0.1:8000, reverse proxy assumed |
| Q6 | Should V1 identity hunts (token replay, device code, OAuth consent) be built for consumers that have Entra sign-in logs? | V1 coverage | Not built |
| Q7 | Are Linux and edge-server hunts in scope? | V2 coverage | Windows only |
| Q8 | What should `auto_block_pre_iocs` mean for integrators (which kinds of control)? | Integration Kit wording | Hint only; auto-block off |
| Q9 | WAF virtual patching: which WAF, which format, which contract field? | V2 completeness | Not built |
| Q10 | Is a VirusTotal check required? Are a key and quota available? | V3 confidence features | Not built |
| Q11 | Telegram CTI and HIBP: which channels may legally be monitored? Is a research account available? Is the domain verified in HIBP? | Phase 2b live checks | Built; disabled until configured |
| Q12 | LLM provider: paid Gemini key or a local model? | Enabling AI | AI off |
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
| IQ1 | Should packs carry more compiled languages (Splunk SPL, Elastic ECS DSL/ES\|QL), or should integrators convert the included Sigma themselves (sigma-cli/pySigma)? | Sigma + Wazuh DSL + Defender KQL only |
| IQ2 | What should the Zabbix integration do? Zabbix cannot run hunting queries — IOC watchlists, an alert feed, or digest-like triggers? | Undefined |
| IQ3 | Which platforms, in which order? | Wazuh, Splunk, Elastic, Zabbix (as listed by the owner) |
