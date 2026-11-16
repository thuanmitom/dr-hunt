# OutSight HuntCompiler — Decision Log

Compact architecture decision records. Status values:

- **Accepted**: built and agreed.
- **Built, unconfirmed**: implemented as a correction to the original concept, and the owner has not explicitly confirmed it.
- **Provisional**: depends on an open question (Qn, listed at the end).

Superseded decisions are kept and marked.

Each entry: *Context → Decision → Why → Rejected alternatives → Consequences.*

---

## A. Delivery and contract

### D-01 Pull is the default delivery mode; push stays optional
**Status:** Accepted (owner confirmed pull as the main path, 2026-11-05) · Phase 1
- **Context:** The concept asks for a one-way push to the SOAR webhook and also says HuntCompiler must never connect into the tenant LAN. Push needs an Internet-reachable n8n.
- **Decision:** The tenant SOAR polls `GET /api/v1/packs?after=<seq>` over an outbound connection. Push (`delivery.mode: push`) is kept for tenants that want it.
- **Why:** No inbound exposure. It also works for a VMware lab without port forwarding or tunnels. The signing contract is identical in both modes.
- **Rejected:** push-only (opens the LAN); a VPN or tunnel into the tenant (violates zero-internal-access); a message broker shared with tenants (more infrastructure, same exposure question).
- **Consequences:** HuntCompiler must be reachable by the SOAR (Q3). The pull cursor is a monotonic `seq` column.

### D-02 HMAC-SHA256 over `timestamp + "." + raw_body`
**Status:** Accepted · Phase 1
- **Decision:** Headers `X-HuntCompiler-Timestamp`, `X-HuntCompiler-Signature: sha256=<hex>`, `X-HuntCompiler-Pack-Id`, and `X-HuntCompiler-Tenant` (feedback). The tolerance window is 300 s. Receivers de-duplicate on `pack_id`. Pulled items carry the same signature over their canonical JSON.
- **Why:** Replay resistance on top of the `sha256=<hmac>` header in the concept. Verifying the raw body avoids re-serialisation mismatches (n8n: enable *Raw Body*).
- **Rejected:** HMAC over the body only (replayable); JWS/JWT (heavier, no gain for symmetric single-producer use); mTLS only (no per-message integrity in storage or queues).

### D-03 Guardrails live in the contract, not only in the producer
**Status:** Accepted · Phase 1
- **Decision:** The Pydantic contract rejects:
  - non-global IPs, and CIDRs broader than /24 (IPv4) or /48 (IPv6);
  - all-zero JARM;
  - `script`, `runtime_mappings` and `stored_fields` in the DSL;
  - KQL control commands, `externaldata`, `http_request` and `evaluate`;
  - undeclared or unknown placeholders;
  - queries over 64 KB, or more than 25 tasks;
  - `auto_block_pre_iocs` with confidence below 80 or with an empty blocklist.
- **Why:** Packs are derived from attacker-controlled content, partly through an LLM. Shape checks alone would let a poisoned pack become a dangerous query or an over-broad block.
- **Rejected:** trusting the producer; validation only on the consumer side (both sides should validate — the Integration Kit must say so).

### D-04 Additive optional fields stay in schema 2.0
**Status:** Provisional (Q13) · Phases 1, 2b
- **Decision:** `expires_at`, `affected_accounts`, and per task `target_scope`, `required_telemetry` and `scope_placeholders` were added without a version bump.
- **Rejected:** bumping to 2.1 for each addition (pending the owner's choice).

### D-05 `required_telemetry` and an `evaluable` feedback flag
**Status:** Built, unconfirmed · Phase 1
- **Decision:** Each task declares the data it needs (e.g. `sysmon:13`). Feedback carries `evaluable=false` when that data is missing.
- **Why:** Zero hits without Sysmon 13 is *unknown*, not *clean*. Without the flag, confidence and reporting would be wrong.
- **Rejected:** a pure 1-bit `sighting` (cannot tell "clean" from "blind").

### D-06 Feedback is content-minimal, authenticated per tenant, and first-answer-wins
**Status:** Built, unconfirmed · Phase 3
- **Decision:** The body is `{pack_id, sighting, evaluable, evaluated_at}`, signed with the tenant secret. Repeats return `duplicate`. "Clean" counts only when `evaluable=true`.
- **Why:** "Anonymous" is read as *no log content leaves the tenant*. True anonymity would allow feedback poisoning.

---

## B. Zero-internal-access and privacy

### D-07 Internal values travel as scopes and placeholders
**Status:** Accepted · Phase 1
- **Decision:** Host groups are expressed as `target_scope` (an enum). Internal values are `${HC_EDGE_DEVICE_INTERNAL_IPS}`, `${HC_DMZ_HOST_IPS}`, `${HC_AFFECTED_UPNS}` and `${HC_AFFECTED_SAM_ACCOUNTS}`, substituted by the SOAR:
  - DSL: an array element equal to the placeholder is replaced by the list of values.
  - KQL: the placeholder is replaced by quoted, comma-separated values.
- **Why:** V2 needs the VPN's inside IP and V6 needs developer host groups. Storing them in HuntCompiler would break zero-internal-access.
- **Rejected:** putting internal IPs or agent groups in the manifest (the manifest now rejects RFC1918, CGNAT, ULA, loopback and link-local ranges).

### D-08 Secrets are referenced by env-var name, encrypted at rest, and tokens are hashed
**Status:** Accepted · Phase 1
- **Decision:**
  - The manifest holds `secret_env` / `api_token_env` names only.
  - HMAC secrets are stored Fernet-encrypted (MultiFernet, so keys can be rotated).
  - API tokens are stored as SHA-256 only.
  - Secrets must be at least 32 characters.
- **Rejected:** secrets in YAML; plaintext in the DB; hashing HMAC secrets (impossible — HMAC needs the key).

### D-09 Credential exposures are pseudonymous HMAC refs, and passwords are dropped at parse time
**Status:** Built, unconfirmed · Phase 2b
- **Decision:** `ref = HMAC_SHA256(HMAC_SHA256(tenant_secret, "account-ref/v1"), lower(account))`, plus a masked form (`n***a@domain`) and the host. Packs carry `affected_accounts`. Only the SOAR, holding the same secret and the directory, can resolve them.
- **Why:** This identifies infected employees (the concept's goal) without HuntCompiler ever holding identities or passwords.
- **Rejected:**
  - storing emails (personal data at rest);
  - plain SHA-256 of emails (dictionary-reversible);
  - forwarding identities in clear;
  - storing passwords "for verification".
- **Consequences:** Rotating a tenant secret changes all refs. Consumers need directory lookups to resolve them (Integration Kit).

### D-10 Telegram CTI reads message text only; no attachments, no stored message text
**Status:** Built · Phase 2b · usage scope set by D-73 (Q11, 2026-11-14)
- **Decision:** Telethon with a StringSession from a dedicated research account. Per-channel cursors in Redis. Only exposures, counts and stealer-family hints are persisted.
- **Rejected:** downloading log archives (handling stolen data, malware risk); bot accounts (cannot read channels they do not administer).

### D-11 MalwareBazaar: metadata only; attacker tokens are minimised and never used
**Status:** Accepted · Phase 2b
- **Decision:** Keep hashes and C2 hosts found under C2-like keys of `vendor_intel`. Telegram bot tokens are reduced to `bot_id:sha256[:16]`; Discord webhooks to their numeric ID.
- **Rejected:** downloading samples to extract strings; storing or using full tokens (accessing attacker infrastructure).

---

## C. Data model and infrastructure

### D-12 PostgreSQL with 4 core tables plus link, audit and reference tables
**Status:** Accepted · Phases 1, 3, 2b
- **Decision:** `tenants`, `raw_intel_events`, `pivoted_clusters`, `hunting_packs`, plus `cluster_event_links`, `ai_compilations` and `reference_datasets`. Multi-tenant model (Q1).
- **Rejected:** a single-tenant model (it would block reuse for SMEs); a document store (constraints and uniqueness matter here).

### D-13 Enums as VARCHAR + CHECK, values append-only
**Status:** Accepted · Phase 1
- **Rejected:** native PostgreSQL ENUM. `ALTER TYPE ... ADD VALUE` cannot run inside a transaction and complicates migrations.

### D-14 Idempotency by content
**Status:** Accepted · Phases 1, 3
- **Decision:**
  - Signals are unique on `(source, dedup_sha256)`.
  - Packs are unique on `(tenant_id, content_sha256)`, ignoring `pack_id`, `timestamp` and expiry.
  - A new pack version is issued only when the *substance* changes (tasks, blocklist, severity, accounts) — never for confidence drift alone.
- **Rejected:** re-issuing on every score change (pack storms, re-hunting the same thing).

### D-15 One container image, split Celery queues, a separate CertStream service
**Status:** Accepted · Phases 1, 2
- **Decision:** One image runs api, worker, beat, migrate and certstream. Queues: `default`, `collectors`, `compiler`, `dispatch`. CertStream runs as a long-lived process, with a self-hosted server recommended.
- **Rejected:** CertStream as a Celery task (it is a permanent websocket); a single queue (slow LLM work would starve dispatch).

### D-16 Hardened runtime
**Status:** Accepted · Phase 1
- **Decision:**
  - Python 3.12 slim image, non-root, read-only root filesystem, `cap_drop: ALL`.
  - PostgreSQL and Redis on an internal-only network.
  - Redis with `noeviction` (it is the broker).
  - API bound to 127.0.0.1 behind a TLS reverse proxy.
- **Rejected:** publishing PostgreSQL or Redis ports; running as root; Redis `allkeys-lru` (would silently drop queued tasks).

### D-17 Hash-locked dependencies
**Status:** Accepted · Phase 1
- **Decision:** `requirements.in` → `uv pip compile --generate-hashes`. The image installs with `--require-hashes`.
- **Rejected:** unpinned ranges (a supply-chain risk in a tool that hunts supply-chain attacks); pip-compile (too slow to generate hashes in the build environment, same output).

---

## D. Collection and processing

### D-18 Whitelist decides per hostname: `block` / `hunt_only` / `drop`
**Status:** Built, unconfirmed (C2) · Phase 2
- **Context:** Parent-domain lookups against the MISP warninglists classify `random.trycloudflare.com`, `evil.pages.dev`, `attacker.github.io` and `evil.ngrok-free.app` as Tranco Top-1M sites.
- **Decision:**
  - `drop`: tenant-owned assets, CDN/anycast ranges, public resolvers, core Microsoft/Google domains, Tranco Top 10K.
  - `block` (exact FQDN only): customer subdomains on PSL-private suffixes or LOTS entries.
  - `hunt_only`: shared-platform roots, popular sites (possibly compromised ClickFix hosts) and cloud-compute ranges.
- **Rejected:** "drop anything in Tranco 1M" (would blind V3 and V4); blocking parents of shared platforms (collateral damage).

### D-19 Static de-obfuscation only, with bounded resources
**Status:** Accepted · Phase 2
- **Decision:** Pure-text decoding (EncodedCommand, FromBase64String, gzip/deflate, XOR, char codes, concatenation, escapes, reversal, hex). Depth ≤ 8, input ≤ 1 MB, decompression ≤ 2 MB. IOCs are collected from every layer.
- **Rejected:** sandbox detonation (out of scope, risky); PowerShell AST emulation (complexity).

### D-20 JARM is corroborating evidence only
**Status:** Accepted · Phase 2
- **Decision:** A suspicious JARM adds +15 at most to the AiTM score. Proxied identity paths (`/common/SAS/ProcessAuth`, `/kmsi`...) carry the decision.
- **Rejected:** JARM as the primary Evilginx signal. Go-based kits share JARM with legitimate Go servers.

### D-21 Active probing only of hosts that already look malicious
**Status:** Accepted · Phase 2 (its known gap was closed by D-46 in Phase T)
- **Decision:** JARM and favicon probes run only on `block`-class domains, at most 10 per event, from the HuntCompiler egress.
- **Known gap (closed 2026-11-02):** there was no SSRF guard, so a malicious domain resolving to private or link-local addresses could be probed. D-46 added the guard.

### D-22 Reference datasets: parsed from the real formats, capped newest-first
**Status:** Accepted · Phase 2b
- **Decision:**
  - Sources: LOLDrivers `drivers.json`, LOLRMM `rmm_tools.json`, HijackLibs repository archive (Sideloading entries only), OSV `MAL-*` advisories (through the ecosystem index since 2026-11-02, see D-47).
  - Caps: 150 hashes, 250 RMM binaries and domains, 200 DLLs and packages, so each query stays under 64 KB.
- **Rejected:** full lists in one query (exceeds the limit); splitting into many tasks (pack size; can be revisited).
- **Consequences:** Older entries are not hunted. The caps are an explicit coverage trade-off.

### D-23 Per-tenant tasks where the manifest matters
**Status:** Accepted · Phase 2b
- **Decision:** Rogue-RMM hunts exclude the tenant's `approved_rmm_tools`. Credential-exposure hunts go only to the affected tenant.

### D-24 Credential-exposure packs notify even with zero hits
**Status:** Built, unconfirmed (C6) · Phase 2b
- **Decision:** `notify_only_on_sighting=false`, plus a remediation hint (reset passwords, revoke sessions).
- **Why:** An exposed credential is an incident whether or not misuse appears in logs.

---

## E. Compilation and AI

### D-25 Our own Wazuh DSL emitter on pySigma's parse tree
**Status:** Accepted · Phase 3
- **Context:** The stock Lucene backend uses `query_string` wildcards, which are case-sensitive on Wazuh keyword fields (`*powershell*` misses `PowerShell`).
- **Decision:**
  - Use `term` / `wildcard` with `case_insensitive: true`. Pin Channel and EventID.
  - Field mapping: `data.win.eventdata.<lowerCamel>`.
  - Parse a fresh SigmaCollection per backend (pipelines mutate rules).
- **Rejected:** pySigma Lucene output (wrong semantics); writing DSL by hand per rule (unmaintainable).
- **Consequences:** The verified dialect is a subset (no regex, CIDR or keyword search).

### D-26 Every compiled query must be testable
**Status:** Accepted · Phase 3
- **Decision:** A harness evaluates the DSL against sample events. KQL is linted (table allow-list; a literal `*` inside `endswith`/`contains` is rejected — pySigma produced `RegistryKey endswith "...RunMRU*"`).
- **Rejected:** trusting compiler output.

### D-27 Deterministic templates for every vector; the LLM is optional and off by default
**Status:** Accepted · Phases 3, 2b
- **Decision:** `HC_LLM_ENABLED=false` by default. Packs never depend on the model. LLM use is enabled only for V2 and V3 by default.
- **Rejected:** an LLM-required pipeline (availability, cost, poisoning).

### D-28 The LLM fills a constrained draft; code renders Sigma, DSL and KQL
**Status:** Built, unconfirmed (C3) · Phase 3
- **Decision:** The output schema allows only:
  - a category from a closed list;
  - fields from an allow-list per category;
  - modifiers `equals`, `contains`, `startswith`, `endswith`;
  - a condition combining selection names with `and`/`or`/`not` only;
  - positive and negative samples.
- **Rejected:** the LLM writing Sigma YAML or queries directly, as in the concept (injection surface, unsupported constructs).

### D-29 Six gates per AI rule
**Status:** Accepted · Phase 3
- **Decision:**
  1. Breadth.
  2. Indicator provenance: every domain/IP must already be in the cluster evidence.
  3. Whitelist: no `drop`-class indicator.
  4. Compilation.
  5. Harness (positive and negative samples).
  6. Contract.

  Rejected rules are recorded with reasons and never shipped.

### D-30 The LLM never receives tenant data; compilation is per cluster and shared
**Status:** Accepted · Phase 3
- **Decision:** Evidence comes from cluster data only, redacted, fenced with a random nonce and capped at 40k characters. Results are cached by evidence hash + prompt version + model and reused for every tenant.
- **Rejected:** per-tenant prompts (leak the tenant's attack surface, multiply cost).

### D-31 Provider abstraction, temperature 0, audited calls, daily token budget
**Status:** Accepted · Phase 3
- **Decision:** `LLMProvider` protocol, with Gemini as the default (`gemini-2.5-flash`, configurable). Every call is stored in `ai_compilations`. A daily budget is enforced in Redis.
- **Rejected:** a hard dependency on one vendor; uncapped spend (flooding GitHub with fake "CVE" repos would amplify cost).
- **Open:** paid vs free tier, or a local model (Q12).

### D-32 Deterministic scoring with per-vector half-life
**Status:** Accepted · Phase 3
- **Decision:**
  - The base score comes from evidence features: KEV, EPSS, credible PoC, Nuclei, clipboard lure, unpacked C2, AiTM score, credential exposure.
  - Decay: `score = base × 0.5^(age_h / half_life_h)`. Half-life is 72 h for V1, 96 h for V3, 720 h for V2/V5.
  - Each sighting adds +5 (capped at +15). Clean results never lower the score.
  - Clusters below 20 expire.
- **Rejected:** LLM-assigned confidence; lowering confidence on "clean" (absence of evidence).

### D-33 Auto-block is a hint that requires tenant opt-in
**Status:** Accepted · Phase 3
- **Decision:** `auto_block_pre_iocs=true` only if the manifest has `allow_auto_block_hint`, confidence ≥ 80 and the blocklist is non-empty. Enforcement belongs to the consumer, and only after a human decision (Q8, answered 2026-11-05); the reference consumer never blocks.

---

## F. Scope and conventions

### D-34 Windows telemetry only for hunts (Sysmon, Security, System)
**Status:** Provisional (Q7)
- **Rejected for now:** Linux hunts (no telemetry design agreed).

### D-35 Retro-hunts target archived events
**Status:** Superseded by D-38 (2026-11-01)
- **Original decision:** hunts are written against raw Sysmon/Security events, which means `wazuh-archives-*` in Wazuh.
- **Now:** running hunts is the consumer's responsibility. The Integration Kit must state that Wazuh consumers need archiving enabled; otherwise most raw events never reach the index.

### D-36 Code and project docs in English; Vietnamese overview as a translation
**Status:** Accepted
- **Decision:** `README.vi.md` is the Vietnamese overview. Examples use `.example` domains and RFC 5737 ranges.

### D-37 Phase order
**Status:** Accepted (owner's decision; updated 2026-11-01)
- **Order:** 1 → 2 → 3 → 2b → **T (Telegram)** → **I (Integration Kit)**. Phase 4 is cancelled (D-38).
- **Why:** assess what the AI reads, and its risks, before adding sources. Telegram comes next because the owner can test it immediately.

---

## G. Product scope after 2026-11-01

### D-38 HuntCompiler is an API service; Phase 4 (n8n/Wazuh SOAR) is cancelled
**Status:** Accepted (owner) · 2026-11-01
- **Decision:**
  - The product is an API for automated TI/TH with AI.
  - Consumers integrate through pull, push and feedback, using an **Integration Kit** (docs + examples) that covers Wazuh, Elastic and Splunk (D-50).
  - HuntCompiler never runs hunts.
- **Why:** keeps the product focused and vendor-neutral. A reference SOAR would tie it to one stack.
- **Rejected:** building and maintaining the n8n/Wazuh reference workflow; shipping vendor connectors as code.
- **Consequences:**
  - Zero-noise filtering and sighting feedback depend on consumers.
  - Confidence is evidence-only unless feedback arrives (TQ3).
  - Integration surfaces (placeholders, `required_telemetry`, `evaluable`) stay.

### D-39 Telegram is the human interface: digest only, one destination, plus commands
**Status:** Accepted (owner) · 2026-11-01
- **Decision:**
  - A periodic digest plus a command bot.
  - One destination chat: the owner's private chat or one SOC group.
  - No instant alerts.
- **Rejected:** instant alerts per pack (noise without retro-hunt filtering); per-tenant chats; Telegram as a machine delivery channel.
- **Answered 2026-11-02:** schedule (TQ1: daily 08:00 Asia/Ho_Chi_Minh) and language (TQ4: English).
- **Open:** an exposure exception (TQ2), feedback buttons (TQ3).

### D-40 The bot identity is separate from the CTI research account
**Status:** Accepted (owner, 2026-11-02) · Phase T
- **Decision:** Bot API token (`HC_TGBOT_*`) in its own module and container. It is never mixed with the Telethon research account (`HC_TELEGRAM_*`) that reads criminal channels.
- **Why:** different risk profiles. Compromising one must not expose the other; the bot must never appear inside monitored channels.
- **Rejected:** one Telegram identity for both.

### D-41 Long polling instead of a Telegram webhook
**Status:** Accepted (owner, 2026-11-02) · Phase T
- **Why:** no inbound exposure; works from a lab or a VPS.
- **Rejected:** a webhook (needs a public HTTPS endpoint and secret-token handling).

### D-42 A thin httpx Bot API client
**Status:** Accepted (owner, 2026-11-02) · Phase T
- **Decision:** five methods (`getUpdates`, `sendMessage`, `sendDocument`, `answerCallbackQuery`, `deleteWebhook`) with 429 handling, message splitting and token scrubbing.
- **Why:** no new dependency (supply chain), testable with `httpx.MockTransport`.
- **Rejected:** python-telegram-bot and aiogram (larger surface, own runtime model, features we do not need).

### D-43 The digest is grouped by cluster, with an idempotent cursor in PostgreSQL
**Status:** Accepted (owner, 2026-11-02) · Phase T
- **Decision:**
  - One line per cluster, listing tenants; the newest pack of the cluster in the window gives the shown pack id.
  - Only clusters with a new pack for the shown tenants are listed (owner, 2026-11-02); clusters below the delivery threshold are not.
  - Table `telegram_digests` holds the high-water marks: the max `hunting_packs.seq` and the max `cluster_event_links.linked_at` (dataset updates). They advance only after a successful send.
  - `/digest` is a preview that never advances them.
- **Rejected:** one line per pack (duplicates across tenants); a Redis-only cursor (no audit, lost on flush); `pivoted_clusters.updated_at` as a mark (pack building rewrites the decayed confidence every 10 minutes, so every active cluster would look updated in every digest).

### D-44 Telegram content policy
**Status:** Accepted (owner, 2026-11-02; answers former Q15) · Phase T
- **Decision:**
  - IOCs defanged; accounts masked only.
  - Sigma and queries sent as attachments on request (`/pack`), not in the digest.
  - HTML escaping for all dynamic text; AI text labelled `[AI]`; link previews off.
- **Why:** Telegram is a third-party cloud, and group members may change over time.
- **Rejected:** full pack details in messages; clickable attacker URLs.

### D-45 Bot commands are database-only
**Status:** Accepted (owner, 2026-11-02) · Phase T
- **Decision:** `/status`, `/digest`, `/latest`, `/pack`, `/ioc`, `/cve` read PostgreSQL only. Allowlist on chat and user. 10 commands per user per minute.
- **Rejected:** commands that fetch or scan user-supplied URLs or hosts (SSRF, abuse, legal exposure).

### D-46 An SSRF guard is mandatory before any live run
**Status:** Accepted (owner, 2026-11-02) · built in Phase T
- **Decision:**
  - Resolve before probing; refuse any non-global address (loopback, RFC1918, CGNAT, link-local / `169.254.169.254`, ULA).
  - Re-validate every redirect; pin the validated IP where possible.
- **Built:** `app/core/netguard.py`. Favicon requests go to the validated IP with `Host` and TLS SNI set to the hostname (httpx `sni_hostname`). JARM hellos are built by pyjarm for the hostname and sent to the validated IP (pyjarm 0.0.5 internals, covered by `tests/test_netguard.py`).
- **Rejected:** relying on the whitelist (it never resolves DNS); disabling probes permanently (loses JARM and favicon pivots).

### D-47 OSV malicious packages come from the ecosystem index, not the bulk archive
**Status:** Accepted (owner, 2026-11-02) · fix shipped with Phase T
- **Context:** `npm/all.zip` was 219,694,900 bytes on 2026-11-01, more than three times the 64 MB archive cap. The fetch raised, and because npm and PyPI shared one dataset, PyPI was lost too: the V6 template never had data.
- **Decision:**
  - Download `<ecosystem>/modified_id.csv` (8.7 MB for npm). Keep `MAL-*` IDs modified within `HC_OSV_LOOKBACK_DAYS`, newest first, at most `HC_OSV_MAX_IDS_PER_RUN` (1,000) per ecosystem.
  - Download `<ecosystem>/<ID>.json` only for advisories that are new or changed against the stored dataset. Each is capped at 64 KB (the largest of 50 sampled was 17 KB).
  - A failing ecosystem keeps its stored records and marks `reference_sync` as failing in the health heartbeats.
- **Rejected:** raising the cap to 256 MB for OSV (changes a hard constraint; about 250 MB every 6 hours); streaming the zip to disk (the container root is read-only and `/tmp` is a RAM tmpfs).
- **Consequences:** about 700 small requests on the first run for a 14-day window (497 npm and 187 PyPI advisories on 2026-11-02), then only the changes.

### D-48 Collector heartbeats live in Redis
**Status:** Accepted (owner, 2026-11-02) · Phase T
- **Context:** The digest's Health section needs the last success or failure per collector, and nothing recorded it.
- **Decision:** Each scheduled job writes `hc:health:<job>`: state, last success, last failure and a short note (exception type or partial-failure note, never the message, which can carry URLs or keys). Readers derive `stale` (no success in 2× the interval) and `unknown` (never reported). Jobs that skip for a missing key report `not_configured`.
- **Rejected:** a database table (`TELEGRAM.md` §6 allows only `telegram_digests`); inferring health from `raw_intel_events` (cannot tell an idle source from a broken one).
- **Consequences:** a Redis flush only loses health history; the digest then reports collectors as not reported yet, never as healthy.

### D-49 Integrators convert the Sigma rule; packs carry no extra query languages
**Status:** Accepted (owner, IQ1, 2026-11-05) · Phase I
- **Decision:** Packs keep Sigma, Wazuh DSL and Defender KQL (schema 2.0 unchanged; KQL removed later by D-63). For Elastic and Splunk the consumer substitutes placeholders inside the Sigma rule, then converts it with pySigma (Elastic: `EqlBackend` + ECS pipeline; Splunk: `SplunkBackend` + `sysmon_pipeline` + `splunk_windows_pipeline`).
- **Why:** no contract change, and the default "no extra query languages in packs" stays. All twelve HuntCompiler templates convert for both platforms (tested).
- **Rejected:** compiling SPL and ECS queries centrally (more contract fields and backends to maintain, without a harness for those languages); Lucene as Elastic's default (case-sensitive wildcards on keyword fields, the problem D-25 solved for Wazuh).
- **Consequences:** HuntCompiler's harness does not cover the converted queries; each guide has a live check.

### D-50 Integration Kit scope: Wazuh, Elastic and Splunk
**Status:** Accepted (owner, IQ2 and IQ3, 2026-11-05) · Phase I
- **Decision:** Order: the shared reference consumer, then Wazuh, Elastic, Splunk.
- **Rejected:** Zabbix (it cannot run log hunts); a Microsoft Defender XDR guide (Microsoft's own integrations already cover it). Packs still carry `kql_defender` until the owner decides otherwise (decided: D-63, no more KQL).

### D-51 The reference consumer is standalone, re-validates everything and never acts
**Status:** Accepted (owner, Q2, Q8 and the dependency question, 2026-11-05) · Phase I
- **Decision:**
  - `integration_kit/` never imports `app` and is not copied into the image. Its dependencies are hash-locked in `integration_kit/requirements.txt` (httpx, jsonschema, pySigma and the two backends), separate from the service.
  - Pull is the main path; a small push receiver (HMAC on the raw body, 1 MB cap) is the alternative. An inbox decouples intake from hunting.
  - Every pack is re-validated against a byte-identical copy of `contracts/hunting_pack_v2.schema.json` plus the guardrails a schema cannot express, even with a valid signature (ARCHITECTURE.md §9, T4).
  - `evaluable` requires every task's relevant `required_telemetry` to be declared by the integrator; Defender/Entra tags are ignored; `sysmon:<category>` counts as the matching event id. A task above `HC_KIT_MAX_HITS` is a broken rule.
  - `auto_block_pre_iocs` is reported as a hint only; the consumer never blocks.
- **Rejected:** importing HuntCompiler code in the kit (integrators would need the whole service); trusting the signature alone; counting a huge hit volume as a sighting.

### D-52 KEV-to-tech-tag matching needs a product-specific word
**Status:** Accepted (owner, 2026-11-05) · bug fix
- **Context:** the shared word "server" made "Exchange Server" match `microsoft:windows_server` and "SharePoint Server" match both Exchange and Windows Server, so V2 packs reached tenants that do not run the product.
- **Decision:** generic product words (server, services, enterprise, software, management...) never match on their own; a tag made only of generic words never matches.
- **Rejected:** exact product-name equality (KEV product names vary: "FortiOS and FortiProxy").

### D-53 Wazuh DSL matches the doubled backslashes Wazuh stores
**Status:** Accepted (owner, 2026-11-08) · bug fix found on Wazuh indexer 4.14.7
- **Context:** Wazuh 4.x's eventchannel decoder stores every backslash of a Windows event value doubled (`C:\\Windows\\...`); Wazuh's own ruleset matches paths that way. Our DSL used single backslashes. On the official Wazuh indexer 4.14.7 (OpenSearch 2.19.5) this gave two false positives (the `System32\drivers\` filters of the V5 driver tasks never applied) and one missed detection (`Windows\Temp\` in the HijackLibs task); the V3 `RunMRU` registry path could never match. Single-segment patterns such as `*\powershell.exe` matched by chance, and the harness built its sample documents with single backslashes, so the tests did not see it.
- **Decision:** the Wazuh DSL emitter doubles every literal backslash in `term` and `wildcard` values. The harness stores `data.win.eventdata.*` sample values the Wazuh way, so AI-draft samples and templates are checked against what the indexer holds. Splunk, Elastic and KQL output is unchanged.
- **Rejected:** rewriting queries in the consumer (the DSL in the pack must be correct as shipped; other consumers run it directly); `regexp` queries accepting one or two backslashes (slower on keyword fields, and the harness would need a regex engine for them); asking integrators to change the decoder (not configurable).
- **Consequences:** packs with Windows paths change content and are re-issued once at the next build. Placeholder values with a backslash must be doubled by the integrator (`integration_kit/wazuh/GUIDE.md` §3). Wazuh 5.x is not covered.

### D-54 GitHub only enriches a KEV signal
**Status:** Accepted (owner, Phase H plan, 2026-11-08) · bug fix
- **Context:** without a token GitHub code search answers 401, and any GitHub error (rate limit, outage) aborted the whole KEV sweep, so the V2 alert itself was lost, not just the PoC details.
- **Decision:** PoC search and Nuclei lookup run per CVE inside their own error handling. A failure leaves `pocs`/`nuclei_templates` empty, adds a reason to `enrichment_notes`, and marks the sweep "failing" with that reason on the health page; the KEV signal still ships. Without a token the code search is skipped (it always fails) and that is noted, not reported as a failure.
- **Rejected:** retrying the CVE on the next run (a missing token would block the alert forever); a mandatory token (one missing setting must not silence V2).
- **Consequences:** signals are deduplicated on the CVE, so a CVE first seen while GitHub was unavailable keeps its empty enrichment. Without PoC/Nuclei points (+10 each) a KEV with low EPSS may stay under a tenant's delivery threshold: the token is still recommended.

### D-55 The unused Shodan pivot is removed
**Status:** Accepted (owner, Phase H plan, 2026-11-08)
- **Decision:** `ShodanPivot`, `PivotHit`, `PivotUnavailable` and the `HC_SHODAN_*` settings are deleted; nothing ever called them. `IntelSource.SHODAN` and the cluster states `merged`/`suppressed` stay (enums are append-only) and are marked reserved.
- **Rejected:** keeping dead code and a setting that does nothing.

### D-56 Tenant API rate limits; authentication failures look the same for every tenant
**Status:** Accepted (owner, Phase H plan, 2026-11-08)
- **Decision:** fixed windows in the existing Redis, no new dependency (`app/api/ratelimit.py`): `HC_API_RATE_LIMIT_PER_MINUTE` calls per tenant (default 60), and after `HC_API_AUTH_FAILURES_PER_IP` failed authentications in `HC_API_AUTH_FAILURE_WINDOW_SECONDS` (20 in 600 s) an IP gets 429 with `Retry-After` for the rest of the window, even with a valid credential. Feedback for an unknown tenant slug is verified against a random secret, so it costs the same work and returns the same error as a wrong signature. If Redis fails, the API stays available (fail open, logged, 30 s back-off).
- **Rejected:** an extra rate-limit library or a gateway product (more moving parts for two endpoints); fail closed (a Redis blip would cut every tenant off).
- **Consequences:** per-IP limits need the real client IP: behind Caddy, uvicorn's `--proxy-headers` reads `X-Forwarded-For`.

### D-57 Data retention
**Status:** Accepted (owner, Phase H plan, 2026-11-08)
- **Decision:** a daily job (`maintenance.retention`, 02:45 UTC, reported on the health page) deletes `raw_intel_events` older than 90 days unless they belong to a still-active cluster, and `ai_compilations` older than 180 days. `0` keeps a table forever. Packs, clusters, tenants, datasets and digests are never purged.
- **Rejected:** partitioning (not needed at this volume); deleting by `observed_at` (a late-ingested old event would vanish at once).
- **Consequences:** the AI audit trail covers the last 180 days (`docs/AI_RISK_ASSESSMENT.md`). An event older than the window can be stored again if a source re-sends it.

### D-58 JSON logs; no metrics endpoint yet
**Status:** Accepted (owner, Phase H plan, 2026-11-08)
- **Decision:** `HC_LOG_FORMAT=json` writes one JSON object per line from the API, worker, beat, CertStream watcher and bot (stdlib only). Logger filters run first, so the Telegram token scrubber still applies. Text stays the default.
- **Rejected for now:** a Prometheus `/metrics` endpoint (a new dependency and one more endpoint to protect; collector health is already on `/status`).

### D-59 Public HTTPS through Caddy; images pinned by digest
**Status:** Accepted (owner, Phase H plan, 2026-11-08)
- **Decision:** compose profile `edge` runs Caddy with automatic certificates for `HC_PUBLIC_HOSTNAME`, exposing only `/api/v1/*` and `/healthz` (1 MB body limit, HSTS). The API itself stays on 127.0.0.1. Every image (`python`, `postgres`, `redis`, `caddy`, `certstream-server-go`) is pinned by digest.
- **Rejected:** nginx with certbot (two services and renewal scripts); publishing uvicorn directly.
- **Checked:** 2026-11-09 with `localhost` and Caddy's local CA (TLS 1.3, routing, signed pull, per-IP lockout on the
  forwarded client IP). A public hostname is still to check.

### D-60 Backups with pg_dump
**Status:** Accepted (owner, Phase H plan, 2026-11-08)
- **Decision:** compose profile `backup` runs `deploy/backup.sh` in the pinned postgres image: one custom-format `pg_dump` per day into the `pg_backups` volume, newest 14 kept (`HC_BACKUP_KEEP`). Restore steps are in README.md "Backups".
- **Rejected:** WAL archiving and point-in-time recovery (more operations than this data needs; a day of loss is acceptable because intelligence is re-collected).
- **Consequences:** the volume sits on the same host; copy dumps off the host for disaster recovery.
- **Verified:** 2026-11-09: rotation kept the newest two of three dumps; a dropped table came back with the README steps.

### D-61 Self-hosted CertStream
**Status:** Accepted (owner, Phase H plan, 2026-11-08)
- **Decision:** compose profile `certstream` runs `certstream-server-go` v1.10.1 (Calidog-compatible lite stream at `/`), reachable only inside the compose network; the watcher uses it when `HC_CERTSTREAM_URL=ws://certstream-server:8080/`.
- **Rejected:** staying on the public endpoint (it delivered nothing, 2026-11-05).
- **Verified:** 2026-11-09: the real watcher received certificates within seconds; heartbeat every minute.

### D-62 A blank setting means "not set"
**Status:** Accepted (owner, Phase H plan, 2026-11-08) · bug fix
- **Context:** `.env.example` ships `HC_URLSCAN_API_KEY=` blank. pydantic-settings read that as an empty secret, not as missing, so the URLScan sweep called the API with an empty key every 30 minutes (403) instead of reporting `not_configured`. Every optional key had the same problem.
- **Decision:** `env_ignore_empty=True`: a blank variable, in the environment or in `.env`, falls back to the default.

### D-63 Packs carry no Defender KQL
**Status:** Accepted (owner, 2026-11-10) · supersedes the KQL part of D-27, D-28 and D-49
- **Context:** Microsoft Defender XDR is out of scope (D-50) and no supported integration runs KQL. The owner asked to remove it completely.
- **Decision:** the compiler emits the Wazuh DSL only; templates and AI tasks no longer produce KQL or declare the Defender/Entra telemetry tags; the Telegram `/pack` query file shows the DSL only; `pysigma-backend-kusto` is removed from the dependencies. `CompiledQueries.kql_defender` stays in the schema (optional, always null in new packs) and keeps its guardrails.
- **Rejected:** deleting the field from the schema (contract changes are additive only, and packs issued before D-63 would stop validating); forbidding it in the schema (same reason).
- **Consequences:** every pack's content changes once, so the next pack build re-issues them. The V1 exposure task loses its Entra sign-in check (it existed only in KQL) and keeps the on-prem 4625 check; `${HC_AFFECTED_UPNS}` is no longer used by any template (the enum value stays). Entra hunting for consumers without Defender is part of Q6.

### D-64 A KEV entry alone reaches the delivery threshold
**Status:** Accepted (owner, Phase Q plan item Q1, 2026-11-13) · supersedes the KEV weight in D-32
- **Context:** "in KEV" was worth 50 points and the default delivery threshold is 60. A fresh KEV entry usually has a low EPSS and no PoC yet, so a vulnerability CISA confirms as exploited in the wild was not delivered. The KEV event is dated 00:00 UTC of `dateAdded`, so the score starts decaying before HuntCompiler even sees it: 60 would fall to 59 within about 9 hours.
- **Decision:** "in KEV" is worth **70**. With the 30-day half-life a KEV-only cluster stays at or above 60 for about 7 days, the length of the KEV lookback window, and its severity is HIGH. EPSS, PoC, Nuclei and ransomware points still add on top (capped at 100).
- **Rejected:** a special delivery rule for KEV regardless of the threshold (an exception inside the pack builder); a per-vector threshold in the manifest (a contract change every tenant would have to tune).
- **Consequences:** more V2 packs, by design. Only tenants whose tech tags match receive them. Clusters scored before the change keep their stored base score.

### D-65 Opt-in ops alerts in Telegram
**Status:** Accepted (owner, Phase Q plan item Q5, 2026-11-13) · narrows the "digest only" rule of D-39 to intelligence
- **Decision:** with `HC_TGBOT_OPS_ALERTS=true` (default **false**), a job that failed `HC_TGBOT_OPS_ALERT_AFTER_FAILURES` runs in a row (3), or is stale, is announced once per `HC_TGBOT_OPS_ALERT_COOLDOWN_HOURS` (6), with a "recovered" message when it is ok again. The messages carry no intelligence: job label, state and the short heartbeat note, HTML-escaped. Heartbeats gain a `consecutive_failures` counter. The task `notify.ops_alerts` runs every 5 minutes, only when enabled.
- **Rejected:** instant intelligence alerts (TQ2 stays "no"); alerts on `unknown` or `not_configured` (a missing key is a setting, not an outage).

### D-66 Forwarded client IPs are trusted from Caddy only
**Status:** Accepted (owner, Phase Q plan item Q6, 2026-11-13)
- **Context:** uvicorn ran with `--forwarded-allow-ips "*"`, so any process able to reach port 8000 could set `X-Forwarded-For` and dodge the per-IP lockout of D-56.
- **Decision:** an internal network `edge` (`HC_EDGE_SUBNET`, default `172.31.250.0/28`) links Caddy and the API. Docker hands out dynamic addresses only from `HC_EDGE_IP_RANGE` (default `172.31.250.8/29`). Caddy has a fixed address outside that range (`HC_EDGE_CADDY_IP`, default `172.31.250.2`) and reaches the API through the alias `api-edge`; uvicorn trusts forwarded headers from that address only. Direct calls on `127.0.0.1:8000` are identified by their real peer address.
- **Rejected:** trusting a whole Docker subnet (other containers live there); a shared-secret header added by Caddy (uvicorn's proxy middleware cannot check it).
- **Consequences:** if `172.31.250.0/28` clashes with another Docker network, change the three settings together. The live check (2026-11-13) found that without `ip_range` the API, which starts before Caddy, takes Caddy's address and Caddy cannot start; hence the range.

### D-67 Audience and deployment: self-hosted, for individuals, research and small businesses
**Status:** Accepted (owner, Q1 and Q3, 2026-11-14)
- **Decision:** HuntCompiler is for personal use, research, or small businesses. It runs **on the user's or the business's own machine** (one Docker Compose stack per installation), not as a shared hosted service. The multi-tenant data model stays; a normal installation has one tenant.
- **Consequences:**
  - Zero-Internal-Access is unchanged: even on the user's machine, HuntCompiler only reads public intelligence and serves packs; it never connects to the user's internal systems.
  - Consumers reach the API on the same machine or the LAN. A public hostname with Let's Encrypt is optional, not a requirement; LAN HTTPS uses Caddy's internal CA (checked 2026-11-09).
  - Follow-ups (local-only HTTPS mode, loopback HTTP for a consumer on the same machine, hardware sizing) are planned in `docs/plans/KE_HOACH_PHASE_R.md`.
- **Rejected:** a hosted multi-tenant SaaS (legal review, data custody and operations beyond the target users).

### D-68 AI provider: paid Gemini
**Status:** Accepted (owner, Q12, 2026-11-14)
- **Decision:** the AI compiler uses a paid Gemini API key. The default stays "LLM off": each installation enables it with `HC_LLM_ENABLED=true`, `HC_GEMINI_API_KEY` and a daily token budget.
- **Consequences:** the model names in `.env.example` must be checked against Google's current list before the first live run; the Phase 3 live check (one Gemini run reviewed by a human) waits for a key.
- **Rejected:** a local model (hardware cost on small machines, weaker output).

### D-69 Entra sign-in hunting: documentation only
**Status:** Accepted (owner, Q6, 2026-11-14)
- **Decision:** `integration_kit/ENTRA_GUIDE.md` explains how an integrator can check exposed accounts against Entra ID sign-in logs on Wazuh, Elastic or Splunk, with example queries. Nothing is added to packs, templates or tests; the examples are not run.
- **Rejected:** a Sigma template for Entra logs (it would break the Windows-only default and need per-platform field mappings and live tests).

### D-70 KEV entries are classified: edge products get packs, OS and desktop software get a patch reminder
**Status:** Accepted (owner, Phase R plan item R1, option A, 2026-11-14) · narrows D-64
- **Context:** every KEV entry that matched a tenant tag became a V2 "edge device exploit" pack with the edge lateral-movement hunts (logons and admin connections from the appliance's inside IP). A Windows or browser CVE got hunts that do not fit it, and the tag `microsoft:windows_server` matches several "Microsoft Windows" KEV entries every month, so tenants received many low-value packs.
- **Decision:** `classify_kev(vendorProject, product)` in `app/collectors/edge_exploits.py` sorts each entry, by a code-held table, into `edge` (VPN, firewall, gateway, load balancer, internet-facing servers such as Exchange, SharePoint, IIS, vCenter, Tomcat, file-transfer products) or `endpoint` (everything else, unknown products included). The result is the cluster feature `kev_class`.
  - `edge`: unchanged V2 pack with the edge hunts.
  - `endpoint`: no edge hunts. Without other tasks (AI tasks, IOC sightings) there is no pack; the CVE is listed instead in a new digest section "Exploited CVEs to patch" for the matching tenants that got no pack.
  - A tenant that lists the matched product in `login_portals[].product` gets the edge hunts anyway (an RD Web or other portal on that product faces the Internet).
  - Clusters built before this change have no `kev_class` and keep the old behaviour.
- **Rejected:** a new attack vector for endpoint vulnerabilities with its own templates (much larger, and there is no good generic hunt for that class yet); keeping everything and only rewording (does not remove the noise); asking the LLM to classify (the table must be deterministic and reviewable).
- **Consequences:** fewer V2 packs. The score is unchanged (D-64), so an endpoint KEV entry still counts toward the threshold when AI tasks make a pack. The vendor and product table needs occasional review when KEV adds new edge vendors. The live run on 2026-11-15 checked it against the whole catalog (1,781 entries: 651 edge, 1,130 endpoint) and found that CISA now lists VMware products under "Broadcom" and that several internet-facing products (Cisco Secure Email Gateway and SD-WAN, BeyondTrust Remote Support, GoAnywhere, ScreenConnect, IBM Aspera) fell to `endpoint`; the table was extended and each case has a test.

### D-71 Daily retry of GitHub enrichment for KEV entries
**Status:** Accepted (owner, Phase R plan item R4 = Phase Q item Q4, 2026-11-14)
- **Context:** a KEV entry is stored once (deduplicated by CVE). When GitHub failed on that first run, or no token was set, the entry kept empty PoC and Nuclei data, and the 10 + 10 points they can add, for good.
- **Decision:** the task `collectors.kev_reenrich` runs daily at 04:15 UTC. It retries KEV events inside the lookback window (`HC_KEV_LOOKBACK_DAYS`) whose `enrichment_notes` show missing data, at most `HC_KEV_REENRICH_MAX_ATTEMPTS` (5) runs each and 50 events per run. A missing token alone is retried only once a token is set, so the code search is never called without one. A part that fails again keeps the data stored earlier. The event payload, the cluster's `credible_poc` and `nuclei_template` features and its base score are updated; GitHub calls happen outside database transactions. Failures show on the health page (`kev_reenrich`).
- **Rejected:** re-collecting the whole KEV window with GitHub calls every run (rate limits without a token); retrying entries without notes to catch PoCs published later (unbounded GitHub traffic; can be added later with its own cap).
- **Consequences:** a cluster that was below a tenant's threshold gets its pack at the next pack build. A pack already sent is not re-issued for a score change alone (substance rule).

### D-72 Local deployment: HTTPS from Caddy's internal CA, loopback HTTP for a consumer on the same machine
**Status:** Accepted (owner, Phase R plan items R5.1, R5.2 and R5.4, 2026-11-14) · follows D-67
- **Decision:**
  - `HC_TLS_MODE=internal` makes Caddy (profile `edge`) issue the certificate from its own local CA, for a LAN without a public name; `HC_PUBLIC_HOSTNAME` is then the LAN name or IP consumers use, and they trust Caddy's root certificate (`docs/INSTALL.md`). `public` (default) keeps Let's Encrypt. Any other value stops Caddy at startup.
  - The reference consumer accepts `http://` without `HC_KIT_ALLOW_HTTP` only when the host is `localhost` or a loopback address literal (`127.0.0.0/8`, `::1`). LAN addresses, other names, lookalike names and URLs with user info still need HTTPS.
  - The Phase H live check "HTTPS with a public hostname" becomes optional.
- **Rejected:** plain HTTP inside the LAN (tokens and packs on the wire); a self-signed certificate made by hand (no renewal, and every consumer would have to pin it anyway).
- **Consequences:** loopback HTTP never leaves the machine, so the kit's guardrail is narrowed, not dropped. Consumers on other LAN machines install Caddy's root certificate or point `HC_KIT_CA_BUNDLE` at it.

### D-73 Telegram CTI and HIBP: public channels only, own verified domains only
**Status:** Accepted (owner, Q11 proposal in `docs/plans/KE_HOACH_PHASE_R.md` §2, 2026-11-14). A technical and operational policy, not legal advice.
- **Decision:**
  - Telegram CTI monitors **public** channels and groups only (visible to anyone, no invitation, approval or payment). It never joins closed or vetted groups, never posts, buys or talks to anyone there, never downloads attachments (blocked in code) and never uses credentials it finds.
  - It runs on a separate research account (own SIM), not a personal account. The channel list is kept in an uncommitted internal file with the reason and the date each channel was added, and reviewed every quarter. Start with 3 to 5 channels and assess them for two weeks.
  - HIBP is used only for domains the user or the business owns and administers, each verified in the HIBP dashboard (DNS TXT recommended), with a paid API key. The domains go into `brand.email_domains`.
- **Consequences:** both collectors stay off until configured. The data handling already in place (passwords dropped at once, accounts kept as HMAC references plus a masked form, no message text stored) is the data-minimisation basis. Businesses should still ask their legal adviser before enabling either collector.
- **Rejected:** monitoring closed groups or paid leak markets (legal and ethical exposure, and it means dealing with criminals).

### D-74 Continuous integration with GitHub Actions
**Status:** Accepted (owner, Phase R plan item R3 = Phase Q item Q2, 2026-11-14)
- **Decision:** `.github/workflows/ci.yml` runs on push to `main` and on pull requests: ruff, the full test suite with a PostgreSQL 16 service, `alembic upgrade head && alembic check`, contract regeneration with a diff check, the Integration Kit's schema copy, and `pip-audit` on the dev lock and the kit lock. Actions are pinned by commit SHA and the PostgreSQL image by digest; the job has a read-only token and no secrets. `requirements-dev.in` takes the runtime lock as its input and `requirements-dev.txt` is now hash-locked with uv, so CI tests the exact versions the image ships.
- **Rejected:** another CI service (the code is on GitHub); actions pinned by tag (tags can move); auditing only the runtime lock (the dev tools also run code).
- **Consequences:** CI starts only once the owner commits and pushes. A new advisory against a pinned package fails the build until the lock is updated.
- **Accepted advisory (owner, 2026-11-15):** PYSEC-2026-2447 (CVE-2025-69872): `diskcache` up to 5.6.3 unpickles its cache files, so whoever can write the cache directory can run code. No fixed release exists. `diskcache` comes with pySigma, which uses it only to cache MITRE ATT&CK and D3FEND data; HuntCompiler never loads that data (the full test suite creates no cache directory), and in the image the directory would belong to the service user. CI ignores this one ID, nothing else; remove the exception once a fixed version is locked. Rejected: a red CI until upstream ships a fix (it would hide new findings); removing pySigma (it compiles every rule).

### D-75 The worker loads the MISP warninglists once, before forking
**Status:** Accepted (owner, 2026-11-15, after the Phase R resource measurement)
- **Context:** the whitelist reads the MISP warninglists (about 300 MiB in memory). Each of the worker's 4 task processes loaded its own copy on first use, so the worker needed about 1.5 GiB of the stack's 1.8 GiB. Self-hosted installations run on small machines (D-67).
- **Decision:** a `worker_init` handler in `app/worker/celery_app.py` loads the lists in the worker's main process before the pool forks, then calls `gc.freeze()` so the garbage collector does not touch (and so copy) the shared objects. If loading fails, the worker starts anyway and each task process loads the lists itself as before.
- **Measured (2026-11-15):** the worker uses about 550 MiB after 16 task runs across its processes and about 650 MiB (peak 690 MiB) after a dataset sync (before: 1.49 GiB); each process's own share (PSS) is about 110 MiB.
- **Rejected:** fewer task processes (slower sweeps for the same saving); loading only some warninglists (changes whitelist behaviour, needs its own review).

## Open questions referenced above

**General**
- **Q2** — Confirm pull as the default for integrators. *Answered 2026-11-05: yes, with a push example (D-51).*
- **Q7** — Are Linux and edge-server hunts in scope?
- **Q8** — What should `auto_block_pre_iocs` mean for integrators? *Answered 2026-11-05: a hint only (D-51).*
- **Q11** — Which Telegram CTI channels may legally be monitored; research account; HIBP domain verification? *Answered 2026-11-14: public channels only, a separate research account, own verified domains only (D-73).*
- **Q12** — Paid Gemini key or a local model? *Answered 2026-11-14: paid Gemini (D-68).*
- **Q13** — Do additive fields stay in `2.0`, or bump to `2.1`?

**Telegram**
- **TQ1** — Digest schedule. *Answered 2026-11-02: daily 08:00 Asia/Ho_Chi_Minh.*
- **TQ2** — Should credential exposure be sent immediately?
- **TQ3** — Feedback buttons.
- **TQ4** — Bot language. *Answered 2026-11-02: English.*

**Integration Kit**
- **IQ1** — More query languages in packs, or Sigma conversion by integrators? *Answered: conversion (D-49).*
- **IQ2** — What the Zabbix integration should do. *Answered: out of scope (D-50).*
- **IQ3** — Platform order. *Answered: Wazuh, Elastic, Splunk (D-50).*
