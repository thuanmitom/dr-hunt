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
**Status:** Built, unconfirmed (Q2) · Phase 1
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
**Status:** Built, unconfirmed (legal: Q11) · Phase 2b
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
- **Decision:** `auto_block_pre_iocs=true` only if the manifest has `allow_auto_block_hint`, confidence ≥ 80 and the blocklist is non-empty. Enforcement belongs to the SOAR (Q8).

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
  - Consumers (Splunk, Wazuh, Elastic, Zabbix…) integrate through pull, push and feedback, using an **Integration Kit** (docs + examples).
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

## Open questions referenced above

**General**
- **Q2** — Confirm pull as the default for integrators.
- **Q7** — Are Linux and edge-server hunts in scope?
- **Q8** — What should `auto_block_pre_iocs` mean for integrators?
- **Q11** — Which Telegram CTI channels may legally be monitored; research account; HIBP domain verification?
- **Q12** — Paid Gemini key or a local model?
- **Q13** — Do additive fields stay in `2.0`, or bump to `2.1`?

**Telegram**
- **TQ1** — Digest schedule. *Answered 2026-11-02: daily 08:00 Asia/Ho_Chi_Minh.*
- **TQ2** — Should credential exposure be sent immediately?
- **TQ3** — Feedback buttons.
- **TQ4** — Bot language. *Answered 2026-11-02: English.*

**Integration Kit**
- **IQ1** — More query languages in packs, or Sigma conversion by integrators?
- **IQ2** — What the Zabbix integration should do.
- **IQ3** — Platform order.
