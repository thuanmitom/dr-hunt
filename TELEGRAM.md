# OutSight HuntCompiler — Telegram Digest & Bot (Phase T)

Status: **Built, not verified** (the owner's manual checklist in §9 is pending) · 2026-11-02. Owner choices:
- **Role:** periodic digest **and** command bot.
- **Destination:** one private chat **or** one SOC group, set by configuration.
- **Cadence:** **digest only**, no instant alerts.

Defaults below marked *(default)* are configuration values, not assumptions about the concept. Open items are in §10.

---

## 1. Purpose

Give the operator or SOC a low-noise human interface to HuntCompiler:

- **Digest:** a scheduled summary of new intelligence and hunting packs since the last digest.
- **Bot:** on-demand lookups (latest items, pack details with Sigma/query files, IOC and CVE lookups, service status).

Telegram is an **operator interface**, not a delivery channel for machines. Systems integrate through the API and
webhook (Integration Kit); people read Telegram.

## 2. Hard rules

1. **Separate identity.** Use the Telegram **Bot API** with a BotFather token (`HC_TGBOT_TOKEN`). Never reuse the Telethon research account that reads CTI channels (`HC_TELEGRAM_*`). The two must never share credentials, modules or containers.
2. **Allowlist, deny by default.**
   - Process an update only if its chat is in `HC_TGBOT_CHAT_IDS` **and** the sender is in `HC_TGBOT_ALLOWED_USER_IDS`.
   - In a group, every command and button press is checked against the user allowlist.
   - Everything else is ignored without a reply. Only the chat and user IDs are logged (at INFO), so the operator can enrol them.
3. **Content minimisation.** Telegram is a third-party cloud.
   - IOCs are **defanged** (`hxxps://evil[.]example`).
   - Accounts appear **only in masked form** (`n***a@domain`); account refs and counts may also appear.
   - Never send tenant secrets, manifest internals, raw leak text or full bot tokens or webhooks seen in intel.
   - Sigma and queries go as **file attachments** (`/pack`), not in the digest text.
4. **No outbound actions from commands.** No command may trigger a network request to user-supplied input (no `/scan <url>`). Commands read from the database only. This avoids SSRF and abuse.
5. **Text safety.** Use HTML parse mode with every dynamic value escaped (`&`, `<`, `>`). AI-written text is labelled `[AI]` and escaped like any other value. Link previews are always disabled.
6. **Token hygiene.** The token is part of every Bot API URL. Scrub it from exceptions, logs and stored errors. Tests must assert it never appears.

## 3. Components

| Component | Runs as | Purpose |
|---|---|---|
| `app/integrations/telegram/client.py` | library | Minimal Bot API client on httpx: `getUpdates`, `sendMessage`, `sendDocument`, `answerCallbackQuery`, `deleteWebhook`. Handles 429 `retry_after`, splits messages over 4,096 chars, scrubs the token |
| `app/integrations/telegram/format.py` | library | Pure formatting: escape, defang, digest and pack views, chunking |
| `app/integrations/telegram/digest.py` | Celery task `notify.telegram_digest` | Builds and sends the digest; idempotent via `telegram_digests` |
| `app/integrations/telegram/bot.py` | container `telegram-bot` (`python -m app.integrations.telegram.bot`) | Long-polling `getUpdates` loop and command handlers |
| `app/worker/health.py` | library | Collector heartbeats in Redis, read by the Health section (D-48) |

**Long polling, not a webhook:** no inbound exposure is needed, and it works from a lab or a VPS alike. The bot
calls `deleteWebhook` at start, because `getUpdates` cannot be used while a webhook is set.

**Proposed decision:** a thin httpx client instead of python-telegram-bot or aiogram. It is ~200 lines, adds no new
dependency (supply chain), stays testable with `httpx.MockTransport`, and covers only the 5 methods we need.
Rejected: PTB (larger surface; its own event loop and persistence model); aiogram (same).

## 4. Digest

### Schedule

- Once a day at **08:00 Asia/Ho_Chi_Minh** (confirmed by the owner on 2026-11-02, TQ1). `HC_TGBOT_DIGEST_TIMES=["08:00"]` and `HC_TGBOT_TIMEZONE=Asia/Ho_Chi_Minh`; several times per day are allowed.
- `/digest` sends an on-demand preview without moving the cursor.

### Unit of content

The digest is grouped **by cluster**, not by pack. One cluster sent to several tenants appears once, listing those
tenants (or only the tenants in `HC_TGBOT_TENANTS`; empty means all). The line shows the newest pack of the cluster in
the window. Only clusters with a new pack for the shown tenants are listed (owner, 2026-11-02); clusters below the
delivery threshold are not.

### Window

The window covers everything since the last *successfully sent* digest. High-water marks are the max
`hunting_packs.seq` (top items, credential exposure, edge CVEs) and the max `cluster_event_links.linked_at` (dataset
updates), stored in `telegram_digests`. `pivoted_clusters.updated_at` is not used: pack building rewrites the decayed
confidence every 10 minutes, so every active cluster would look updated.

### Sections, in order (each one omitted if empty)

1. **Header:** period, counts by vector and by severity, new vs updated clusters.
2. **Top items:** at most `HC_TGBOT_DIGEST_TOP` *(default 10)*, sorted by severity, then confidence. One line each:

   ```
   [HIGH 78] V3 ClickFix — c2[.]evil-cdn[.]example · 4 tasks · 2 IOCs · #3f1c2b7e
   ```

3. **Credential exposure:** affected tenants, number of masked accounts, sources (Telegram, HIBP), stealer families. No refs and no masked list beyond 5 per tenant.
4. **Edge CVEs:** KEV entries that matched tenants' tech tags, with EPSS percentile and a "credible PoC" flag.
5. **Dataset updates:** LOLDrivers, LOLRMM, HijackLibs, OSV — new entries since the last digest.
6. **Health:**
   - last success or failure per collector;
   - LLM tokens used vs budget, and accepted/rejected AI rules;
   - push dead letters;
   - stale sources (no success in more than 2× their interval).

   Collector states come from Redis heartbeats (`hc:health:<job>`): `ok`, `failing`, `not_configured` (API key
   missing), `stale` and `unknown` (never reported). Unknown collectors are never summarised as healthy.

- **Empty window:** a one-line heartbeat ("No new intelligence since …; all collectors healthy" or the failing ones). Controlled by `HC_TGBOT_SEND_EMPTY_DIGEST` *(default true)*.
- **Length:** split into several messages at section boundaries, each ≤ 4,096 characters.
- **Optional attachment:** `digest-<date>.json` (cluster IDs, pack IDs, summaries). Controlled by `HC_TGBOT_ATTACH_JSON` *(default false)*.

### Idempotency

- Write a `telegram_digests` row with status `sending`. Send. Then mark it `sent` with the message IDs and advance the high-water marks.
- On failure, mark it `failed` and do not advance the marks; the next run re-covers the window.

## 5. Commands

| Command | Reply |
|---|---|
| `/start`, `/help` | Command list. Same allowlist as everything else (no reply to strangers) |
| `/status` | Service health (the digest's Health section) plus DB counts |
| `/digest` | Preview of the next digest (does not advance the cursor) |
| `/latest [n]` | The n most recent clusters (default 5, max 20) in the digest line format |
| `/pack <id-prefix>` | Pack summary (vector, severity, confidence, tasks, blocklist sizes, expiry) plus documents: `pack-<id>.json`, one `.yml` per task (Sigma), `queries-<id>.txt` (DSL + KQL). The prefix must be ≥ 8 hex characters and unique |
| `/ioc <value>` | Normalise the value (domain, IP or SHA256; defang input accepted), run the whitelist verdict, list matching clusters. **DB only, no external lookups** |
| `/cve <CVE-ID>` | KEV cluster status, EPSS, matched tenants, packs |

Commands in groups may be addressed as `/cmd@BotName`. Input is validated with the existing validators before any
query. Rate limit: 10 commands per user per minute; extra commands are dropped silently. `HC_TGBOT_TENANTS` limits
every command too, not only the digest.

## 6. Data model

New table `telegram_digests` (one Alembic revision):

```
id (uuid PK) · scheduled_for · window_start · window_end · max_pack_seq · max_link_at
status (sending|sent|failed|preview) · message_ids (int[]) · error (text, token-scrubbed) · created_at · updated_at
```

No other schema changes. Pack and cluster data are read-only for this feature.

## 7. Configuration (`.env`)

```
HC_TGBOT_ENABLED=false
HC_TGBOT_TOKEN=                         # BotFather token (secret)
HC_TGBOT_CHAT_IDS=[]                    # one private chat id (positive) or one group id (negative, -100… for supergroups)
HC_TGBOT_ALLOWED_USER_IDS=[]            # who may run commands / press buttons
HC_TGBOT_TENANTS=[]                     # empty = all tenants
HC_TGBOT_DIGEST_TIMES=["08:00"]
HC_TGBOT_TIMEZONE=Asia/Ho_Chi_Minh
HC_TGBOT_DIGEST_TOP=10
HC_TGBOT_SEND_EMPTY_DIGEST=true
HC_TGBOT_ATTACH_JSON=false
```

`HC_TGBOT_CHAT_IDS` accepts at most one ID (D-39); settings validation rejects more.

Compose: new service `telegram-bot` (same image, networks `backend` + `egress`) in the profile `telegram`, so a plain
`docker compose up` does not start it. It uses `restart: on-failure` and exits 0 when `HC_TGBOT_ENABLED=false`. The
digest runs in the existing worker/beat, on the default queue.

## 8. Operational guidance

- **Group setup:**
  - Use a **private** group with invite links disabled.
  - Keep BotFather privacy mode **on**, so the bot only sees commands.
  - Add only the people in the user allowlist.
- **First run:**
  1. Start the bot with an empty allowlist (`docker compose up -d telegram-bot`).
  2. Send `/start` from your account (and from the group).
  3. Read the logged chat and user IDs.
  4. Put them into `.env` and recreate `worker`, `beat` and `telegram-bot`.
- **Rate limits:** the client sleeps on HTTP 429 using `retry_after`, and sends digest parts sequentially (≥ 1 s apart in groups).
- **Rotation:** revoke the token in BotFather, set a new one and restart. Old messages stay in the chat history; Telegram retention is outside our control.

## 9. Acceptance criteria

Automated tests (no network):
- [x] Formatting escapes HTML, defangs every IOC, and never emits a raw `http`, an unmasked account or a token; messages are ≤ 4,096 characters.
- [x] A message from a non-allowlisted chat, or a command from a non-allowlisted user in an allowed group, gets no reply and causes no DB access beyond logging IDs.
- [x] The digest groups packs by cluster; tenant filtering works; an empty window produces the heartbeat only when enabled.
- [x] Idempotency: a failed send does not advance the cursor; a retry covers the same window; a successful send advances it; `/digest` preview never advances it.
- [x] The client honours 429 `retry_after` and splits long text; the token never appears in exceptions or logs (asserted).
- [x] `/ioc` and `/cve` validate input and use no external network (asserted with a transport that fails on any call).
- [x] `/pack` produces valid JSON and Sigma files and rejects ambiguous or short prefixes.

All automated items pass (2026-11-02): `tests/test_telegram_format.py`, `test_telegram_client.py`, `test_telegram_bot.py`
and `test_telegram_integration.py` (PostgreSQL).

Manual test by the owner:
- [ ] Bot created; `/status` answers in the private chat; a stranger's account gets no answer.
- [ ] `/digest` preview looks right; the scheduled digest arrives at the configured time.
- [ ] `/pack <prefix>` returns the JSON, `.yml` and query files; `/ioc` on a known cluster domain shows the cluster.
- [ ] The same in the SOC group, with a non-allowlisted member's command ignored.

## 10. Open items (owner decision needed)

| ID | Question | Default until answered |
|---|---|---|
| TQ1 | Is a daily 08:00 digest right, or do you want another frequency or times? | **Answered 2026-11-02:** daily 08:00 Asia/Ho_Chi_Minh |
| TQ2 | Should credential exposure be an exception to digest-only (sent immediately)? | No — digest only, as chosen |
| TQ3 | Should pack details carry feedback buttons ("Seen in our environment" / "Checked, not seen")? Without them, nothing feeds confidence now that there is no SOAR retro-hunt. | Not built |
| TQ4 | Bot message language: English, Vietnamese, or configurable? | **Answered 2026-11-02:** English |
