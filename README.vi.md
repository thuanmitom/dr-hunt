# OutSight HuntCompiler — Tài liệu tổng hợp (Phase 1 → 3, 2b và T)

> Phiên bản code: `0.4.0` · 170 test pass (có PostgreSQL) · 4 migration · Cập nhật: 02/11/2026
> Tài liệu kỹ thuật gốc bằng tiếng Anh: `README.md`, `SPEC.md`, `DECISIONS.md`, `ARCHITECTURE.md`, `TELEGRAM.md`,
> `docs/AI_RISK_ASSESSMENT.md`, `CLAUDE.md`.

---

## 1. Dự án này làm gì

OutSight HuntCompiler đứng **ngoài Internet**. Nó thu thập tín hiệu tấn công mới (domain giả mạo, CVE thiết bị
biên đang bị khai thác, trang ClickFix, driver lỗ hổng, công cụ RMM, gói npm/PyPI độc hại, rò rỉ tài khoản...).
Sau đó nó xoay trục hạ tầng, giải mã payload và **biên dịch thành gói săn tìm (Hunting Pack v2.0)** có chữ ký
HMAC-SHA256. Gói được cung cấp qua API cho bất kỳ SIEM/SOAR nào (pull, push webhook, feedback 1 bit). Người dùng đọc
tin qua bot Telegram: digest hằng ngày và các lệnh tra cứu.

Hệ thống của bên tích hợp tự chạy truy vấn hồi tố (retro-hunt) 14–30 ngày và gửi về 1 bit `sighting` kèm `evaluable`.
HuntCompiler không chạy hunt và không chạm vào mạng nội bộ. Phase 4 (n8n + Wazuh) đã huỷ ngày 01/11/2026; hướng dẫn
tích hợp sẽ nằm trong Integration Kit (Phase I).

### Nguyên tắc bất biến

| # | Nguyên tắc | Được đảm bảo bằng |
|---|---|---|
| 1 | **Zero-Internal-Access**: không đọc log nội bộ, không cài agent, không lưu thông tin nội bộ | Manifest từ chối dải IP private. Thông tin nội bộ chỉ đi dưới dạng `target_scope` hoặc placeholder `${HC_*}`, do SOAR tự điền |
| 2 | **Một chiều**: chỉ gửi gói, chỉ nhận về 1 bit | Feedback chỉ gồm `pack_id`, `sighting`, `evaluable`, thời gian. Không có số hit, host, user hay dòng log |
| 6 | **Không probe vào địa chỉ nội bộ** | Mọi probe JARM/favicon đi qua `app/core/netguard.py`: chỉ IP public, cổng 443/80, ghim IP đã kiểm, kiểm lại mỗi lần redirect |
| 3 | **AI chỉ đề xuất, code quyết định** | Blocklist, điểm, severity, auto-block, TTL đều do code tính. AI mặc định **tắt** |
| 4 | **Không bao giờ thực thi mã độc** | PoC, stager, mẫu malware chỉ xử lý dạng text, có giới hạn kích thước |
| 5 | **Không lưu mật khẩu rò rỉ** | Mật khẩu bị bỏ ngay khi parse. Tài khoản chỉ lưu dạng HMAC ref + dạng che (`n***a@...`) |

---

## 2. Kiến trúc 5 tầng

```
 INTERNET (máy chủ HuntCompiler)                                                ║  MẠNG NỘI BỘ TENANT
                                                                                ║
 T1 Collectors ─► T2 Pivot/Unpack/Guardrails ─► T3 Compiler (+AI) ─► T4 Lưu trữ/API/Dispatch
 CertStream        Whitelist theo hostname       Sigma → DSL Wazuh      PostgreSQL, Redis,
 URLScan           Giải mã stager đệ quy          Sigma → KQL Defender   Celery, FastAPI
 KEV/EPSS/GitHub   JARM, favicon mmh3, Shodan     Template cố định       │
 Telegram, HIBP    Brand matcher (homoglyph)      AI đề xuất + 6 cửa     │ Hunting Pack v2.0 (HMAC)
 LOLDrivers/RMM    Leak redactor (HMAC ref)       Scoring time-decay     │ pull (mặc định) / push
 HijackLibs, OSV                                                         ▼
 MalwareBazaar                                                  ║  SIEM/SOAR của bên tích hợp tự chạy hunt
                    tenant_manifest.yaml (chỉ dữ liệu công khai)║  (Integration Kit, Phase I)
                              feedback 1-bit  ◄═════════════════╝
```

T4 còn cấp dữ liệu cho bot Telegram (Phase T): digest hằng ngày và các lệnh chỉ đọc database.

**Luồng xử lý:** collector tạo `IntelSignal` → lưu idempotent vào `raw_intel_events` → enrich (whitelist, JARM,
favicon) → gom cụm vào `pivoted_clusters` → tạo gói theo từng tenant trong `hunting_packs` → push có retry, hoặc
SOAR tự pull → feedback cập nhật điểm của cluster.

**Lịch chạy (Celery beat):**

| Tác vụ | Tần suất |
|---|---|
| URLScan, KEV/EPSS/GitHub, Telegram | mỗi 30 phút |
| MalwareBazaar | 2 giờ |
| Dataset tham chiếu | 6 giờ |
| HIBP | hằng ngày |
| Gom cụm | 5 phút |
| Tạo gói | 10 phút |
| Push | mỗi phút |
| Digest Telegram | 08:00 hằng ngày giờ Việt Nam (cấu hình được) |

---

## 3. Trạng thái 6 vector tấn công

| Vector | Nguồn TI đã có | Hunting task đã có | Còn thiếu |
|---|---|---|---|
| **V1** AiTM, infostealer, OAuth/Device Code | CertStream (lookalike), URLScan (chấm điểm AiTM theo path `/common/SAS/ProcessAuth`, `/kmsi`...), Telegram CTI, HIBP, MalwareBazaar | IOC DNS/network, hash thực thi, đăng nhập thất bại của tài khoản bị lộ (4625 + Entra) | **Session Token Replay, DeviceCode, OAuth Consent** cần log sign-in Entra trong SIEM; chưa có template |
| **V2** 0/N-day thiết bị biên | CISA KEV, EPSS, GitHub PoC (heuristic phát hiện PoC giả), Nuclei | Logon 4624 type 3 và kết nối SMB/RDP/WinRM/LDAP từ IP nội bộ của thiết bị biên (placeholder), cộng task do AI đọc PoC | **Xuất rule WAF (virtual patching)**: AI đã trích được URI path nhưng chưa xuất rule |
| **V3** ClickFix / Fake CAPTCHA | URLScan DOM, phát hiện clipboard lure, giải mã đệ quy | RunMRU (Sysmon 13), explorer → script host (Sysmon 1), IOC, task AI | Correlation tiến trình + kết nối mạng (Sysmon 1 + 3) chưa nối |
| **V4** LOTS, Rogue RMM, tunnel | LOLRMM (358 công cụ) | RMM không được phép (loại trừ theo từng tenant), DNS tunnel (trycloudflare, devtunnels, ngrok...), script host gọi API Telegram/Discord | — |
| **V5** BYOVD, DLL side-loading | LOLDrivers (2.325 SHA256), HijackLibs (537 DLL) | Driver theo hash (Sysmon 6), driver không ký ngoài `System32\drivers`, service 7045 bất thường, DLL side-load từ thư mục người dùng | Ràng buộc "DLL nằm cùng thư mục với EXE có ký" chưa diễn đạt được bằng Sigma, đang để cho bước triage |
| **V6** Supply chain, Fake PoC, SEO | OSV (MAL-*), heuristic PoC giả | Cài gói độc hại (pip/npm/yarn/pnpm) trên máy Developer | **SEO poisoning / quảng cáo bộ cài giả** (PuTTY, WinSCP...) chưa có nguồn và template |

---

## 4. Các phase đã hoàn thành

### Phase 1 — Hạ tầng, database, data contract
- PostgreSQL với 4 bảng chính (`tenants`, `raw_intel_events`, `pivoted_clusters`, `hunting_packs`) và bảng nối cluster↔event. Enum lưu dạng VARCHAR + CHECK để dễ migrate.
- Pydantic schema cho Hunting Pack v2.0, manifest và feedback; xuất JSON Schema trong `contracts/`.
- Secret không nằm trong manifest (chỉ tham chiếu tên biến môi trường). HMAC secret mã hóa Fernet trong DB. API token chỉ lưu SHA-256.
- Docker: image chạy non-root, filesystem read-only. Postgres và Redis nằm trên network `internal` không có Internet. Dependency khóa hash (85 gói).
- **Quyết định quan trọng:** mặc định giao gói bằng **pull**. Push buộc hệ thống bên nhận phải mở webhook ra Internet, đi ngược nguyên tắc cách ly.

### Phase 2 — Collector, pivot, unpacker, whitelist
- **Phát hiện lớn nhất:** "lọc theo Tranco Top 1M" sẽ coi `*.trycloudflare.com`, `*.pages.dev`, `*.github.io`, `*.ngrok-free.app` là an toàn, vì domain cha của chúng phổ biến. Điều này làm mù V3/V4. Whitelist vì vậy quyết định theo từng hostname với 3 mức:
  - `block`: subdomain của khách trên nền tảng dùng chung, chỉ chặn đúng FQDN.
  - `hunt_only`: site phổ biến (có thể bị hack để cài ClickFix), root dịch vụ dùng chung, dải IP cloud.
  - `drop`: tài sản của chính tenant, CDN, DNS resolver, domain lõi của Microsoft/Google, Tranco Top 10K.
- Bộ giải mã stager tĩnh: EncodedCommand, FromBase64String + gzip, nối chuỗi, char code, `^`, backtick, chuỗi đảo, XOR, IOC đã defang. Có giới hạn chống zip bomb.
- JARM, favicon mmh3, pivot Shodan, chấm điểm AiTM, brand matcher (homoglyph, IDN, dấu tiếng Việt, sai 1 ký tự).
- CertStream chạy ở container riêng.

### Phase 3 — Compiler, AI, scoring, gói, giao nhận
- **Sinh DSL Wazuh từ cây điều kiện của pySigma**, dùng `case_insensitive: true`. Backend Lucene mặc định sẽ trượt `PowerShell` khi tìm `*powershell*`.
- **Harness** chạy DSL trên sự kiện mẫu. **Lint KQL** bắt lỗi `endswith "...RunMRU*"`, loại câu không bao giờ khớp mà pySigma sinh ra.
- Template cố định cho từng vector, nên gói không phụ thuộc AI.
- **AI (Gemini, có thể thay bằng model local):** chỉ điền một cấu trúc hẹp. Mỗi rule phải qua 6 cửa: độ rộng → nguồn gốc IOC → whitelist → biên dịch → harness → contract. Mọi lần gọi được audit trong bảng `ai_compilations`.
- Scoring tất định: điểm theo đặc trưng bằng chứng, giảm theo half-life từng vector, tăng khi có sighting. Gói chỉ phát hành lại khi nội dung thật sự đổi.
- Dispatcher push có retry, backoff và dead-letter. API `GET /api/v1/packs` (bearer) và `POST /api/v1/feedback` (HMAC).

### Phase 2b — Rò rỉ tài khoản và dataset tham chiếu
- **Leak redactor:** đọc 3 dạng dữ liệu (khối `URL/Username/Password` của stealer log, dòng `url:login:pass`, dòng `email:pass`). Mật khẩu bị bỏ ngay khi parse. Tài khoản chỉ còn **ref = HMAC(HMAC(secret, "account-ref/v1"), lower(tài khoản))** cùng dạng che. Chỉ SOAR của tenant, vốn có cùng secret và danh bạ, mới giải ngược được.
- **Telegram CTI** (Telethon): chỉ đọc **text**, không tải file đính kèm, không lưu nội dung tin nhắn, có con trỏ theo từng kênh.
- **HIBP** cho domain đã xác minh. **MalwareBazaar** chỉ đọc metadata, không tải mẫu; bot token và webhook chỉ giữ ID cùng mã băm.
- **Dataset tham chiếu** có parser viết theo file thật: LOLDrivers, LOLRMM, HijackLibs, OSV (MAL-*). Template giới hạn kích thước để query dưới 64 KB.
- Gói lộ tài khoản đặt `notify_only_on_sighting=false`, vì bản thân việc lộ đã là sự cố.

### Phase T — Bot Telegram, chặn SSRF, sửa lỗi (Built, chưa Verified)
- Bot Telegram: digest hằng ngày và 8 lệnh chỉ đọc database. Chi tiết và cách cài ở mục 12.
- Chặn SSRF cho probe JARM/favicon (`app/core/netguard.py`).
- Sửa 3 lỗi: OSV đọc qua file chỉ mục, KQL V1 dùng bảng `EntraIdSignInEvents`, task mạng IOC chỉ khớp đúng host và subdomain.

---

## 5. Data contract

**Hunting Pack v2.0** gồm các trường gốc: `schema_version`, `pack_id`, `timestamp`, `attack_vector`, `severity`,
`confidence_score`, `mitre_attack`, `threat_summary`, `prevention_blocklist`, `internal_hunting_tasks`,
`soar_playbook_hints`.

Phần mở rộng (tùy chọn, tương thích ngược):
- `expires_at`
- `affected_accounts[{ref, masked, host}]`
- trong mỗi task: `target_scope`, `required_telemetry`, `scope_placeholders`

**Chữ ký:**
```
X-HuntCompiler-Timestamp: <unix>
X-HuntCompiler-Signature: sha256=HMAC_SHA256(secret, f"{timestamp}." + raw_body)
X-HuntCompiler-Pack-Id / X-HuntCompiler-Tenant
```
Bên nhận phải kiểm trên **raw body** (ví dụ n8n: bật *Raw Body*), từ chối timestamp lệch quá 300 giây, và chống trùng theo `pack_id`.

**Pull:** `GET /api/v1/packs?after=<seq>` trả về `{"items":[{seq, timestamp, signature, pack}], "next_cursor"}`.

**Placeholder (SOAR tự điền):**

| Placeholder | Ý nghĩa |
|---|---|
| `${HC_EDGE_DEVICE_INTERNAL_IPS}` | IP phía trong của VPN/firewall |
| `${HC_DMZ_HOST_IPS}` | IP các máy DMZ |
| `${HC_AFFECTED_UPNS}` | UPN của tài khoản bị lộ, dùng cho KQL |
| `${HC_AFFECTED_SAM_ACCOUNTS}` | sAMAccountName của tài khoản bị lộ, dùng cho Wazuh |

Quy tắc thay thế:
- Trong DSL: phần tử mảng đúng bằng placeholder được thay bằng danh sách giá trị.
- Trong KQL: placeholder được thay bằng các giá trị đặt trong ngoặc kép, ngăn cách bởi dấu phẩy.

**Feedback:** `POST /api/v1/feedback` với body `{pack_id, sighting, evaluable, evaluated_at}`. `evaluable=false`
nghĩa là thiếu telemetry, tức là **chưa biết**, không phải sạch.

---

## 6. AI và rủi ro (tóm tắt từ `docs/AI_RISK_ASSESSMENT.md`)

- **AI đọc:** facts KEV, đường dẫn Nuclei, mã PoC từ repo không bị gắn cờ giả (không tin cậy), payload clipboard ClickFix (không tin cậy), danh sách IOC của cluster. Tất cả đều qua bước che dữ liệu và giới hạn 40k ký tự.
- **AI không bao giờ thấy:** thông tin tenant, log nội bộ, secret, dữ liệu rò rỉ.
- **Rủi ro còn lại cần nhớ:**
  - **R3 (cao):** bằng chứng bị đầu độc có thể khiến task AI không bao giờ khớp. 0 hit trên task AI **không** có nghĩa là an toàn.
  - **R2 (trung bình):** mẫu test do chính AI viết.
  - Phần tóm tắt AI có thể chứa câu thao túng, cần hiển thị dạng plain text. Bot Telegram escape, defang và gắn nhãn `[AI]`.
  - Gói Gemini miễn phí có thể dùng dữ liệu gửi lên để cải thiện sản phẩm, nên dùng key trả phí và kiểm tra lại điều khoản.

---

## 7. Cấu trúc thư mục

```
app/core        cấu hình, mã hóa, chữ ký, netguard (chặn SSRF)    app/schemas     contract, validator
app/db          model, session, kiểu mã hóa     app/collectors  T1 (+ tasks, tasks_2b)
app/processors  T2 (whitelist, unpacker, pivot, brand matcher, leak redactor)
app/compiler    T3 (DSL, harness, translate, template, AI, scoring)
app/services    gom cụm, tạo gói, AI evidence   app/dispatch    push   ·   app/api   pull/feedback/health
app/integrations/telegram   bot Telegram: client, format, digest, bot
app/worker      Celery, runtime, heartbeat collector (Redis)
migrations/     4 revision                      contracts/      JSON Schema + gói mẫu ClickFix
config/         tenant_manifest.yaml            scripts/        load_manifest, export_contracts, telegram_login
docs/           AI_RISK_ASSESSMENT.md           tests/          170 test
```

---

## 8. Cài đặt và chạy

```bash
cp .env.example .env            # điền mật khẩu, khóa Fernet, secret tenant, API key
docker compose up -d --build    # postgres, redis, migrate, api, worker, beat, certstream
docker compose run --rm api python -m scripts.load_manifest config/tenant_manifest.yaml
curl -s http://127.0.0.1:8000/readyz
```

- **Telegram CTI (đọc kênh):** chạy `python -m scripts.telegram_login` **một lần** bằng tài khoản nghiên cứu riêng (không dùng tài khoản cá nhân). Dán chuỗi nhận được vào `HC_TELEGRAM_SESSION` và khai báo kênh trong `HC_TELEGRAM_CHANNELS`.
- **AI:** để `HC_LLM_ENABLED=false` cho đến khi gói tạo từ template hiển thị đúng ở phía SOAR.
- **Bot Telegram (Phase T):** xem mục 12. Bot dùng token BotFather riêng, không dùng tài khoản Telethon ở trên.

**Biến môi trường chính:**

| Nhóm | Biến |
|---|---|
| Hạ tầng | `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `HC_MASTER_ENCRYPTION_KEYS` |
| Nguồn TI | `HC_URLSCAN_API_KEY`, `HC_GITHUB_TOKEN`, `HC_SHODAN_API_KEY`, `HC_ABUSECH_AUTH_KEY`, `HC_HIBP_API_KEY`, `HC_TELEGRAM_*` |
| AI | `HC_LLM_ENABLED`, `HC_GEMINI_API_KEY`, `HC_LLM_DAILY_TOKEN_BUDGET`, `HC_LLM_VECTORS` |
| Bot Telegram | `HC_TGBOT_ENABLED`, `HC_TGBOT_TOKEN`, `HC_TGBOT_CHAT_IDS`, `HC_TGBOT_ALLOWED_USER_IDS`, `HC_TGBOT_TENANTS`, `HC_TGBOT_DIGEST_TIMES`, `HC_TGBOT_TIMEZONE` |
| Tenant | `HC_TENANT_<TÊN>_HMAC_SECRET`, `HC_TENANT_<TÊN>_API_TOKEN` (tên biến khai báo trong manifest) |

---

## 9. Kiểm thử: đã và chưa kiểm chứng

**Đã kiểm chứng (170 test, PostgreSQL 16 thật, 02/11/2026):**
- Migration chạy lên/xuống.
- Contract và guardrail.
- Chữ ký HMAC.
- Whitelist trên MISP warninglists thật.
- Unpacker. (Đính chính 02/11/2026: repo không có test JARM trên TLS server, brand matcher, chấm điểm AiTM, phát hiện
  clipboard lure, khớp KEV với tech tag, heuristic PoC giả hay Retry-After. Các mục này đã ghi vào known gaps.)
- Chặn SSRF: loopback, RFC1918, metadata `169.254.169.254`, redirect sang địa chỉ nội bộ đều bị chặn; JARM và favicon
  kết nối đúng IP đã kiểm.
- OSV qua file chỉ mục và từng bản ghi; lỗi một ecosystem không làm mất ecosystem kia.
- Bot Telegram: allowlist, rate limit, escape và defang, token không lộ trong log hay lỗi, digest idempotent, lệnh không
  ra mạng ngoài.
- Mọi cửa kiểm duyệt AI (injection, IOC ngoại lai, rule quá rộng, mẫu sai, sai schema, ngân sách token, che dữ liệu).
- Parser dataset trên dữ liệu thật.
- Luồng end-to-end: tín hiệu → cluster → gói cho 2 tenant → không phát hành lại → push có retry → pull có chữ ký → feedback.
- Luồng rò rỉ → gói có `affected_accounts`.

**Chưa kiểm chứng (sandbox không ra được Internet):**
- API thật của URLScan, GitHub search, CISA/FIRST, Shodan, Gemini, Telegram (Telethon và Bot API), HIBP, MalwareBazaar,
  tải bản ghi OSV (định dạng file chỉ mục và kích thước đã kiểm ngày 02/11/2026).
- Build Docker image.
- Wazuh indexer thật.
- Cú pháp query URLScan theo gói tài khoản bạn dùng.

---

## 10. Việc bắt buộc trước khi tin kết quả "không thấy gì"

1. **Wazuh mặc định chỉ index event có tạo alert** (`wazuh-alerts-*`). Event Sysmon như ghi RunMRU thường không tạo alert, nên retro-hunt phải chạy trên `wazuh-archives-*` (bật `logall_json` và input archives trong Filebeat). Cần kiểm tra trong lab.
2. Sysmon cần bật các event 1, 3, 6, 7, 11, 13, 22, và băm SHA256 cho event 1/6.
3. Truy vấn `wildcard *...*` trên keyword khá nặng. Nên giới hạn khoảng thời gian và số kết quả.
4. Microsoft đã thay bảng `AADSignInEventsBeta` bằng `EntraIdSignInEvents` từ 19/10/2026; template V1 đã dùng tên mới.
   Bảng này cần license Entra ID P2.

---

## 11. Lộ trình tiếp theo

**Phase 4 (n8n + Wazuh) đã huỷ ngày 01/11/2026.** HuntCompiler là dịch vụ API; bên tích hợp tự chạy hunt.

**Phase I — Integration Kit (chờ trả lời IQ1–IQ3 trong `SPEC.md` §9):** mỗi nền tảng (Wazuh, Splunk, Elastic,
Zabbix…) có một hướng dẫn và ví dụ: pull hoặc nhận gói, kiểm HMAC trên raw body, thay placeholder, chạy task, gửi
`sighting` và `evaluable`.

**Bổ sung các phần còn thiếu ở mục 3:**
- Token replay, DeviceCode, OAuth consent cho V1.
- Xuất rule WAF cho V2.
- SEO poisoning cho V6.
- Correlation tiến trình + mạng cho V3.

---

## 12. Bot Telegram (Phase T)

Trạng thái: **Built** (đã code và qua test tự động), chưa **Verified** cho tới khi bạn chạy xong checklist thủ công ở
`TELEGRAM.md` §9.

**Bot làm gì:**
- **Digest** lúc 08:00 hằng ngày giờ Việt Nam: mỗi cluster có pack mới là một dòng, kèm mục lộ tài khoản (chỉ dạng che),
  CVE thiết bị biên, cập nhật dataset và tình trạng collector. Kỳ không có gì mới chỉ gửi một dòng báo. Gửi lỗi thì con
  trỏ không tiến, kỳ sau gửi lại đúng khoảng thời gian đó.
- **Lệnh** (chỉ chat và người dùng có trong allowlist, chỉ đọc database): `/status`, `/digest` (xem trước, không đẩy
  con trỏ), `/latest [n]`, `/pack <tiền tố id>` (tóm tắt kèm file JSON, Sigma, query), `/ioc <giá trị>`, `/cve <mã CVE>`.
- **An toàn nội dung:** IOC được defang, HTML được escape, văn bản AI gắn nhãn `[AI]`, tắt link preview, token bot không
  bao giờ xuất hiện trong log hay lỗi.
- Bot dùng **token BotFather riêng** (`HC_TGBOT_*`), tách hẳn khỏi tài khoản nghiên cứu Telethon đọc kênh CTI
  (`HC_TELEGRAM_*`).

**Cài đặt (khoảng 10 phút):**
1. Trong Telegram, nhắn **@BotFather**: `/newbot`, đặt tên, chép token. Giữ privacy mode **bật**.
2. Trong `.env`: `HC_TGBOT_ENABLED=true` và `HC_TGBOT_TOKEN=<token>`. Tạm để `HC_TGBOT_CHAT_IDS=[]` và
   `HC_TGBOT_ALLOWED_USER_IDS=[]`.
3. Chạy `docker compose up -d --build`, rồi `docker compose up -d telegram-bot` (bot có profile compose riêng).
4. Gửi `/start` cho bot, hoặc trong group SOC. Lệnh `docker compose logs telegram-bot` sẽ hiện dòng
   `ignored update from chat_id=… user_id=…`.
5. Điền `HC_TGBOT_CHAT_IDS=[<chat_id>]` và `HC_TGBOT_ALLOWED_USER_IDS=[<user_id>]`, rồi chạy
   `docker compose up -d --force-recreate worker beat telegram-bot`.
6. Thử `/status`, `/digest`, `/latest`. Digest định kỳ đến vào giờ trong `HC_TGBOT_DIGEST_TIMES`.

Mỗi lúc chỉ có một nơi nhận: chat riêng **hoặc** một group SOC. Muốn chuyển sang group thì đổi ID và làm lại bước 5.
Group nên để riêng tư, tắt link mời, và chỉ thêm người có trong allowlist.

**Để có dữ liệu thật khi test mà không cần API key trả phí:** LOLDrivers, LOLRMM, HijackLibs, OSV, CISA KEV và EPSS đều
không cần key. Sau khi nạp manifest, các cluster và pack V2/V4/V5/V6 sẽ xuất hiện trong digest.
