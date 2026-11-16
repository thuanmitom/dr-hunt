# OutSight HuntCompiler — Tài liệu tổng hợp (Phase 1 → 3, 2b, T, I, H, Q và R)

> Phiên bản code: `0.4.0` · 349 test pass (có PostgreSQL) · 4 migration · Cập nhật: 16/11/2026
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
tích hợp nằm trong Integration Kit (`integration_kit/`, Phase I) cho Wazuh, Elastic và Splunk.

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
 URLScan           Giải mã stager đệ quy          Sigma gốc kèm gói      Celery, FastAPI
 KEV/EPSS/GitHub   JARM, favicon mmh3             Template cố định       │
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
- JARM, favicon mmh3, chấm điểm AiTM, brand matcher (homoglyph, IDN, dấu tiếng Việt, sai 1 ký tự).
- CertStream chạy ở container riêng.

### Phase 3 — Compiler, AI, scoring, gói, giao nhận
- **Sinh DSL Wazuh từ cây điều kiện của pySigma**, dùng `case_insensitive: true`. Backend Lucene mặc định sẽ trượt `PowerShell` khi tìm `*powershell*`.
- **Harness** chạy DSL trên sự kiện mẫu. (Gói không còn KQL từ D-63, nên cũng không còn lint KQL.)
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
- Sửa 3 lỗi: OSV đọc qua file chỉ mục, KQL V1 dùng bảng `EntraIdSignInEvents` (sau đó bỏ hẳn KQL, D-63), task mạng IOC chỉ khớp đúng host và subdomain.

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
| `${HC_AFFECTED_UPNS}` | UPN của tài khoản bị lộ. Từ D-63 không template nào dùng nữa (chỉ KQL từng dùng) |
| `${HC_AFFECTED_SAM_ACCOUNTS}` | sAMAccountName của tài khoản bị lộ, dùng cho Wazuh |

Quy tắc thay thế:
- Trong DSL: phần tử mảng đúng bằng placeholder được thay bằng danh sách giá trị.
- (Gói phát hành trước D-63 còn có KQL; ở đó placeholder được thay bằng các giá trị trong ngoặc kép, cách nhau bởi dấu phẩy.)

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
docs/           AI_RISK_ASSESSMENT.md, plans/ (kế hoạch tiếng Việt)   tests/   349 test
integration_kit/  Phase I: hướng dẫn Wazuh, Elastic, Splunk và consumer mẫu (chạy phía bên tích hợp)
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
| Nguồn TI | `HC_URLSCAN_API_KEY`, `HC_GITHUB_TOKEN`, `HC_ABUSECH_AUTH_KEY`, `HC_HIBP_API_KEY`, `HC_TELEGRAM_*` |
| AI | `HC_LLM_ENABLED`, `HC_GEMINI_API_KEY`, `HC_LLM_DAILY_TOKEN_BUDGET`, `HC_LLM_VECTORS` |
| Bot Telegram | `HC_TGBOT_ENABLED`, `HC_TGBOT_TOKEN`, `HC_TGBOT_CHAT_IDS`, `HC_TGBOT_ALLOWED_USER_IDS`, `HC_TGBOT_TENANTS`, `HC_TGBOT_DIGEST_TIMES`, `HC_TGBOT_TIMEZONE` |
| Tenant | `HC_TENANT_<TÊN>_HMAC_SECRET`, `HC_TENANT_<TÊN>_API_TOKEN` (tên biến khai báo trong manifest) |

---

## 9. Kiểm thử: đã và chưa kiểm chứng

**Đã kiểm chứng (349 test, PostgreSQL 16 thật, 15/11/2026):**
- Migration chạy lên/xuống.
- Contract và guardrail.
- Chữ ký HMAC.
- Whitelist trên MISP warninglists thật.
- Unpacker. Brand matcher, chấm điểm AiTM, phát hiện clipboard lure, khớp KEV với tech tag, heuristic PoC giả, Retry-After
  và JARM trên một TLS server cục bộ (test bổ sung ngày 05/11/2026; trước đó README ghi là đã test nhưng repo không có).
- Hai lỗi tìm thấy ngày 05/11/2026 đã được sửa: chữ "server" chung chung làm khớp nhầm KEV với tech tag;
  `Retry-After` dạng ngày giờ làm collector báo lỗi.
- Integration Kit: chữ ký, kiểm lại pack, placeholder, giải tài khoản bị lộ, chuyển Sigma cho Splunk và Elastic, ba
  adapter, endpoint nhận push; một test end-to-end chạy consumer qua API thật trên PostgreSQL.
- Chặn SSRF: loopback, RFC1918, metadata `169.254.169.254`, redirect sang địa chỉ nội bộ đều bị chặn; JARM và favicon
  kết nối đúng IP đã kiểm.
- OSV qua file chỉ mục và từng bản ghi; lỗi một ecosystem không làm mất ecosystem kia.
- Bot Telegram: allowlist, rate limit, escape và defang, token không lộ trong log hay lỗi, digest idempotent, lệnh không
  ra mạng ngoài.
- Mọi cửa kiểm duyệt AI (injection, IOC ngoại lai, rule quá rộng, mẫu sai, sai schema, ngân sách token, che dữ liệu).
- Parser dataset trên dữ liệu thật.
- Luồng end-to-end: tín hiệu → cluster → gói cho 2 tenant → không phát hành lại → push có retry → pull có chữ ký → feedback.
- Luồng rò rỉ → gói có `affected_accounts`.

**Chưa chạy thật:**
- API thật của URLScan, tìm code trên GitHub (cần token), Gemini, Telegram CTI (Telethon), HIBP, MalwareBazaar.
- Cú pháp query URLScan theo gói tài khoản bạn dùng.

**Đã chạy thật ngày 14–15/11/2026:** build Docker image; CISA KEV, FIRST EPSS, tìm repo PoC trên GitHub (không token);
các dataset tham chiếu, kể cả tải bản ghi OSV; HTTPS trong LAN qua Caddy (xem mục 14 và 16). Bot Telegram (Bot API)
đã được bạn chạy thử ngày 05/11.

**Đã chạy thật ngày 08/11/2026:**
- Stack docker compose chạy thử: mọi health check xanh, `/readyz` trả 200.
- Wazuh indexer chính hãng 4.14.7 (OpenSearch 2.19.5), mapping chính thức của Wazuh: truy vấn của pack chạy đúng,
  kể cả `case_insensitive`. Lần chạy đầu tìm ra lỗi Wazuh lưu đường dẫn Windows với dấu `\` nhân đôi, đã sửa (D-53);
  lần chạy lại 12/12 task đúng. Xem `integration_kit/wazuh/SAMPLE_RUN.md`.

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

**Phase I — Integration Kit:** đã xây xong (mục 13). Wazuh đã chạy thử; Elastic và Splunk còn chờ.

**Phase H — Hoàn thiện để chạy thật:** đã xây xong và chạy thật đủ (mục 14).

**Phase Q và R:** đã xây xong các mục được duyệt (mục 15 và 16). Còn chờ: Q3 (thử phát hiện trên Windows thật), Q7
(sao lưu ra ngoài máy), Q8 (lọc archives Wazuh), R6 (chạy thật Gemini khi có key).

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

**Collector chỉ chạy theo lịch.** Sau khi khởi động, dataset tham chiếu chỉ chạy ở mốc 6 giờ kế tiếp, còn HIBP lúc 03:30
UTC. Muốn có dữ liệu ngay thì kích hoạt bằng tay:

```bash
docker compose exec worker celery -A app.worker.celery_app:celery_app call collectors.reference_sync
docker compose exec worker celery -A app.worker.celery_app:celery_app call collectors.edge_exploit_sweep
```

Chờ khoảng 15 phút (gom cụm mỗi 5 phút, tạo pack mỗi 10 phút), rồi thử `/latest`, `/pack`, `/ioc`.

**CertStream:** endpoint công khai mặc định `wss://certstream.calidog.io/` nhận kết nối nhưng không gửi chứng chỉ nào
(kiểm ngày 05/11/2026), nên CertStream luôn báo `unknown`. Cần tự chạy certstream-server-go và đặt `HC_CERTSTREAM_URL`.

---

## 13. Integration Kit (Phase I)

Trạng thái: **Built**. Wazuh đã chạy thử trọn luồng trên Wazuh indexer chính hãng 4.14.7 (mẫu kết quả:
`integration_kit/wazuh/SAMPLE_RUN.md`). Elastic và Splunk mỗi bên còn cần một lần chạy với nền tảng thật.

Thư mục `integration_kit/` dành cho bên tích hợp. Nó không nằm trong image Docker, không import code của HuntCompiler và
có file dependency riêng, khoá bằng hash.

- **Luồng:** pull (hoặc nhận push), kiểm HMAC, kiểm lại pack theo JSON Schema và guardrail, thay placeholder bằng dữ
  liệu nội bộ, giải tài khoản bị lộ từ danh bạ nội bộ, chạy từng task, chỉ gửi về `sighting` và `evaluable`. Số hit và
  chi tiết nằm lại trong báo cáo cục bộ.
- **Truy vấn:** Wazuh chạy DSL có sẵn trong pack. Elastic (mặc định EQL) và Splunk chạy rule Sigma được pySigma chuyển
  sang. Zabbix và Defender XDR nằm ngoài phạm vi.
- **An toàn:** chữ ký đúng vẫn phải kiểm lại pack; quá `HC_KIT_MAX_HITS` hit thì coi là rule hỏng; consumer không bao
  giờ tự chặn.

Bắt đầu từ `integration_kit/README.md`, rồi đọc hướng dẫn của nền tảng bạn dùng: `wazuh/GUIDE.md`, `elastic/GUIDE.md`,
`splunk/GUIDE.md`.

---

## 14. Phase H — Hoàn thiện để chạy thật

Trạng thái: **Built và Verified** (15/11/2026: đã chạy thật đủ các mục bắt buộc). Tiêu chí và kết quả: `SPEC.md` §6.
Các quyết định: D-54 đến D-62.

- **Thiếu key không còn làm hỏng lượt quét.** Biến để trống trong `.env` được coi là chưa đặt, nên collector báo
  `not_configured` thay vì gọi API với key rỗng (D-62). GitHub chỉ bổ sung thông tin cho cảnh báo KEV: thiếu token hay
  GitHub lỗi thì cảnh báo vẫn ra, chỉ thiếu phần PoC/Nuclei, và `/status` ghi rõ lý do (D-54).
- **Bảo vệ API (D-56):** mỗi tenant 60 lần gọi/phút. Một IP xác thực sai 20 lần trong 10 phút thì bị chặn (429) tới hết
  khung giờ đó. Tên tenant không tồn tại bị từ chối y hệt chữ ký sai, nên không dò được tên khách hàng.
- **Dọn dữ liệu (D-57):** 02:45 UTC hằng ngày. Xoá sự kiện thô cũ hơn 90 ngày (trừ khi cụm của nó còn hoạt động) và
  nhật ký AI cũ hơn 180 ngày.
- **Log JSON (D-58):** đặt `HC_LOG_FORMAT=json`.
- **Bỏ hẳn KQL cho Defender (D-63, 10/11/2026):** gói chỉ còn Sigma và DSL cho Wazuh; Elastic và Splunk tự chuyển từ
  Sigma. Trường `kql_defender` để trống để gói cũ vẫn hợp lệ. Hệ quả: task V1 mất phần kiểm tra đăng nhập Entra (chỉ
  có trong KQL), còn lại kiểm tra 4625 trên máy chủ nội bộ.
- **Triển khai (D-59 đến D-61):** mọi image được ghim theo digest. Ba profile tuỳ chọn:
  `edge` (Caddy tự cấp HTTPS cho `HC_PUBLIC_HOSTNAME`), `backup` (sao lưu PostgreSQL hằng ngày, giữ 14 bản),
  `certstream` (tự chạy máy chủ CertStream).
- **Nợ kỹ thuật:** bỏ `assert` trong dispatcher (gói push của tenant đã chuyển sang pull được chuyển sang pull API), xoá
  mã Shodan không dùng (D-55), contract luôn ghi xuống dòng LF, thêm file LICENSE (độc quyền).

Đã chạy thật ngày 09/11/2026: khôi phục từ bản sao lưu; máy chủ CertStream tự host gửi chứng chỉ cho watcher; HTTPS qua
Caddy với chứng chỉ nội bộ (TLS, chỉ mở đúng đường dẫn, pull gói có chữ ký hợp lệ, khoá IP, log JSON). HTTPS với tên
miền thật và chứng chỉ Let's Encrypt giờ là tuỳ chọn (D-72). Ngày 15/11 đã chạy thật HTTPS trong LAN với CA nội
bộ của Caddy: consumer kéo pack, kiểm chữ ký đúng.

---

## 15. Phase Q — Nâng chất lượng (còn Q3, Q7, Q8)

Kế hoạch: `docs/plans/KE_HOACH_PHASE_Q.md`. Đã duyệt và xây xong ngày 13/11/2026:

- **CVE trong KEV tự đủ điểm (D-64):** "có trong KEV" được 70 điểm thay vì 50. Một lỗ hổng CISA xác nhận đang bị khai
  thác sẽ đạt ngưỡng gửi 60 trong suốt 7 ngày của cửa sổ KEV, kể cả khi EPSS thấp và chưa có PoC.
- **Cảnh báo vận hành, tự bật (D-65):** đặt `HC_TGBOT_OPS_ALERTS=true` để nhận tin Telegram khi một job lỗi 3 lần liên
  tiếp hoặc ngừng báo cáo (tối đa 6 giờ một lần), và tin khi job hồi phục. Tin này không chứa tình báo.
- **Không giả được IP (D-66):** API chỉ tin header `X-Forwarded-For` từ địa chỉ cố định của Caddy trên mạng nội bộ
  `edge` (`HC_EDGE_SUBNET`, `HC_EDGE_CADDY_IP`).

Q2 (CI) và Q4 (bổ sung dữ liệu GitHub) đã làm trong Phase R (mục 16). Còn chờ bạn: Q3 (thử trên Windows thật), Q7
(sao lưu ra ngoài), Q8 (lọc archives Wazuh).

---

## 16. Phase R — Sẵn sàng cho người dùng tự cài đặt

Trạng thái: **Built** (code xong, test qua, có test với PostgreSQL và chạy thật trên Docker). Chưa *Verified*: CI chưa
chạy trên GitHub (chờ bạn push), và R6 (chạy thật Gemini) chờ key. Kế hoạch và kết quả: `docs/plans/KE_HOACH_PHASE_R.md`.
Các quyết định: D-70 đến D-74.

- **Phân loại CVE trong KEV (D-70).** Thiết bị biên và máy chủ phơi ra Internet (VPN, firewall, cổng email, Exchange,
  vCenter, phần mềm truyền file...) vẫn ra gói V2 kèm task săn tìm. Hệ điều hành và phần mềm máy trạm (Windows, Office,
  trình duyệt...) không ra gói; digest Telegram liệt kê chúng ở mục mới "Exploited CVEs to patch" (CVE đang bị khai thác,
  cần vá). Sản phẩm có trong `login_portals` của manifest luôn được coi là phơi ra Internet. Bảng phân loại nằm trong
  code, đã đối chiếu với toàn bộ danh mục KEV.
- **Gọn log (D-58).** Log từng request HTTP chỉ hiện khi `HC_LOG_LEVEL=DEBUG`. Khi `HC_LOG_FORMAT=json`, cả dòng khởi
  động của API cũng ra JSON.
- **Bổ sung lại dữ liệu GitHub (D-71).** 04:15 UTC hằng ngày, thử lại phần PoC/Nuclei cho CVE trong cửa sổ KEV bị thiếu
  dữ liệu, tối đa `HC_KEV_REENRICH_MAX_ATTEMPTS` (5) lần mỗi CVE. Lỗi hiện trên trang sức khoẻ.
- **Chạy trên máy của bạn (D-72).** `HC_TLS_MODE=internal`: Caddy tự cấp chứng chỉ bằng CA nội bộ, dùng trong LAN mà
  không cần tên miền công khai. Consumer chạy cùng máy được dùng `http://127.0.0.1` hoặc `http://localhost`; mọi địa
  chỉ khác vẫn bắt buộc HTTPS. Tên miền công khai với Let's Encrypt giờ là tuỳ chọn.
- **Chính sách Telegram CTI và HIBP (D-73).** Chỉ theo dõi kênh công khai, chỉ đọc, bằng tài khoản nghiên cứu riêng;
  HIBP chỉ dùng cho domain bạn sở hữu và đã xác minh.
- **CI (D-74).** `.github/workflows/ci.yml` chạy lint, toàn bộ test với PostgreSQL, `alembic check`, kiểm tra
  contract và `pip-audit`. Các action ghim theo commit SHA, token chỉ đọc. `requirements-dev.txt` giờ được khoá bằng
  hash từ `requirements-dev.in`.

### Cài đặt trên một máy (tóm tắt `docs/INSTALL.md`)

**Chọn máy.** Nên dùng máy hoặc máy ảo riêng, không dùng máy làm việc hằng ngày: hệ thống xử lý nội dung do kẻ tấn công
viết (chỉ đọc như văn bản, không bao giờ chạy), tách riêng để hạn chế hậu quả nếu có lỗi.

**Tài nguyên đo thật ngày 15/11/2026** (cấu hình mặc định, một tenant, đã nạp dataset tham chiếu):

| Thành phần | RAM | Ghi chú |
|---|---|---|
| worker (4 tiến trình xử lý) | 650 MB (cao nhất 690 MB) | phần lớn là danh sách whitelist MISP (~300 MB), nạp một lần rồi 4 tiến trình dùng chung (D-75; trước đó 1,5 GB) |
| beat, api, certstream | 60–80 MB mỗi cái | |
| PostgreSQL, Redis | 37 MB và 5 MB | |
| **Tổng** | **khoảng 0,9 GB** | Caddy thêm 15 MB; bot Telegram, backup thêm 50–100 MB mỗi cái |

CPU cao nhất 79% một nhân (khi đồng bộ dataset). Ổ đĩa: image 0,54 GB, image PostgreSQL và Redis 0,48 GB, dữ liệu
ban đầu khoảng 50 MB.

| | Tối thiểu | Khuyến nghị |
|---|---|---|
| CPU | 2 nhân | 4 nhân |
| RAM | 4 GB | 8 GB |
| Ổ đĩa trống | 20 GB | 40 GB (có sao lưu) |

**Các bước:**
1. `cp .env.example .env`, điền mật khẩu PostgreSQL và Redis, khoá Fernet (`HC_MASTER_ENCRYPTION_KEYS`), secret và
   token của tenant. Nên có `HC_GITHUB_TOKEN` (token chỉ đọc repo công khai).
2. Sửa `config/tenant_manifest.yaml`: domain, cổng đăng nhập, dải IP công khai, sản phẩm đang dùng. Chỉ thông tin công khai.
3. `docker compose up -d --build`, rồi nạp manifest và kiểm tra `/readyz` (lệnh ở mục 8).
4. Cho consumer kết nối:
   - **cùng máy:** `http://127.0.0.1:8000`;
   - **trong LAN:** đặt `HC_TLS_MODE=internal` và `HC_PUBLIC_HOSTNAME` (tên hoặc IP trong LAN), chạy
     `docker compose --profile edge up -d caddy`, lấy chứng chỉ gốc bằng
     `docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./huntcompiler-root.crt` rồi trỏ
     `HC_KIT_CA_BUNDLE` của consumer tới file đó;
   - **qua Internet:** để `HC_TLS_MODE=public`, tên miền trỏ về máy, mở cổng 80 và 443.
5. Sao lưu: `docker compose --profile backup up -d backup`, và chép bản sao lưu ra nơi khác.

**Cập nhật:** `git pull` rồi `docker compose up -d --build` (migration tự chạy). **Gỡ cài đặt:** lệnh `down -v` trong
`docs/INSTALL.md` xoá toàn bộ dữ liệu, nên sao lưu trước nếu còn cần.
