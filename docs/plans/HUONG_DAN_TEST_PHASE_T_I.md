# Hướng dẫn test Phase T (Telegram) và Phase I (Integration Kit)

Cập nhật: 16/11/2026. Mục tiêu: chuyển hai phase từ **Built** sang **Verified**.

| Phần | Nội dung | Ai làm | Trạng thái |
|---|---|---|---|
| 0 | Chuẩn bị key và kích hoạt collector | Bạn | Đã chạy collector; còn thiếu key (mục 0.1) |
| A | Checklist Telegram | Bạn | Một phần đã đạt (mục A) |
| B | Integration Kit với Wazuh | Tôi | **Đã test xong**, có mẫu kết quả (mục B) |
| C, D | Elastic, Splunk | Bạn, nếu có nền tảng đó | Chưa làm |

---

## 0. Chuẩn bị chung

### 0.1 Key trong `.env`

| Biến | Cần không? | Vì sao |
|---|---|---|
| `HC_GITHUB_TOKEN` | Nên có | Xem giải thích ngay dưới bảng. |
| `HC_URLSCAN_API_KEY` | Nên có | Thiếu key thì URLScan trả `403 Forbidden` mỗi lượt quét. Khi đó `/status` báo URLScan `failing (HTTPStatusError)`. Có key mới có cluster giả mạo thương hiệu, AiTM (V1) và ClickFix (V3). |
| `HC_ABUSECH_AUTH_KEY` | Nên có | Key miễn phí của abuse.ch (MalwareBazaar). Nó tạo cluster có domain và hash thật, để `/ioc` tìm thấy cluster. |

**Vì sao cần GitHub token.** Khi một CVE mới vào danh sách KEV của CISA và khớp tech stack của bạn (FortiGate,
Exchange, vCenter...), HuntCompiler lên GitHub tìm hai thứ:
1. **Các repo PoC công khai cho CVE đó.** Hệ thống đọc chúng dưới dạng văn bản, không bao giờ chạy. Mục đích là chấm
   điểm PoC giả hoặc có mã độc (loại này hay nhắm vào chính dân bảo mật) và lấy dấu hiệu khai thác.
2. **Template Nuclei cho CVE đó.** Có template nghĩa là kẻ tấn công quét hàng loạt rất dễ, nên mức ưu tiên tăng.

GitHub không cho tìm kiếm code nếu không đăng nhập (trả lỗi 401). Không có token thì các lệnh gọi khác chỉ được 60 lần
mỗi giờ, trong khi mỗi CVE tốn khoảng một chục lần gọi.

Thiếu token hay GitHub lỗi thì cảnh báo KEV **vẫn ra**, chỉ thiếu phần PoC/Nuclei (D-54). Phần thiếu được thử lại mỗi
ngày lúc 04:15 UTC (D-71). Lần chạy thật ngày 15/11 cho thấy không có token thì hạn mức hết rất nhanh, và CVE có thể
thiếu tới 20 điểm (PoC đáng tin + template Nuclei). Vì vậy vẫn nên có token.

Cách tạo: GitHub → Settings → Developer settings → *Fine-grained tokens*, chọn "Public repositories (read-only)",
không cấp quyền nào khác. Token chỉ dùng để đọc.

Sửa `.env` xong thì tạo lại các container đọc file này:

```bash
docker compose up -d --force-recreate worker beat telegram-bot
```

### 0.2 Kích hoạt collector ngay, không chờ lịch

```bash
docker compose exec worker celery -A app.worker.celery_app:celery_app call collectors.edge_exploit_sweep
```

```bash
docker compose exec worker celery -A app.worker.celery_app:celery_app call collectors.malwarebazaar_sweep
```

Lệnh thứ hai chỉ có tác dụng khi đã có `HC_ABUSECH_AUTH_KEY`. Chờ khoảng 15 phút rồi gửi `/status`.

---

## A. Telegram: checklist TELEGRAM.md §9

Đã đạt (chủ dự án xác nhận):

| Mục | Kết quả |
|---|---|
| `/status` | Có tình trạng từng collector; Reference datasets, Edge exploits, Clustering, Pack building đều `ok` |
| `/digest` (xem trước) | Đạt (05/11) |
| `/latest` | Liệt kê 3 cluster V6, V5, V4 kèm mã pack |
| `/ioc` | `127.0.0.0` → `drop (not_global)`; một IP công khai → `block (no_whitelist_match)`, không có cluster |
| Lệnh sai (`/lastest`) | Bot gợi ý `/help` |

Còn lại:

1. **Người lạ:** dùng một tài khoản Telegram khác nhắn `/status`. **Mong đợi:** bot im lặng.
2. **Digest định kỳ:** đặt `HC_TGBOT_DIGEST_TIMES=["<giờ hiện tại + 5 phút>"]` (giờ Việt Nam), chạy
   `docker compose up -d --force-recreate beat` và chờ. **Mong đợi:** digest tới đúng giờ, không có chữ "preview".
   Xong thì đặt lại `["08:00"]`.
3. **`/pack <mã 8 ký tự sau dấu #>`**, ví dụ `/pack 7baa27d2`. **Mong đợi:** một tin tóm tắt và các file `.json`,
   `.yml`, `queries-….txt`.
4. **`/cve`**: viết liền, không có dấu cách sau `/`. Ví dụ `/cve CVE-2099-0001` phải trả "not tracked". Gõ `/ cve`
   (có dấu cách) thì bot hiểu đó không phải lệnh và không trả lời.
5. **Group SOC:** thêm bot vào một group riêng tư, đặt `HC_TGBOT_CHAT_IDS=[-100…]`, tạo lại `worker beat telegram-bot`,
   rồi lặp lại bước 2 và 3. Một thành viên không có trong `HC_TGBOT_ALLOWED_USER_IDS` gửi lệnh: bot phải im lặng.

---

## B. Integration Kit với Wazuh: đã test, đây là mẫu kết quả

Tôi đã chạy toàn bộ luồng trên Wazuh indexer chính hãng. Bản đầy đủ bằng tiếng Anh, gồm lệnh, log, báo cáo và cách
Wazuh lưu sự kiện, nằm ở [integration_kit/wazuh/SAMPLE_RUN.md](../../integration_kit/wazuh/SAMPLE_RUN.md).

**Môi trường:**
- Wazuh indexer **4.14.7** (OpenSearch 2.19.5), image chính thức, HTTPS và chứng chỉ sinh bằng công cụ của Wazuh.
- Mapping chính thức của Wazuh (`wazuh-template.json`), nạp giống cách Filebeat nạp.
- 22 sự kiện Windows đúng định dạng Wazuh ghi vào `wazuh-archives-*`, gồm Sysmon 1, 3, 6, 7, 22, Security 4624/4625 và
  System 7045. Mỗi sự kiện khớp có một sự kiện "gần giống" phải **không** khớp.
- HuntCompiler 0.4.0 với tenant mẫu `tencongty`: 5 pack, 12 task (V1, V2, V4, V5, V6).
- Consumer mẫu chạy đúng lệnh mà bên tích hợp sẽ dùng: `python -m integration_kit.reference_consumer cycle`.

**Kết quả:**

```text
pull: {'queued': 5, 'duplicate': 0, 'rejected': 0}
pack 0d6bf841…: sighting=True evaluable=True feedback=recorded
pack 22524d37…: sighting=True evaluable=True feedback=recorded
pack 4322b3a5…: sighting=True evaluable=True feedback=recorded
pack b17bef2a…: sighting=True evaluable=True feedback=recorded
pack f89848a6…: sighting=True evaluable=True feedback=recorded
```

| Task | Phải khớp | Không được khớp | Kết quả |
|---|---|---|---|
| V4 tunnel DNS | `hc-test.trycloudflare.com`, cả bản viết HOA | `www.example.com` | 2/2 đúng |
| V4 bot API | powershell.exe gọi `api.telegram.org` | chrome.exe gọi cùng tên | đúng |
| V4 RMM lạ (process và DNS) | `labrmm.exe`, `relay.labrmm.example` | AnyDesk (đã duyệt trong manifest) | đúng |
| V1 tài khoản bị lộ | 4625 của `anguyen` | 4625 của `bthanh` | đúng |
| V2 thiết bị biên | đăng nhập và kết nối 445 từ `10.20.0.1` | từ `10.30.0.5` | đúng |
| V5 driver, side-load | driver có hash xấu, driver lạ ngoài `System32\drivers`, DLL trong `Windows\Temp` | driver hợp lệ trong `System32\drivers`, DLL có chữ ký trong `System32` | đúng |
| V6 package độc | `npm install lab-evil-pkg` | `npm install express` | đúng |

Tổng cộng **12/12 task đúng**. HuntCompiler ghi nhận feedback cho cả 5 pack. Chi tiết số hit chỉ nằm trên máy consumer,
không gửi về.

**Lỗi tìm ra khi test và đã sửa (D-53):** Wazuh lưu đường dẫn Windows với dấu `\` nhân đôi (`C:\\Windows\\...`), trong
khi truy vấn cũ dùng dấu `\` đơn. Lần chạy đầu sai 3 task:
- 2 cảnh báo sai: driver hợp lệ trong `System32\drivers` vẫn bị báo;
- 1 lần bỏ sót: DLL side-load trong `Windows\Temp` không bị phát hiện.

Rule ClickFix V3 (đường dẫn registry `RunMRU`) cũng bị cùng lỗi này và trước đây không bao giờ khớp trên Wazuh. Đã sửa
code, thêm test hồi quy và chạy lại: 12/12 đúng. Truy vấn Splunk và Elastic không đổi. Các pack cũ có đường dẫn Windows
sẽ được phát lại bản đã sửa ở lần build pack kế tiếp.

**Khi đưa vào Wazuh của bạn**, chỉ cần làm theo mục 7 của SAMPLE_RUN.md: bật archives, tra DNS
`hc-test.trycloudflare.com` trên một máy có Sysmon, rồi chạy `cycle`.

---

## C. Chuẩn bị consumer (chỉ khi test Elastic hoặc Splunk)

1. Cài trên Windows (file `integration_kit/requirements.txt` khoá cho Linux, nên trên Windows cài từ `.in`):
   ```powershell
   py -3.12 -m venv .kitvenv
   .\.kitvenv\Scripts\pip install -r integration_kit\requirements.in
   ```
2. Chép `integration_kit\consumer.env.example` thành `consumer.env` và điền:
   - `HC_KIT_BASE_URL=http://127.0.0.1:8000` (consumer chạy cùng máy nên được dùng `http://`, D-72; máy khác thì
     dùng HTTPS theo `docs/INSTALL.md`);
   - `HC_KIT_TENANT=tencongty`;
   - `HC_KIT_API_TOKEN` và `HC_KIT_HMAC_SECRET` lấy từ `HC_TENANT_TENCONGTY_API_TOKEN` và
     `HC_TENANT_TENCONGTY_HMAC_SECRET` trong `.env`;
   - `HC_KIT_TELEMETRY`: chỉ ghi những gì máy test thật sự gửi lên.
3. Nạp biến vào PowerShell:
   ```powershell
   Get-Content .\consumer.env | Where-Object { $_ -match '^\s*HC_KIT_[A-Z_]+=' } | ForEach-Object {
     $name, $value = $_ -split '=', 2
     Set-Item -Path "env:$($name.Trim())" -Value $value.Trim()
   }
   ```
4. **Tạo sự kiện vô hại trước khi chạy consumer**: `Resolve-DnsName hc-test.trycloudflare.com` trên máy có Sysmon.
   HuntCompiler chỉ nhận feedback đầu tiên của mỗi pack, nên chạy consumer trước thì pack bị ghi là "không thấy".

Lưu ý: sau khi Docker khởi động lại, cổng `127.0.0.1:8000` có thể không được mở ra máy dù container API vẫn chạy tốt.
Nếu consumer báo không kết nối được, chạy `docker compose up -d --force-recreate api`.

## D. Elastic hoặc Splunk

**Elastic:** đặt `HC_KIT_PLATFORM=elastic`, cùng `HC_KIT_ELASTIC_URL`, `_INDEX` (`logs-*` hoặc `winlogbeat-*`),
`_API_KEY` (chỉ đọc) và `_CA_BUNDLE`. Xem trước truy vấn:
`.\.kitvenv\Scripts\python -m integration_kit.reference_consumer convert pack-xxxx.json --platform elastic`. Nếu
Elastic báo thiếu trường `*.caseless`, đặt `HC_KIT_ELASTIC_PIPELINE=ecs_windows_old`.

**Splunk:** đặt `HC_KIT_PLATFORM=splunk`, cùng `HC_KIT_SPLUNK_URL=https://<splunk>:8089`, `_TOKEN` và `_CA_BUNDLE`.
Nếu input Windows dùng XML thì đặt `HC_KIT_SPLUNK_SOURCE_STYLE=xml`.

Sau đó chạy `.\.kitvenv\Scripts\python -m integration_kit.reference_consumer cycle` và mở báo cáo trong
`hc-kit-state\done\`. Task `v4-tunnel-dns` phải có `"hits"` lớn hơn 0.

---

## E. Những gì gửi lại cho tôi

| Phần | Cần gửi |
|---|---|
| 0 | Ảnh `/status` sau khi thêm key và kích hoạt collector |
| A | Năm mục còn lại đạt hay không |
| D | Số hit của `v4-tunnel-dns` và các `notes` lạ, nếu bạn test Elastic hoặc Splunk |

Tôi sẽ đánh dấu **Verified** đúng những mục bạn xác nhận, không làm tròn.
