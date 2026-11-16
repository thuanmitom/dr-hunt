# Kế hoạch Phase R: sẵn sàng cho người dùng tự cài đặt

Ngày lập: 14/11/2026 · Trạng thái: **đã duyệt (14/11, "duyệt theo đề xuất"); R1–R5 và Q11 xây xong 15/11/2026**; R6 chờ key Gemini. Kết quả ở cuối file.

Nguồn: câu trả lời của chủ dự án ngày 14/11 (Q1, Q3, Q6, Q11, Q12), kết quả tự test ngày 14/11 (điểm A, B, C), và
các mục còn lại của Phase Q (Q2, Q4).

---

## 1. Các quyết định đã ghi nhận

| Câu hỏi | Bạn chọn | Ghi tại | Hệ quả |
|---|---|---|---|
| Q1. Sản phẩm cho ai | Cá nhân, nghiên cứu, hoặc doanh nghiệp nhỏ | D-67 | Không làm dịch vụ dùng chung cho nhiều khách. Mỗi bản cài thường chỉ có một tenant. |
| Q3. Chạy ở đâu | Trên chính máy của người dùng hoặc doanh nghiệp | D-67 | Không bắt buộc có tên miền công khai. HTTPS dùng trong mạng nội bộ. Cần hướng dẫn cài đặt trên một máy (mục R5). |
| Q12. AI | Gemini trả phí | D-68 | AI vẫn tắt mặc định; mỗi bản cài tự bật bằng key và ngân sách (mục R6). |
| Q6. Entra | Chỉ cần tài liệu, không đưa vào test | D-69 | Đã viết `integration_kit/ENTRA_GUIDE.md`: cách tự kiểm tra tài khoản bị lộ trong log đăng nhập Entra trên Wazuh, Elastic, Splunk, kèm truy vấn mẫu. |
| Q11. Telegram CTI và HIBP | Nhờ đề xuất, đã duyệt đề xuất | D-73 | Chỉ kênh công khai, chỉ đọc; HIBP chỉ domain của bạn đã xác minh. |

Nguyên tắc "không kết nối vào mạng nội bộ" vẫn giữ nguyên: dù chạy trên máy người dùng, HuntCompiler chỉ đọc tình báo
công khai và phát gói; không đọc log, không kết nối tới hệ thống nội bộ.

---

## 2. Đề xuất cho Q11 (cần bạn duyệt)

> Đây là đề xuất kỹ thuật và vận hành, **không phải tư vấn pháp lý**. Nếu dùng cho doanh nghiệp, nên hỏi bộ phận
> pháp chế trước khi bật.

### 2.1 Theo dõi Telegram (Telegram CTI)

**Nên theo dõi:**
- Chỉ kênh hoặc nhóm **công khai**: ai cũng xem được, không cần được duyệt hay mời, không phải trả tiền.
- Ví dụ loại kênh: kênh tin tức tình báo mối đe doạ, kênh công khai thông báo vụ rò rỉ dữ liệu, kênh theo dõi các trang
  công bố nạn nhân ransomware.

**Không bao giờ:**
- tham gia nhóm kín hay nhóm phải qua sàng lọc;
- mua bán, đăng bài, nhắn tin hay tương tác với người trong kênh;
- tải file đính kèm (code đã chặn sẵn);
- dùng tài khoản hay mật khẩu tìm thấy để đăng nhập thử.

**Cách làm đề xuất:**
1. Dùng một **tài khoản Telegram nghiên cứu riêng** (SIM riêng), không dùng tài khoản cá nhân.
2. Lập **danh sách kênh** trong một file nội bộ (không commit): tên kênh, lý do theo dõi, ngày thêm. Rà lại mỗi quý; gỡ
   kênh nào chuyển sang riêng tư.
3. Bắt đầu với 3–5 kênh, xem chất lượng trong 2 tuần rồi mới thêm.
4. Chấp nhận rủi ro tài khoản nghiên cứu bị Telegram khoá vì truy cập tự động.

**Về dữ liệu cá nhân:** hệ thống đã tối giản dữ liệu. Mật khẩu bị bỏ ngay khi đọc, tài khoản chỉ lưu dạng mã HMAC kèm
bản che, và không lưu nội dung tin nhắn. Cách làm này phù hợp nguyên tắc tối thiểu hoá dữ liệu trong các quy định bảo vệ
dữ liệu cá nhân hiện hành (Nghị định 13/2023/NĐ-CP và Luật Bảo vệ dữ liệu cá nhân 2025).

### 2.2 HIBP (Have I Been Pwned)

**Điều kiện:**
- Có **API key** của HIBP (gói trả phí; trang API key ghi gói thấp nhất từ khoảng 3,95 USD/tháng, nên kiểm tra lại
  trước khi mua).
- **Xác minh quyền sở hữu domain** trong dashboard của HIBP. Có 4 cách: bản ghi DNS TXT, email gửi tới địa chỉ quản trị
  của domain, thẻ meta, hoặc file đặt ở gốc website. Mỗi domain phải xác minh riêng; subdomain không tự được tính theo
  domain cha.

**Đề xuất:**
- Chỉ xác minh domain bạn hoặc doanh nghiệp **sở hữu và quản trị**. Không tra domain của người khác.
- Dùng cách DNS TXT: gọn và lưu được lâu.
- Điền domain email vào `brand.email_domains` trong manifest (collector HIBP dùng danh sách này trước), rồi đặt
  `HC_HIBP_API_KEY` trong `.env`.

---

## 3. Đợt việc tiếp theo

| # | Việc | Nguồn | Độ lớn | Cần bạn |
|---|---|---|---|---|
| R1 | Phân loại CVE trong KEV | Tự test (điểm A) | Vừa | Chọn phương án |
| R2 | Gọn log | Tự test (điểm B, C) | Nhỏ | Không |
| R3 | CI (GitHub Actions) | Phase Q (Q2) | Nhỏ | Đồng ý; chỉ chạy khi bạn push |
| R4 | Bổ sung lại dữ liệu GitHub cho CVE | Phase Q (Q4) | Vừa | Không |
| R5 | Điều chỉnh cho mô hình tự cài đặt | D-67 | Vừa | Duyệt 2 thay đổi nhỏ |
| R6 | Bật AI Gemini và chạy thật | D-68 | Nhỏ (phần tôi) | Key Gemini |

### R1. Phân loại CVE trong KEV

**Vấn đề (thấy khi tự test).** Mọi CVE trong KEV đều thành gói V2 "khai thác thiết bị biên", kèm task tìm đăng nhập từ
IP của VPN/firewall. Một CVE của Windows nhận task không liên quan. Tag `microsoft:windows_server` lại khớp với mọi KEV
"Microsoft Windows" (mỗi tháng có nhiều), nên khách nhận nhiều gói ít giá trị.

**Phương án:**

| | Cách làm | Đánh giá |
|---|---|---|
| **A (đề xuất)** | Code phân loại từng CVE theo sản phẩm: **(1) thiết bị biên và dịch vụ phơi ra Internet** (VPN, firewall, gateway, cân bằng tải, Exchange, SharePoint, vCenter...) thì giữ gói V2 như hiện nay; **(2) hệ điều hành và phần mềm máy trạm** (Windows, Office, trình duyệt...) thì **không tạo gói săn tìm** mà đưa vào mục mới "CVE đang bị khai thác cần vá" trong digest Telegram. Nếu AI được bật và tạo được task riêng từ PoC thì mới tạo gói. Sản phẩm nằm trong `login_portals` của manifest luôn được coi là phơi ra Internet. Bảng phân loại do code giữ, không dùng AI để đoán. | Hết gói nhiễu, vẫn nhắc vá. Gói V2 giữ đúng nghĩa. |
| B | Thêm một vector mới cho lỗ hổng máy trạm, có template riêng | Lớn hơn nhiều, và hiện chưa có task săn tìm chung nào tốt cho loại lỗ hổng này |
| C | Giữ nguyên, chỉ sửa mô tả | Không giải quyết nhiễu |

**Xong khi:**
- CVE thiết bị biên vẫn ra gói V2;
- CVE Windows không ra gói nhưng có trong digest;
- có test âm cho sản phẩm không rõ loại (mặc định xử lý như loại 2, chỉ nhắc vá).

Ghi thành quyết định D-70.

### R2. Gọn log

- Hạ log của thư viện HTTP xuống mức chỉ ghi cảnh báo ở worker, beat và watcher (bot đã làm sẵn). Khi tự test, loại log
  này chiếm 94% số dòng.
- Khi `HC_LOG_FORMAT=json`, cấu hình uvicorn để cả 2 dòng khởi động của API cũng ra dạng JSON.
- **Xong khi:** test kiểm tra mức log, và một lần chạy thật cho thấy mọi dòng log của API đều là JSON.

### R3. CI

Như mục Q2 của Phase Q:
- `.github/workflows/ci.yml` chạy PostgreSQL 16 (image đã ghim), lint, toàn bộ test, `alembic check`, kiểm tra contract
  và bản sao schema trong Integration Kit;
- các GitHub Action được ghim theo commit SHA; khoá `requirements-dev.txt` bằng hash; thêm `pip-audit`.

CI chỉ chạy sau khi bạn commit và push. Tôi viết sẵn file, không tự push.

### R4. Bổ sung lại dữ liệu GitHub cho CVE

Như mục Q4 của Phase Q: job hằng ngày thử lại phần PoC/Nuclei cho các CVE trong cửa sổ KEV đang có ghi chú "thiếu dữ liệu
GitHub", rồi cập nhật điểm. Cụm nào trước đó chưa đủ điểm sẽ được gửi khi đủ.

### R5. Điều chỉnh cho mô hình tự cài đặt (D-67)

| # | Việc | Ghi chú |
|---|---|---|
| R5.1 | **HTTPS trong mạng nội bộ:** thêm `HC_TLS_MODE=internal` cho Caddy. Chứng chỉ do CA nội bộ của Caddy cấp, dùng được trong LAN mà không cần tên miền công khai. Kèm hướng dẫn lấy chứng chỉ gốc cho consumer. | Đã chạy thử với `localhost` ngày 09/11. Chế độ Let's Encrypt giữ làm tuỳ chọn. |
| R5.2 | **Consumer chạy trên cùng máy:** cho phép `http://127.0.0.1` và `http://localhost` mà không cần `HC_KIT_ALLOW_HTTP`. Mọi địa chỉ khác vẫn bắt buộc HTTPS. | Nới nhẹ một rào chắn của consumer (lưu lượng loopback không rời khỏi máy). **Cần bạn duyệt.** |
| R5.3 | **Hướng dẫn cài trên một máy** (tiếng Việt và tiếng Anh): yêu cầu RAM, CPU và ổ đĩa (đo trong lần chạy thử tới), các bước cài, cập nhật, sao lưu, gỡ cài đặt. | Khuyến nghị chạy trên máy hoặc máy ảo riêng, không trên máy làm việc hằng ngày, vì hệ thống xử lý nội dung do kẻ tấn công viết (dưới dạng văn bản). |
| R5.4 | Chuyển mục kiểm tra "HTTPS với tên miền công khai" của Phase H thành **tuỳ chọn**. | Không còn bắt buộc với mô hình tự cài. |

### R6. Bật AI Gemini

**Phần của bạn:** tạo API key Gemini trả phí, đặt `HC_GEMINI_API_KEY`, `HC_LLM_ENABLED=true`, và ngân sách token mỗi
ngày (`HC_LLM_DAILY_TOKEN_BUDGET`).

**Phần của tôi:**
1. Kiểm tra tên model hiện hành của Google. Mặc định đang là `gemini-2.5-flash` / `gemini-2.5-pro`, có thể đã cũ.
2. Chạy thật một lần trên cụm V2/V3 thật.
3. Cùng bạn duyệt nhật ký AI. Đây là mục kiểm tra chạy thật của Phase 3.
4. Ước tính chi phí mỗi ngày.

Việc này chờ key. Mặc định "AI tắt" không đổi.

---

## 4. Câu hỏi cần bạn trả lời

| # | Câu hỏi | Đề xuất |
|---|---|---|
| 1 | R1: chọn phương án A, B hay C? | A |
| 2 | R5.2: cho phép consumer dùng HTTP trên loopback (cùng máy)? | Có |
| 3 | R5.1: thêm chế độ HTTPS nội bộ cho Caddy? | Có |
| 4 | R3: dùng GitHub Actions, có thêm `pip-audit`? | Có, có |
| 5 | Q11: duyệt đề xuất ở mục 2? | Duyệt |
| 6 | R6: khi nào có key Gemini? | Khi bạn sẵn sàng |

Trả lời "duyệt theo đề xuất" là tôi làm R1, R2, R3 (chỉ viết file), R4 và R5. R6 làm khi có key.

**Cách nghiệm thu chung:** toàn bộ test qua (có PostgreSQL), lint sạch, có test âm cho mỗi rào chắn mới, tài liệu và
quyết định được cập nhật, và mỗi phần có thể chạy thật thì đều được chạy thật.

---

## Kết quả (15/11/2026)

| # | Trạng thái | Kiểm chứng |
|---|---|---|
| R1 | **Built**, đã chạy thật | D-70. Test đơn vị 32 cách đặt tên hãng/sản phẩm (có test âm cho sản phẩm không rõ loại và tên na ná) và test PostgreSQL. Chạy thật trên danh mục KEV thật: 3 CVE thiết bị biên (Barracuda ESG, Cisco BroadWorks, IBM Aspera Faspex) ra gói; Office và Chromium không ra gói mà nằm ở mục "Exploited CVEs to patch" của digest. |
| R2 | **Built**, đã chạy thật | Không còn dòng log httpx nào (trước đây 94% số dòng của worker). Mọi dòng log của API, kể cả "Started server process", đều là JSON. |
| R3 | **Built** (chỉ viết file) | `.github/workflows/ci.yml`, `requirements-dev.txt` khoá bằng hash (giữ nguyên 84 phiên bản runtime). Đã chạy ở máy đủ các bước của CI: lint, 349 test với PostgreSQL, `alembic check`, sinh lại contract (không đổi), bản schema của kit (giống hệt), `pip-audit` (qua). CI thật chạy khi bạn push. |
| R4 | **Built**, đã chạy thật | D-71. Lần 1, GitHub đang chặn (403): dữ liệu cũ giữ nguyên, trang sức khoẻ báo `failing`. Lần 2, sau khi GitHub mở lại: 4 CVE được bổ sung PoC, điểm tăng từ 70 lên 80, sức khoẻ về `ok`. Không có token thì không gọi tìm code. |
| R5 | **Built**, đã chạy thật | D-72. HTTPS trong LAN với CA nội bộ của Caddy (tên `huntcompiler.lan`): consumer chỉ tin chứng chỉ gốc của Caddy, kéo 3 pack, chữ ký đúng, cấu trúc đúng; sai secret thì cả 3 bị bỏ; thiếu chứng chỉ gốc hoặc sai tên máy thì không kết nối được; giá trị `HC_TLS_MODE` sai thì Caddy không khởi động. Kit nhận `http://` tới localhost, chặn mọi địa chỉ khác (test âm). `docs/INSTALL.md` và README.vi mục 16 có số đo thật. |
| Q11 | **Đã ghi** | D-73; SPEC Q11 đã trả lời. |
| R6 | Chờ key Gemini | — |

**Lần chạy thật tìm ra 2 vấn đề, đã sửa:**
1. Bảng phân loại KEV: CISA giờ ghi VMware dưới tên "Broadcom", và một số sản phẩm phơi ra Internet (Cisco Secure Email
   Gateway, Cisco SD-WAN, BeyondTrust, GoAnywhere, ScreenConnect, IBM Aspera) bị xếp nhầm. Đã đối chiếu với toàn bộ
   1.781 mục KEV (sau khi sửa: 651 thiết bị biên, 1.130 máy trạm) và thêm test cho từng trường hợp.
2. RAM của worker: 1,5 GB vì danh sách whitelist MISP (~300 MB) bị nạp riêng ở 4 tiến trình. Đã sửa (D-75): nạp một lần
   rồi dùng chung, worker còn khoảng 650 MB, cả stack khoảng 0,9 GB.

**Bạn đã duyệt ngày 15/11:**
- `pip-audit` báo lỗ hổng PYSEC-2026-2447 trong `diskcache` 5.6.3 (đi kèm pySigma, chưa có bản sửa, HuntCompiler không
  dùng phần đó). CI bỏ qua riêng mã này, có ghi lý do trong D-74; bỏ ngoại lệ khi có bản sửa.
- Phase H chuyển sang **Verified**: HTTPS qua Caddy đã chạy thật; tên miền công khai là tuỳ chọn.

**Còn lại (không chặn việc commit):**
- Banner khởi động của Celery (worker, beat) vẫn in dạng chữ thường, không phải JSON; không chứa bí mật.
- curl trên Windows cần thêm `--ssl-no-revoke` khi thử với CA nội bộ (đã ghi trong `docs/INSTALL.md`).
- Trong 9 lần chạy toàn bộ test ngày 15/11, lần đầu có 1 test lỗi, 8 lần sau đều qua hết 349 test (kể cả khi máy đang
  bận). Lần lỗi không được lưu nên chưa biết test nào; nếu CI gặp lại, log của CI sẽ chỉ ra.
