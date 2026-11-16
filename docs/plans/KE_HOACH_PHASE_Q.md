# Kế hoạch Phase Q: nâng chất lượng (8 điểm tự đánh giá)

Ngày lập: 12/11/2026 · Trạng thái: **Q1, Q5, Q6 đã duyệt và xây xong (13/11/2026)**; Q2 và Q4 làm trong Phase R
(xong 15/11/2026, xem `KE_HOACH_PHASE_R.md`); **Q3, Q7, Q8 còn chờ** bạn chuẩn bị hoặc chọn.

Mục tiêu: sửa 8 điểm yếu tìm ra khi tự đánh giá ngày 11/11. Các mặc định đã chốt giữ nguyên, trừ chỗ ghi rõ "cần bạn
quyết". Mỗi điểm có: vấn đề, đề xuất, phần bạn cần quyết, độ lớn, và cách biết là xong.

## Tóm tắt

| # | Điểm | Đề xuất ngắn | Độ lớn | Cần bạn |
|---|---|---|---|---|
| Q1 | CVE trong KEV chỉ được 50 điểm, dưới ngưỡng gửi 60 | Nâng điểm KEV lên 70 | Nhỏ | Chọn phương án |
| Q2 | Chưa có CI | GitHub Actions chạy test, lint, kiểm tra migration và contract | Nhỏ | Đồng ý; push code |
| Q3 | Phát hiện chưa thử trên máy Windows thật | Bộ thao tác vô hại, chạy trong Windows Sandbox, rồi sửa rule theo kết quả | Vừa | Chọn môi trường thử |
| Q4 | CVE lỡ thiếu dữ liệu GitHub thì thiếu mãi | Job bổ sung lại hằng ngày | Vừa | Không |
| Q5 | Không tự báo khi hệ thống hỏng | Tin cảnh báo vận hành qua Telegram, mặc định tắt | Nhỏ | Đồng ý thêm loại tin mới |
| Q6 | Có thể giả IP để né khoá | Chỉ tin `X-Forwarded-For` từ Caddy | Nhỏ | Không |
| Q7 | Bản sao lưu nằm cùng máy chủ | Chép bản sao lưu đã mã hoá ra nơi khác (restic) | Vừa | Chọn nơi lưu |
| Q8 | Khách dùng Wazuh phải lưu mọi sự kiện | Hướng dẫn chỉ lưu các loại sự kiện pack cần, có số liệu dung lượng | Vừa | Cho phép thử trên Wazuh manager |

**Thứ tự đề xuất:**
- **Đợt 1** (làm được ngay, không cần chuẩn bị gì): Q1, Q6, Q4, Q2.
- **Đợt 2** (cần bạn chuẩn bị hoặc chọn): Q3, Q7, Q8.
- **Đợt 3** (cần bạn quyết một mặc định): Q5.

---

## Q1. Điểm của CVE trong KEV

**Vấn đề.** Điểm tin cậy cho một CVE được cộng như sau:

| Có trong KEV | EPSS ≥ 10% | EPSS top 10% | Có PoC đáng tin | Có template Nuclei | Dùng trong ransomware |
|---|---|---|---|---|---|
| +50 | +15 | +10 | +10 | +10 | +10 |

Ngưỡng gửi mặc định của tenant là 60. CVE mới vào KEV thường có EPSS thấp trong vài ngày đầu và chưa có PoC, nên chỉ được
50 điểm. Kết quả là **không gửi cho khách, dù CISA đã xác nhận lỗ hổng đang bị khai thác.**

Thêm một chi tiết: điểm giảm dần theo thời gian, bắt đầu từ 0 giờ UTC ngày CVE vào KEV (giảm một nửa sau 30 ngày). Nếu
chỉ nâng lên đúng 60, điểm sẽ tụt xuống 59 sau khoảng 9 giờ, thường là trước cả khi HuntCompiler kịp xử lý.

**Phương án:**

| | Cách làm | Ưu | Nhược |
|---|---|---|---|
| **A (đề xuất)** | Nâng điểm "có trong KEV" từ 50 lên **70** | Một dòng code. Đủ ngưỡng 60 trong khoảng 7 ngày, khớp với cửa sổ quét KEV 7 ngày. Mức độ hiển thị: HIGH. | Mọi CVE KEV khớp tech stack đều được gửi. Đây đúng là ý đồ, nhưng số pack V2 sẽ tăng. |
| B | Giữ điểm; luật riêng: CVE KEV khớp tech stack thì gửi bất kể ngưỡng | Không đổi cách tính điểm | Thêm một ngoại lệ đặc biệt trong logic gửi |
| C | Thêm ngưỡng riêng cho từng loại tấn công vào manifest (trường mới, tuỳ chọn) | Linh hoạt nhất | Đổi hợp đồng manifest; tenant phải tự chỉnh |

**Xong khi:** có test cho thấy một CVE KEV chỉ có tín hiệu "có trong KEV" vẫn được gửi cho tenant khớp tech stack trong
7 ngày đầu; test âm cho thấy CVE không khớp tech stack thì không gửi. Ghi quyết định D-64.

## Q2. CI (kiểm tra tự động mỗi lần push)

**Vấn đề.** Không có CI, nên test chỉ chạy khi có người chạy tay.

**Đề xuất.** Thêm `.github/workflows/ci.yml`, chạy trên mỗi lần push và Pull Request:
1. PostgreSQL 16, đúng image đã ghim, làm database test dùng một lần.
2. Cài dependency từ file khoá có hash. Đồng thời khoá luôn `requirements-dev.txt` bằng hash: hiện file này trộn dòng có
   hash và dòng không hash, nên lệnh `pip install -r requirements-dev.txt` trong CLAUDE.md có thể hỏng trên Linux.
3. `ruff check`, `ruff format --check`, `pytest` (có cả test PostgreSQL), `alembic upgrade head && alembic check`.
4. Sinh lại contract rồi kiểm tra không có khác biệt. Bản sao schema trong Integration Kit phải trùng từng byte.
5. Các GitHub Action được ghim theo commit SHA, không theo tag, để tránh rủi ro chuỗi cung ứng.

**Cần bạn:** đồng ý dùng GitHub Actions (repo riêng tư có quota phút miễn phí hằng tháng); commit và push code thì CI mới
chạy. Tuỳ chọn: thêm `pip-audit` để quét lỗ hổng trong dependency.

**Xong khi:** CI xanh trên GitHub ở lần push đầu tiên.

## Q3. Thử phát hiện trên Windows thật

**Vấn đề.** Mọi bài test mới chỉ dùng sự kiện mẫu. Riêng rule V6 (cài gói độc) dựa vào chuỗi `npm install` /
`pip install` trong dòng lệnh. Trên Windows, npm thường chạy qua `npm.cmd` rồi `node.exe … npm-cli.js install …`, nên
chuỗi này có thể không xuất hiện trong log. Nếu vậy, rule sẽ bỏ sót.

**Đề xuất.**
1. Viết một **bộ thao tác vô hại** (PowerShell) tạo đúng loại sự kiện mà từng task tìm:
   - tra DNS tới dịch vụ tunnel và tới API Telegram;
   - một giá trị RunMRU có `cmd /c echo http-test`;
   - đăng nhập sai mật khẩu bằng một tài khoản thử;
   - tạo một dịch vụ driver trỏ tới file `.sys` không tồn tại (tạo sự kiện 7045, không nạp gì), rồi xoá;
   - một file exe vô hại được đổi tên theo một công cụ RMM;
   - `npm install` và `pip install` với **gói hợp lệ, phổ biến**. Không bao giờ cài gói độc thật; bước này chỉ để xem dòng
     lệnh trông thế nào.
2. Chạy trong **Windows Sandbox**: máy ảo dùng một lần có sẵn trên Windows 11 Pro, tự xoá sạch khi đóng. Trong đó cài
   Sysmon (của Microsoft Sysinternals), Node.js và Python.
3. Xuất sự kiện Sysmon, so với rule. Sửa những rule bỏ sót (dự kiến V6) và thêm test hồi quy.
4. Đưa bộ thao tác vô hại vào Integration Kit để khách tự kiểm tra pipeline của họ.

Bỏ qua V2 (đăng nhập từ IP thiết bị biên) và việc nạp driver thật: không mô phỏng an toàn được, nên vẫn dùng sự kiện mẫu.

**Cần bạn chọn:**
- (a) bật tính năng Windows Sandbox trên máy này (đổi cài đặt Windows, bạn tự bật), và cho phép tải Sysmon, Node.js,
  Python vào sandbox; hoặc
- (b) cung cấp một máy ảo Windows trong lab; hoặc
- (c) bỏ qua, chỉ ghi chú rủi ro.

**Xong khi:** có bảng "task → sự kiện thật → khớp hay không", và mọi rule sai đã được sửa, có test.

## Q4. Bổ sung lại dữ liệu GitHub cho CVE

**Vấn đề.** CVE được lưu một lần (chống trùng theo mã CVE). Nếu lần đầu GitHub lỗi hoặc thiếu token, CVE đó không bao giờ
có thông tin PoC/Nuclei, nên cũng không bao giờ được cộng 10 + 10 điểm.

**Đề xuất.** Job chạy hằng ngày:
- tìm các CVE trong cửa sổ KEV (7 ngày) có ghi chú "thiếu dữ liệu GitHub";
- thử lại khi đã có token;
- cập nhật dữ liệu và điểm của cụm;
- giới hạn số lần thử, và báo trạng thái trên trang sức khoẻ.

Pack chưa từng gửi vì thiếu điểm sẽ được gửi khi đủ điểm. Pack đã gửi không bị phát lại chỉ vì điểm đổi; đây là quy tắc
có sẵn.

**Xong khi:** test cho thấy một CVE lỡ dữ liệu GitHub được bổ sung ở lần chạy sau, điểm tăng, và pack được tạo khi vượt
ngưỡng. Test âm: không có token thì không gọi tìm code.

## Q5. Cảnh báo vận hành

**Vấn đề.** Collector hỏng thì chỉ thấy khi bạn gõ `/status` hoặc đọc digest buổi sáng.

**Đề xuất.** Một loại tin mới, tách khỏi tin tình báo: "⚠ Ops: URLScan lỗi 3 lần liên tiếp (HTTP 403)".
- Gửi khi một collector lỗi liên tiếp từ 3 lần, hoặc quá hạn chạy gấp đôi chu kỳ.
- Mỗi nguồn tối đa một tin mỗi 6 giờ, và có tin "đã hồi phục".
- Bật bằng `HC_TGBOT_OPS_ALERTS`, **mặc định tắt**.

**Cần bạn quyết:** mặc định đã chốt là "Telegram chỉ gửi digest". Tin vận hành không chứa tình báo, nhưng vẫn là tin gửi
ngoài digest, nên cần bạn đồng ý. Tôi đề xuất cho phép, mặc định tắt.

**Xong khi:** có test gửi đúng lúc, không gửi trùng, và có tin hồi phục; test âm: khi tắt thì không gửi gì.

## Q6. Chống giả IP

**Vấn đề.** API tin header `X-Forwarded-For` từ mọi nguồn (`--forwarded-allow-ips "*"`). Một tiến trình chạy trên chính
máy chủ có thể gọi thẳng cổng 8000, giả IP và né việc khoá IP.

**Đề xuất.** Tạo một mạng Docker riêng giữa Caddy và API, với dải địa chỉ cố định chỉnh được trong `.env`. Uvicorn chỉ tin
header đến từ dải này. Gọi thẳng cổng 8000 thì API dùng địa chỉ thật của kết nối. Phải kiểm tra uvicorn 0.54 có nhận dải
địa chỉ (CIDR) không; nếu không, dùng một IP cố định cho Caddy.

**Xong khi:** test: header giả từ ngoài dải bị bỏ qua, header từ Caddy được dùng. Chạy lại bài kiểm tra Caddy như ngày
09/11.

## Q7. Sao lưu ra ngoài máy chủ

**Vấn đề.** Bản sao lưu nằm trong volume trên cùng máy chủ. Mất máy hay hỏng ổ là mất cả hai.

**Đề xuất.** Thêm profile `offsite` dùng **restic**:
- bản sao lưu được mã hoá ngay trên máy, chỉ chép phần thay đổi;
- đẩy lên kho lưu trữ tương thích S3 (Backblaze B2, Wasabi, AWS S3, MinIO tự dựng...);
- giữ theo lịch: 14 bản ngày, 8 bản tuần, 6 bản tháng;
- mật khẩu mã hoá và key kho lưu trữ chỉ nằm trong `.env`.

**Cần bạn chọn:** nơi lưu, rồi tự tạo tài khoản và key. Hoặc tạm hoãn.

**Xong khi:** khôi phục thử từ kho bên ngoài vào một database rỗng thành công.

## Q8. Dung lượng Wazuh

**Vấn đề.** Pack cần Wazuh bật archives, tức lưu **mọi** sự kiện. Ổ đĩa phình rất nhanh, có thể khiến khách ngại dùng.

**Đề xuất.**
- Thêm vào hướng dẫn Wazuh một bộ lọc của Filebeat: chỉ giữ trong archives những sự kiện pack cần (Sysmon 1, 3, 6, 7,
  11, 13, 22; Security 4624/4625; System 7045), bỏ phần còn lại.
- Kèm bảng ước tính dung lượng tiết kiệm được.
- Thử thật trên Wazuh manager trong lab: một sự kiện cần giữ phải vào được archives, một sự kiện thừa phải bị bỏ.

**Cần bạn:** cho phép tải image Wazuh manager chính hãng (khoảng 1 GB; tôi sẽ báo con số chính xác trước khi tải), xoá
sạch sau khi thử. Hoặc chỉ viết hướng dẫn, không thử thật.

**Xong khi:** hướng dẫn có bộ lọc đã chạy thật, và mẫu kết quả trong `integration_kit/wazuh/SAMPLE_RUN.md`.

---

## Cách nghiệm thu chung

- Toàn bộ test qua, có cả PostgreSQL; `ruff` sạch; `alembic check` không lệch; contract được sinh lại nếu schema đổi.
- Mỗi hành vi mới có test, kể cả test âm.
- Quyết định mới ghi vào `DECISIONS.md` (dự kiến D-64 trở đi). Hai README, SPEC và CLAUDE.md được cập nhật.
- Báo trạng thái hai mức như trước: **Built** (code xong, test qua) và **Verified** (đã chạy thật).

## Câu hỏi cần bạn trả lời

| # | Câu hỏi | Đề xuất |
|---|---|---|
| 1 | Q1: chọn phương án A, B hay C? | A (điểm KEV = 70) |
| 2 | Q2: dùng GitHub Actions? Thêm `pip-audit`? | Có, có |
| 3 | Q3: môi trường thử là (a) Windows Sandbox, (b) máy ảo lab, hay (c) bỏ qua? | (a) |
| 4 | Q5: cho phép tin cảnh báo vận hành, mặc định tắt? | Có |
| 5 | Q7: nơi lưu bản sao lưu bên ngoài? | Bạn chọn; tạm hoãn cũng được |
| 6 | Q8: thử thật trên Wazuh manager, hay chỉ viết hướng dẫn? | Thử thật |

Trả lời "duyệt theo đề xuất" là tôi làm Đợt 1 ngay. Đợt 2 và 3 làm khi bạn chuẩn bị xong phần của mình.

---

## Kết quả (13/11/2026)

| Mục | Trạng thái | Ghi chú |
|---|---|---|
| Q1 | **Built** | Phương án A: "có trong KEV" = 70 (D-64). Test: đủ ngưỡng trong 7 ngày, hết sau 8 ngày; trên PostgreSQL chỉ tenant dùng FortiOS nhận gói, mức HIGH. Cụm tạo trước thay đổi giữ điểm cũ. |
| Q5 | **Built** | D-65. Mặc định tắt. Heartbeat có thêm bộ đếm lỗi liên tiếp. Test: không gửi khi tắt; gửi sau 3 lần lỗi; không lặp trong 6 giờ; có tin hồi phục; job "chưa cấu hình" không báo; nội dung được escape. Chưa gửi thử vào Telegram thật của bạn. |
| Q6 | **Built**, đã chạy thật trên Docker | D-66. Mạng `edge` nội bộ, Caddy có IP cố định 172.31.250.2, uvicorn chỉ tin IP đó. Chạy thật (13/11), API khởi động trước như bản thật: chỉ "Caddy" được tin; container khác trên `edge`, container trên `egress` và lệnh gọi thẳng qua cổng 8000 gửi IP giả đều bị ghi đúng địa chỉ thật. **Lần chạy này tìm ra lỗi:** API được cấp động đúng IP dành cho Caddy, nên Caddy không khởi động được. Đã sửa bằng vùng cấp động riêng (`HC_EDGE_IP_RANGE`). |
