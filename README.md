# AutoTool LicenseServer

LicenseServer là dịch vụ độc lập dùng để cấp quyền AutoTool theo hardware serial Android (`ro.serialno`). Dự án cũ `Server/` không được sử dụng hay thay đổi.

## Chạy local bằng Docker

Yêu cầu Docker Desktop đang chạy. Mở PowerShell tại thư mục này:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\setup-local.ps1 -AdminUser admin -AdminPassword "MatKhauRatManh-123"
```

Sau khi hoàn tất:

- Web Admin: `http://127.0.0.1:9100/admin`
- Health check: `http://127.0.0.1:9100/health`
- PostgreSQL không được publish ra máy ngoài; API chỉ bind loopback.
- Private key, pepper và database password nằm trong `.env`/`secrets/`, đều đã được ignore.

Source AutoTool tự tìm public key tại `LicenseServer/secrets/ed25519-public.pem` và mặc định gọi `http://127.0.0.1:9100`. Có thể tạo `AutoTool/license.local.json` theo mẫu:

```json
{
  "server_url": "http://127.0.0.1:9100",
  "public_key_path": "../LicenseServer/secrets/ed25519-public.pem"
}
```

## Luồng thử end-to-end

1. Mở Admin và dùng form **Tạo khách hàng + License**, nhập số ngày và ít nhất một serial.
2. Lấy hardware serial trong màn hình kích hoạt AutoTool, paste vào form này.
3. Sao chép key ở khung màu xanh; khách hàng và license được tạo chung trong một transaction, key đầy đủ chỉ hiện một lần.
4. Nhập key vào AutoTool khi đang kết nối ít nhất một serial đã cấp.
5. Kiểm tra cột License: máy được cấp có thể tích chọn, máy lạ chỉ hiển thị.
6. Thêm máy sau này bằng cùng key; mỗi lô mới có ngày bắt đầu và hết hạn riêng.
7. Gia hạn bằng cách chọn một hoặc nhiều serial. Máy còn hạn được cộng nối tiếp, máy hết hạn bắt đầu kỳ mới từ lúc gia hạn.
8. Thử Khóa/Mở khóa; AutoTool online nhận thay đổi ở heartbeat kế tiếp (25–35 giây) và dừng/mở lại an toàn.
9. Dùng Rotate key khi cần vô hiệu hóa vĩnh viễn key và toàn bộ phiên kích hoạt cũ.

Mỗi khách hàng chỉ có một license. Số máy bằng đúng số serial đã cấp, không có giới hạn khai báo trước. Thêm serial hoặc gia hạn từng máy đều giữ nguyên key và phiên AutoTool hiện tại.

Muốn tạo dữ liệu demo (không dùng cho production):

```powershell
docker compose run --rm api python scripts/seed_demo.py
```

## Chạy không dùng Docker để phát triển

```powershell
python -m pip install -r requirements.txt
$env:DATABASE_URL = "sqlite+pysqlite:///./license_server.db"
alembic upgrade head
python scripts/bootstrap.py --username admin --password "MatKhauRatManh-123"
uvicorn app.main:app --host 127.0.0.1 --port 9100 --reload
```

## Production sau này

Không public cấu hình local trực tiếp lên Internet. Giai đoạn production cần PostgreSQL backup, VPS/domain, Caddy hoặc reverse proxy TLS, secret mới, `https_only` cho cookie và build AutoTool kèm đúng `license_public.pem` + URL HTTPS. Rotate key thu hồi refresh token ngay; signed lease offline cũ chỉ còn hiệu lực đến hard-expiry tối đa 24 giờ. Khóa là thao tác có thể mở lại và không xóa refresh token.
