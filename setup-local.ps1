param([string]$AdminUser = "admin", [Parameter(Mandatory=$true)][string]$AdminPassword)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
if (-not (Test-Path ".env")) {
    function New-RandomBase64([int]$Length) {
        $Bytes = New-Object byte[] $Length
        [Security.Cryptography.RandomNumberGenerator]::Fill($Bytes)
        return [Convert]::ToBase64String($Bytes)
    }
    $AppSecret = New-RandomBase64 48
    $Pepper = New-RandomBase64 48
    $DbPassword = (New-RandomBase64 24).Replace("/", "A").Replace("+", "B")
    @"
DATABASE_URL=postgresql+psycopg://autotool:$DbPassword@db:5432/autotool_license
POSTGRES_PASSWORD=$DbPassword
APP_SECRET=$AppSecret
LICENSE_KEY_PEPPER=$Pepper
SIGNING_PRIVATE_KEY_PATH=/app/secrets/ed25519-private.pem
ADMIN_TIMEZONE=Asia/Ho_Chi_Minh
LEASE_HOURS=24
MIN_CLIENT_VERSION=1.2.0
"@ | Set-Content -Encoding utf8 ".env"
}
New-Item -ItemType Directory -Force "secrets" | Out-Null
docker compose pull db
if ($LASTEXITCODE -ne 0) { throw "Không tải được PostgreSQL image. Kiểm tra mạng rồi chạy lại setup." }
docker compose build
if ($LASTEXITCODE -ne 0) { throw "Build LicenseServer API thất bại." }
docker compose up -d db
if ($LASTEXITCODE -ne 0) { throw "Không khởi động được PostgreSQL." }
docker compose run --rm api python scripts/bootstrap.py --username $AdminUser --password $AdminPassword
if ($LASTEXITCODE -ne 0) { throw "Không tạo được tài khoản admin." }
docker compose up -d
if ($LASTEXITCODE -ne 0) { throw "Không khởi động được LicenseServer." }
Write-Host "LicenseServer: http://127.0.0.1:9100/admin"
