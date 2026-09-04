from __future__ import annotations

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .admin import make_admin_router
from .api import make_api_router
from .config import get_settings
from .security import load_or_create_signing_key
from .service import LicenseService


settings = get_settings()
signing_key = load_or_create_signing_key(settings.signing_private_key_path)
service = LicenseService(settings, signing_key)

app = FastAPI(title="AutoTool LicenseServer", version="1.1.0")
app.add_middleware(SessionMiddleware, secret_key=settings.app_secret, same_site="strict", https_only=False)
app.include_router(make_api_router(service))
app.include_router(make_admin_router(settings))


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "AutoTool LicenseServer"}
