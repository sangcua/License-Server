from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .database import get_db
from .rate_limit import MemoryRateLimiter
from .schemas import ActivateRequest, DeactivateRequest, HeartbeatRequest, SignedLeaseResponse
from .service import LicenseService, LicenseServiceError


def make_api_router(service: LicenseService) -> APIRouter:
    router = APIRouter(prefix="/api/v1/license", tags=["license"])
    limiter = MemoryRateLimiter()

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def translate(call):
        try:
            return call()
        except LicenseServiceError as exc:
            raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc

    @router.post("/activate", response_model=SignedLeaseResponse)
    def activate(body: ActivateRequest, request: Request, db: Session = Depends(get_db)):
        ip = client_ip(request)
        if not limiter.allow(f"activate:{ip}", 5):
            raise HTTPException(429, detail={"code": "rate_limited", "message": "Quá nhiều lần kích hoạt; hãy thử lại sau"})
        return translate(lambda: service.activate(db, key=body.license_key, installation_id=body.installation_id, app_version=body.app_version, serials=body.serials, ip_address=ip))

    @router.post("/heartbeat", response_model=SignedLeaseResponse)
    def heartbeat(body: HeartbeatRequest, request: Request, db: Session = Depends(get_db)):
        ip = client_ip(request)
        token_hint = body.refresh_token[-12:]
        if not limiter.allow(f"heartbeat:{token_hint}", 30):
            raise HTTPException(429, detail={"code": "rate_limited", "message": "Heartbeat quá nhanh"})
        return translate(lambda: service.heartbeat(db, refresh_token=body.refresh_token, installation_id=body.installation_id, app_version=body.app_version, serials=body.serials, ip_address=ip))

    @router.post("/deactivate")
    def deactivate(body: DeactivateRequest, db: Session = Depends(get_db)):
        translate(lambda: service.deactivate(db, refresh_token=body.refresh_token, installation_id=body.installation_id))
        return {"ok": True}

    return router

