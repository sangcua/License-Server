from __future__ import annotations

from pydantic import BaseModel, Field


class ActivateRequest(BaseModel):
    license_key: str = Field(min_length=20, max_length=200)
    installation_id: str = Field(min_length=16, max_length=80)
    app_version: str = Field(min_length=1, max_length=40)
    serials: list[str] = Field(default_factory=list, max_length=500)


class HeartbeatRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=200)
    installation_id: str = Field(min_length=16, max_length=80)
    app_version: str = Field(min_length=1, max_length=40)
    serials: list[str] = Field(default_factory=list, max_length=500)


class DeactivateRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=200)
    installation_id: str = Field(min_length=16, max_length=80)


class SignedLeaseResponse(BaseModel):
    payload: dict
    signature: str
    refresh_token: str | None = None

