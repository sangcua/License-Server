from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
import secrets

from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except Exception:
        return False


def canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def token_fingerprint(token: str, pepper: str) -> str:
    return hmac.new(pepper.encode("utf-8"), token.strip().encode("utf-8"), hashlib.sha256).hexdigest()


def generate_license_key() -> str:
    raw = base64.b32encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    return "AT-" + "-".join(raw[index:index + 5] for index in range(0, len(raw), 5))


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def load_or_create_signing_key(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key


def public_key_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def sign_payload(private_key: Ed25519PrivateKey, payload: dict) -> str:
    return b64url(private_key.sign(canonical_json(payload)))

