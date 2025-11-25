from __future__ import annotations

import time
import uuid

import jwt
from fastapi.testclient import TestClient

from app.config import get_settings

settings = get_settings()


def _register_and_login(client: TestClient, username: str | None = None) -> str:
    username = username or f"user_{uuid.uuid4().hex[:8]}"
    password = "StrongPass123!"
    res = client.post("/auth/register", json={"username": username, "password": password})
    assert res.status_code == 201, res.text
    res = client.post("/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_expired_token_is_rejected(client: TestClient):
    username = f"user_{uuid.uuid4().hex[:8]}"
    _register_and_login(client, username)

    expired_token = jwt.encode(
        {"sub": username, "exp": int(time.time()) - 60},
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    res = client.get("/api/posts", headers=_auth(expired_token))
    assert res.status_code == 401
    assert "Invalid token" in res.json()["detail"]


def test_invalid_signature_is_rejected(client: TestClient):
    username = f"user_{uuid.uuid4().hex[:8]}"
    _register_and_login(client, username)

    forged_token = jwt.encode(
        {"sub": username, "exp": int(time.time()) + 3600},
        "wrong-secret",
        algorithm=settings.jwt_algorithm,
    )
    res = client.get("/api/posts", headers=_auth(forged_token))
    assert res.status_code == 401
    assert "Invalid token" in res.json()["detail"]


def test_malformed_tokens_are_rejected(client: TestClient):
    malformed = [
        "not.a.jwt",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
        "",
        "Bearer abc.def",
    ]
    for token in malformed:
        res = client.get("/api/posts", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 401


def test_missing_sub_claim_is_rejected(client: TestClient):
    token = jwt.encode(
        {"exp": int(time.time()) + 120},
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    res = client.get("/api/posts", headers=_auth(token))
    assert res.status_code == 401
    assert "Invalid token" in res.json()["detail"]


def test_nonexistent_user_in_token(client: TestClient):
    token = jwt.encode(
        {"sub": "ghost", "exp": int(time.time()) + 120},
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    res = client.get("/api/posts", headers=_auth(token))
    assert res.status_code == 401
    assert "User not found" in res.json()["detail"]
