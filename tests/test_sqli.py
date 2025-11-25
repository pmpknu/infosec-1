from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import models


def _register_and_login(client: TestClient) -> tuple[str, str, str]:
    username = f"user_{uuid.uuid4().hex[:8]}"
    password = "StrongPass123!"
    res = client.post("/auth/register", json={"username": username, "password": password})
    assert res.status_code == 201
    res = client.post("/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200
    return res.json()["access_token"], username, password


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _table_exists(session: Session, table: str) -> bool:
    result = session.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name=:table"),
        {"table": table},
    )
    return result.fetchone() is not None


def test_post_payloads_do_not_break_schema(client: TestClient, db_session: Session):
    token, _, _ = _register_and_login(client)
    payloads = [
        "'; DROP TABLE posts; --",
        "1' OR '1'='1",
        "admin'; UPDATE users SET password_hash='pw'; --",
    ]

    db_session.expire_all()
    initial_user_count = db_session.query(models.User).count()
    initial_post_count = db_session.query(models.Post).count()

    for idx, payload in enumerate(payloads):
        res = client.post(
            "/api/posts",
            headers=_auth(token),
            json={"title": payload, "content": f"Body {idx}"},
        )
        assert res.status_code == 201
        db_session.expire_all()
        assert _table_exists(db_session, "users")
        assert _table_exists(db_session, "posts")

    db_session.expire_all()
    assert db_session.query(models.User).count() == initial_user_count
    assert db_session.query(models.Post).count() == initial_post_count + len(payloads)


def test_login_injection_attempts_fail(client: TestClient, db_session: Session):
    token, username, password = _register_and_login(client)
    bad_inputs = [
        "' OR '1'='1",
        "admin'--",
        "test'; DROP TABLE users; --",
        f"{username}' OR '1'='1",
    ]

    for payload in bad_inputs:
        res = client.post("/auth/login", json={"username": payload, "password": password})
        assert res.status_code == 401
        res = client.post("/auth/login", json={"username": username, "password": payload})
        assert res.status_code == 401

    db_session.expire_all()
    assert _table_exists(db_session, "users")
    assert _table_exists(db_session, "posts")
    assert db_session.query(models.User).filter(models.User.username == username).count() == 1
    assert token  # ensure fixture used so flake8 doesn't warn
