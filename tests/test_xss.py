from __future__ import annotations

import uuid

from fastapi.testclient import TestClient


def _register_and_login(client: TestClient) -> str:
    username = f"user_{uuid.uuid4().hex[:8]}"
    password = "StrongPass123!"
    res = client.post("/auth/register", json={"username": username, "password": password})
    assert res.status_code == 201, res.text
    res = client.post("/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_title_payloads_are_sanitized(client: TestClient):
    token = _register_and_login(client)
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('x')>",
        "<svg onload=alert(1)>",
        "<b>bold</b> text",
    ]
    for payload in payloads:
        res = client.post(
            "/api/posts",
            headers=_auth(token),
            json={"title": payload, "content": "safe"},
        )
        if res.status_code == 201:
            title = res.json()["title"].lower()
            assert "<script" not in title
            assert "<img" not in title
            assert "<svg" not in title
        else:
            assert res.status_code == 422
            assert "Title" in res.json()["detail"]


def test_content_payloads_are_sanitized(client: TestClient):
    token = _register_and_login(client)
    payloads = [
        "<script>alert('XSS')</script>",
        "Normal <iframe src=javascript:alert('x')>",
        "<style>body{background:red}</style>",
        "<b>bold</b>",
    ]
    for payload in payloads:
        res = client.post(
            "/api/posts",
            headers=_auth(token),
            json={"title": "safe", "content": payload},
        )
        if res.status_code == 201:
            body = res.json()["content"].lower()
            assert "<script" not in body
            assert "<iframe" not in body
            assert "<style" not in body
            assert "onerror" not in body
        else:
            assert res.status_code == 422
            assert "Content" in res.json()["detail"]


def test_listing_only_returns_sanitized_content(client: TestClient):
    token = _register_and_login(client)
    client.post(
        "/api/posts",
        headers=_auth(token),
        json={"title": "Hello <b>World</b>", "content": "Body <script>alert(1)</script>"},
    )
    res = client.get("/api/posts", headers=_auth(token))
    assert res.status_code == 200
    for post in res.json():
        sanitized_title = post["title"].lower()
        sanitized_content = post["content"].lower()
        assert "<script" not in sanitized_title
        assert "<script" not in sanitized_content
        assert "onerror" not in sanitized_title
        assert "onerror" not in sanitized_content
