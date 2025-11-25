from __future__ import annotations

import uuid

from fastapi.testclient import TestClient


def _register_and_login(client: TestClient) -> tuple[str, str]:
    username = f"user_{uuid.uuid4().hex[:8]}"
    password = "StrongPass123!"

    response = client.post("/auth/register", json={"username": username, "password": password})
    assert response.status_code == 201, response.text

    token_resp = client.post("/auth/login", json={"username": username, "password": password})
    assert token_resp.status_code == 200, token_resp.text
    token = token_resp.json()["access_token"]
    return token, username


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_posts_crud_and_authentication(client: TestClient):
    token, _ = _register_and_login(client)

    create = client.post(
        "/api/posts",
        headers=_auth(token),
        json={"title": "Hello <b>World</b>", "content": "<script>alert(1)</script> Safe"},
    )
    assert create.status_code == 201, create.text
    post = create.json()
    assert "<script" not in post["content"].lower()
    assert "<script" not in post["title"].lower()

    listing = client.get("/api/posts", headers=_auth(token))
    assert listing.status_code == 200
    data = listing.json()
    assert isinstance(data, list)
    assert any(item["id"] == post["id"] for item in data)

    unauth_get = client.get("/api/posts")
    assert unauth_get.status_code == 401


def test_cannot_create_or_read_posts_without_auth(client: TestClient):
    create = client.post(
        "/api/posts",
        json={"title": "Unauthorized", "content": "Should fail"},
    )
    assert create.status_code == 401

    listing = client.get("/api/posts")
    assert listing.status_code == 401


def test_login_rejects_wrong_password(client: TestClient):
    _, username = _register_and_login(client)
    bad_login = client.post("/auth/login", json={"username": username, "password": "wrong"})
    assert bad_login.status_code == 401
    assert "Invalid credentials" in bad_login.json()["detail"]
