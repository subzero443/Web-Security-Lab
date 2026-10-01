import pytest

from app import create_app


@pytest.fixture()
def client(tmp_path):
    app = create_app(str(tmp_path / "test.sqlite3"))
    app.config.update(TESTING=True)
    return app.test_client()


def test_sql_search_uses_safe_parameterized_query(client):
    response = client.get("/api/secure/sql-search?q=%27%20OR%201%3D1%20--")
    assert response.status_code == 200
    assert response.json["results"] == []
    assert "query" not in response.json


def test_secure_document_requires_login_and_enforces_owner(client):
    assert client.get("/api/secure/documents/2").status_code == 401
    login = client.post("/api/secure/login", json={"username": "alice", "password": "secure-demo-pass"})
    assert login.status_code == 200
    assert client.get("/api/secure/documents/2").status_code == 404
    assert client.get("/api/secure/documents/1").json["title"] == "Alice's field notes"


def test_secure_file_route_rejects_traversal(client):
    assert client.get("/api/secure/files?path=../private/lesson.txt").status_code == 404
    assert client.get("/api/vulnerable/files?path=../private/lesson.txt").json["content"].startswith("Synthetic private fixture")


def test_secure_xss_returns_text_and_security_headers(client):
    payload = "<script>alert(1)</script>"
    response = client.get("/api/secure/xss", query_string={"text": payload})
    assert response.json["text"] == payload
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_secure_configuration_hides_operational_details(client):
    response = client.get("/api/secure/config")
    assert response.json == {"debug": False, "details": "Operational details are not exposed."}
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_secure_login_throttles_repeated_failures(client):
    for _ in range(5):
        assert client.post("/api/secure/login", json={"username": "alice", "password": "wrong"}).status_code == 401
    response = client.post("/api/secure/login", json={"username": "alice", "password": "wrong"})
    assert response.status_code == 429
