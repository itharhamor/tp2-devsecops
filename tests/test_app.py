import pytest

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_greet(client):
    resp = client.get("/greet?name=Alice")
    assert resp.status_code == 200
    assert resp.get_json()["message"].strip() == "Bonjour Alice"


def test_user_found(client):
    resp = client.get("/user?name=alice")
    assert resp.status_code == 200
    assert resp.get_json()["role"] == "admin"


def test_user_not_found(client):
    resp = client.get("/user?name=inconnu")
    assert resp.status_code == 404


def test_security_headers(client):
    resp = client.get("/")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
