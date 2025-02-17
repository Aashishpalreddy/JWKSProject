from fastapi.testclient import TestClient
from server import app

client = TestClient(app)

def test_jwks():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert "keys" in response.json()

def test_auth():
    response = client.post("/auth")
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_expired_auth():
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    assert "access_token" in response.json()
