from fastapi.testclient import TestClient
from server import app

client = TestClient(app)

def test_jwks():
"""  
    Test the JWKS (JSON Web Key Set) endpoint.  
    Ensures the endpoint returns a 200 status and contains a 'keys' field in the JSON response.  
"""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert "keys" in response.json()

def test_auth():
"""  
    Test the authentication endpoint.  
    Ensures the endpoint returns a 200 status and includes an 'access_token' in the response.  
"""
    response = client.post("/auth")
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_expired_auth():
"""  
    Test the authentication endpoint with an expired token request.  
    Ensures the endpoint still returns a valid response with an 'access_token'.  
"""
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    assert "access_token" in response.json()
