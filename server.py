from fastapi import FastAPI, Query
from cryptography.hazmat.primitives import serialization
import jwt
import time
from keys import keys, generate_rsa_key

app = FastAPI()

@app.get("/.well-known/jwks.json")
def get_jwks():
    """Return public keys in JWKS format, excluding expired ones"""
    current_time = time.time()
    valid_keys = [key["public"] for kid, key in keys.items() if key["public"]["exp"] > current_time]
    return {"keys": valid_keys}

@app.api_route("/auth", methods=["GET", "POST"])
def generate_jwt(expired: bool = Query(False)):
    """Generate JWT with an active key or an expired key if requested"""
    # Generate a new key
    key_id = generate_rsa_key()
    key_data = keys[key_id]
    
    # Set expiry time
    current_time = int(time.time())
    if expired:
        # If expired=true, set the key expiration to the past
        # This ensures the key won't appear in JWKS
        exp_time = current_time - 3600  # 1 hour ago
        key_data["public"]["exp"] = exp_time
    else:
        exp_time = current_time + 3600  # 1 hour in future
        
    # Create payload
    payload = {
        "sub": "fake_user", 
        "iat": current_time,
        "exp": exp_time
    }

    # Serialize private key to PEM format
    private_key_pem = key_data["private"].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Create JWT
    token = jwt.encode(
        payload, 
        private_key_pem, 
        algorithm="RS256",
        headers={"kid": key_id}
    )

    return {"token": token}