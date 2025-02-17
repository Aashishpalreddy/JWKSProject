from fastapi import FastAPI, Query
from cryptography.hazmat.primitives import serialization
import jwt
import time
from keys import keys, generate_rsa_key

app = FastAPI()

@app.get("/.well-known/jwks.json")
def get_jwks():
    """Return public keys in JWKS format, excluding expired ones"""
    valid_keys = [key["public"] for key in keys.values() if key["public"]["exp"] > time.time()]
    return {"keys": valid_keys}

# @app.post("/auth")
# def generate_jwt(expired: bool = Query(False)):
    # """Generate JWT with an active key or an expired key if requested"""
    # key_id = next(iter(keys))  # Get first valid key
    # key_data = keys[key_id]

    # exp_time = time.time() - 3600 if expired else time.time() + 3600  # Set expiration
    # payload = {"sub": "fake_user", "exp": exp_time}

    # token = jwt.encode(payload, key_data["private"].private_bytes(
        # encoding=serialization.Encoding.PEM,
        # format=serialization.PrivateFormat.PKCS8,
        # encryption_algorithm=serialization.NoEncryption(),
    # ), algorithm="RS256", headers={"kid": key_id})

    # return {"access_token": token}
    
@app.post("/auth")
def generate_jwt(expired: bool = Query(False)):
    """Generate JWT with an active key or an expired key if requested"""
    if not keys:
        return {"error": "No keys available"}, 500
    
    key_id = next(iter(keys))  # Get first valid key
    key_data = keys[key_id]

    exp_time = time.time() - 3600 if expired else time.time() + 3600  # Set expiration
    payload = {"sub": "fake_user", "exp": exp_time}

    token = jwt.encode(payload, key_data["private"].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ), algorithm="RS256", headers={"kid": key_id})

    return {"access_token": token}