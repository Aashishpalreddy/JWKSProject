import jwt
import time
import json
import base64
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Store keys in-memory
keys = {}

def generate_rsa_key():
    """Generate an RSA key pair and return public key JWK format"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = str(uuid4())
    expiry = time.time() + 3600  # Key expires in 1 hour

    public_key = private_key.public_key()
    
    public_numbers = public_key.public_numbers()
    n = base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, "big")).decode().rstrip("=")
    e = base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, "big")).decode().rstrip("=")

    jwk = {
        "kid": kid,
        "kty": "RSA",
        "alg": "RS256",
        "n": n,
        "e": e,
        "exp": expiry
    }

    keys[kid] = {"private": private_key, "public": jwk}
    return kid

# Generate an initial key
generate_rsa_key()
