import jwt
import time
import json
import base64
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Store keys in-memory
keys = {}

def int_to_base64url(value, byte_size=None):
    """Convert an integer to base64url-encoded format."""
    if byte_size is None:
        byte_size = (value.bit_length() + 7) // 8
    
    value_bytes = value.to_bytes(byte_size, byteorder="big")
    return base64.urlsafe_b64encode(value_bytes).decode("ascii").rstrip("=")

def generate_rsa_key():
    """Generate an RSA key pair and return public key in JWK format"""
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate a unique Key ID (kid)
    kid = str(uuid4())
    
    # Set expiry to 1 hour from now (default)
    expiry = int(time.time() + 3600)

    # Get public key numbers
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    # Create JWK from public key components
    jwk = {
        "kid": kid,
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64url(public_numbers.n),
        "e": int_to_base64url(public_numbers.e),
        "exp": expiry
    }

    # Store both keys
    keys[kid] = {
        "private": private_key,
        "public": jwk
    }
    
    return kid

# Generate an initial key
generate_rsa_key()