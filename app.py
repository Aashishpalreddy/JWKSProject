from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import time
import uuid
import base64

# Initialize Flask app
app = Flask(__name__)

# Store keys in memory
keys = {}

def int_to_base64url(value, byte_size=None):
    """Convert an integer to base64url-encoded format."""
    if byte_size is None:
        byte_size = (value.bit_length() + 7) // 8
    
    value_bytes = value.to_bytes(byte_size, byteorder="big")
    return base64.urlsafe_b64encode(value_bytes).decode("ascii").rstrip("=")

def generate_key_pair():
    # Generate an RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get the public key from the private key
    public_key = private_key.public_key()
    
    # Generate a unique Key ID (kid)
    kid = str(uuid.uuid4())
    
    # Set expiry time (1 hour from now)
    expiry = int(time.time()) + 3600
    
    # Store the key pair and expiry in memory
    keys[kid] = {
        'private_key': private_key,
        'public_key': public_key,
        'expiry': expiry
    }
    
    return kid, private_key, public_key, expiry

# Endpoint to serve JWKS (JSON Web Key Set)
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    jwks_keys = []
    for kid, key_info in keys.items():
        # Only include unexpired keys
        if key_info['expiry'] > time.time():
            public_key = key_info['public_key']
            public_numbers = public_key.public_numbers()
            
            jwks_keys.append({
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": int_to_base64url(public_numbers.n),
                "e": int_to_base64url(public_numbers.e)
            })
            
    return jsonify(keys=jwks_keys)

# Endpoint to issue JWTs
@app.route('/auth', methods=['POST'])
def auth():
    # Check if the "expired" query parameter is present
    expired = request.args.get('expired', '').lower() == 'true'
    
    # Generate a new key pair
    kid, private_key, _, expiry = generate_key_pair()
    
    if expired:
        # Set expiry to 1 hour ago if "expired" is true
        expiry = int(time.time()) - 3600
        keys[kid]['expiry'] = expiry
        
    # Create a JWT payload
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": int(time.time()),  # Issued at
        "exp": expiry  # Expiry
    }
    
    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Sign the JWT with the private key
    token = jwt.encode(
        payload, 
        private_key_pem, 
        algorithm='RS256', 
        headers={'kid': kid}
    )
    
    return jsonify(token=token)

# Run the server
if __name__ == '__main__':
    app.run(port=8080)