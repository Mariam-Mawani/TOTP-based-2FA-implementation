import os
import base64

# Generate secret key.
def generate_secret(num_bytes: int = 10) -> str:
    """
    Generate a random secret key and return it Base32-encoded
    (this is the standard way TOTP secrets are represented/shared).
    10 raw bytes -> 16 Base32 characters, which matches what most
    real authenticator apps use.
    """
    random_bytes = os.urandom(num_bytes)
    base32_secret = base64.b32encode(random_bytes).decode("utf-8")
    return base32_secret
