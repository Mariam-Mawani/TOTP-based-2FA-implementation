import os
import base64
import struct

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


# HOTP - Core algorithm(RFC 4226)
def hotp(secret_base32: str, counter: int, digits: int =6) -> str:
    """
    Generate an HOTP code from a secret and a counter value.

    secret_base32 : the shared secret, Base32-encoded (a string)
    counter       : a number that increases over time (for TOTP,
                    this comes from the current time -- see totp())
    digits        : how many digits the final code should have
    """
    # Decode the secret from Base32 back into raw bytes
    missing_padding = len(secret_base32) % 8
    if missing_padding != 0:
        secret_base32 += "=" * (8 - missing_padding)
    secret_bytes = base64.b32decode(secret_base32, casefold=True)

    # Convert the counter into 8 bytes(big-endian)
    counter_bytes = struct.pack(">Q", counter)

    # Computes HMAC-SHA1(secret, counter)