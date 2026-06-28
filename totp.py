import os
import base64
import struct
import hmac
import hashlib
import time

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

    # Computes HMAC-SHA1(secret, counter) 20 raw bytes(SHA1 always produces 20 bytes)
    hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation (Clever bit from the RFC) can't show all 20 bytes
    # to user, so have to squeeze down into a short number. 
    # The RFC's rule is:
    # Take the last byte of the hash, and look at only its last
    # 4 bits (a "nibble"). That gives us a number from 0-15, which
    # we use as a starting offset into the 20-byte hash.
    offset = hmac_hash[-1] & 0x0F

    # Starting at that offset, grab 4 bytes from the hash.
    # We mask the very first bit of those 4 bytes off (& 0x7F on the
    # first byte) so the number is always positive when we treat it
    # as a signed 32-bit integer.
    truncated_bytes = hmac_hash[offset:offset + 4]
    code_int = struct.unpack(">I", truncated_bytes)[0] & 0x7FFFFFFF

    # Keep only the last "digits" digits.
    code = code_int % (10 ** digits)

    # Pad with leading zeros if needed(e.g. 42 -> "000042")
    return str(code).zfill(digits)