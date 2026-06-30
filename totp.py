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


# TOTP - turning HOTP into a TIME-based code (RFC 6238)
def totp(secret_base32: str, for_time: int = None, time_step: int = 30, digits: int = 6) -> str:
    """
    Generate a TOTP code for the current moment in time.

    This is just HOTP, but instead of a counter that increases by 1
    each time, we calculate the counter from the current Unix time,
    divided into fixed-size "time steps" (usually 30 seconds).

    for_time  : Unix timestamp to generate the code for.
                Defaults to "right now". Letting this be passed in
                is what lets us test against the RFC's known vectors.
    time_step : how many seconds each code is valid for (30 is standard)
    """
    if for_time is None:
        for_time = int(time.time())

    # This is the only difference from HOTP: the counter is just
    # "how many 30-second windows have passed since 1970".
    counter = int(for_time // time_step)
    return hotp(secret_base32, counter, digits)


# Verifying a code (with a small tolerance window)
def verify_totp(secret_base32: str, code_to_check: str, time_step: int = 30, digits: int = 6,
                window: int = 1) -> bool:
    """
    Check whether `code_to_check` is valid right now.

    We check a small "window" of time steps before/after the
    current one too. This matters in real life because:
      - there can be a tiny clock drift between your phone and
        the server
      - you might type the code just as it's about to expire

    window=1 means "check the previous step, current step, and
    next step" (i.e. allow +/- 30 seconds of drift).
    """
    current_time = int(time.time())
    for error_margin in range(-window, window + 1):
        time_to_check = current_time + (error_margin * time_step)
        expected_code = totp(secret_base32, for_time=time_to_check, 
                             time_step=time_step, digits=digits)
        
        if hmac.compare_digest(expected_code, code_to_check):
            return True
    return False
    

# Self-test against the OFFICIAL RFC 6238 test vectors.
# RFC 6238 Appendix B gives a known secret and known correct outputs
# for specific timestamps. Able to verify implementation is correct, 
# not just plausible.
def run_rfc6238_self_test():
    print("=" * 60)
    print("Running self-test against official RFC 6238 test vouchers")
    print("=" * 60)

    # The RFC's test secret is the ASCII string "12345678901234567890"
    # We need it Base32-encoded since our hotp() function expects that.
    test_secret_ascii = b"12345678901234567890"
    test_secret_base32 = base64.b32encode(test_secret_ascii).decode("utf-8")

    # Each tuple is: (unix_time, expected_8_digit_code)
    # Note: the RFC's test vectors use 8-digit codes, not the usual 6.
    test_vectors = [(59, "94287082"),
                    (1111111109, "07081804"),
                    (1111111111, "14050471"),
                    (1234567890, "89005924"),
                    (2000000000, "69279037"),
                    ]
    
    all_passed = True
    for test_time, expected_code in test_vectors:
        actual_code = totp(test_secret_base32,for_time=test_time, digits=8)
        passed = (actual_code == expected_code)
        all_passed = all_passed and passed
        status = "PASS" if passed else "FAIL"
        print(f"time={test_time:<12} expected={expected_code}"
              f"actual={actual_code} [{status}]")
        
        print("-" * 60)
        if all_passed:
            print("All test vectors passed! The algorithm is implemented correctly.")
        else:
            print("Some test vectors failed -- check the implementation.")
        print("=" * 60)
        return all_passed


# Simulate setting up 2FA and logging in.
def demo():
    print("\nDEMO: Simulating 2FA setup and login\n")

    secret = generate_secret()
    print(f"1. Generated secret key (you'd scan this as a QR code): {secret}")

    code = totp(secret)
    print(f"2. Your current 6-digit authenticator code is: {code}")
    print("   (this code will change every 30 seconds)")

    is_valid = verify_totp(secret, code)
    print(f"3. Verifying that code against the server logic... valid = {is_valid}")

    is_valid_wrong = verify_totp(secret, "000000")
    print(f"4. Verifying a made-up wrong code ('000000')... valid = {is_valid_wrong}")


if __name__ == "__main__":
    run_rfc6238_self_test()
    demo()