"""
totp.py
========================================================
A from-scratch implementation of TOTP (Time-based One-Time
Password) -- the same algorithm used by Google Authenticator,
Microsoft Authenticator, Authy, etc.

We are NOT using a library like pyotp. We are implementing the
actual algorithm ourselves, based on two official specifications:

    RFC 4226 - HOTP (HMAC-based One-Time Password)
    RFC 6238 - TOTP (Time-based One-Time Password), which is
               just HOTP where the "counter" is derived from
               the current time instead of an incrementing number.

HOW IT WORKS (high level):
1. You and the server share a secret key (this is what gets
   shown to you as a QR code when you set up 2FA).
2. Both sides calculate a "counter" value from the current time.
3. Both sides run HMAC-SHA1(secret, counter) to get a hash.
4. Both sides "truncate" that hash down to a short 6-digit number
   using a specific extraction rule (defined in the RFC).
5. If your 6-digit number matches the server's 6-digit number,
   you're authenticated.

Because both sides calculate the same counter from time, neither
side has to send the counter over the network -- which is why this
works completely offline.
========================================================
""" 