# TOTP Authenticator — Notes

Personal notes on building a standards-compliant TOTP authenticator app.

---

## 1. Overview

TOTP (Time-based One-Time Password) is defined in **RFC 6238** and builds on **HOTP (RFC 4226)**. A TOTP authenticator stores a shared secret per account, computes a 6–8 digit code every 30 (or 60) seconds, works offline with no network required, and interoperates with any service that supports standard TOTP.

---

## 2. Formula

TOTP value (K) = HOTP value (K, CT)

Where:

| Symbol | Meaning |
|--------|---------|
| **K** | Shared secret key |
| **CT** | Count of the number of durations TX between T0 and T |
| **T** | Current time in seconds since a particular epoch |
| **T0** | The epoch specified in seconds since the Unix epoch (e.g., if using Unix time, then T0 is 0) |
| **TX** | The length of one-time duration (e.g., 30 seconds) |

Counter calculation: `CT = floor((T - T0) / TX)`

With Unix time as the epoch (T0 = 0): `CT = floor(T / TX)`

Example: given T = 1730000000, T0 = 0, TX = 30, then CT = floor((1730000000 - 0) / 30) = 57666666.

---

## 3. HOTP (RFC 4226)

HOTP is counter-based: `HOTP(K, C) = Truncate(HMAC-HASH(K, C))`

Steps:

1. Compute HMAC-HASH(K, C) where C is an 8-byte big-endian counter.
2. Take the last byte's low 4 bits as offset.
3. Take 4 bytes starting at offset.
4. Mask the top bit (keep 31 bits).
5. Modulo 10^digits.
