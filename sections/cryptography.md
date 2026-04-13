# Cryptography - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#cryptography)

> **Prerequisites:** Basic math concepts  
> **Difficulty:** Intermediate to Advanced

---

## Table of Contents

1. [Encryption vs Encoding vs Hashing vs Obfuscation vs Signing](#1-encryption-vs-encoding-vs-hashing-vs-obfuscation-vs-signing)
2. [Encryption: Asymmetric vs Symmetric](#2-encryption-asymmetric-vs-symmetric)
3. [Encoding: URL, Base64, ASCII](#3-encoding-url-base64-ascii)
4. [Hashing: MD5, SHA1, SHA256](#4-hashing-md5-sha1-sha256)
5. [Obfuscation](#5-obfuscation)
6. [Digital Signing](#6-digital-signing)
7. [Attack Models](#7-attack-models)
8. [PKI and Key Exchange](#8-pki-and-key-exchange)
9. [Forward Secrecy](#9-forward-secrecy)
10. [Ciphers: Block vs Stream](#10-ciphers-block-vs-stream)
11. [Integrity Primitives: Hash Functions, MACs, HMAC](#11-integrity-primitives-hash-functions-macs-hmac)
12. [Entropy and Random Number Generation](#12-entropy-and-random-number-generation)

---

## 1. Encryption vs Encoding vs Hashing vs Obfuscation vs Signing

### Explanation

These five concepts are frequently conflated, but they serve fundamentally different purposes. Understanding the distinctions is one of the most important foundations in security engineering.

| Property | Encryption | Encoding | Hashing | Obfuscation | Signing |
|---|---|---|---|---|---|
| **Purpose** | Confidentiality | Data representation | Integrity / fingerprinting | Hide intent | Authenticity + Integrity |
| **Reversible?** | Yes (with key) | Yes (no key needed) | No (one-way) | Yes (with effort) | Verification only |
| **Key required?** | Yes | No | No | No | Yes (private to sign, public to verify) |
| **Security goal** | Only authorized parties read data | Transport data safely in constrained formats | Detect tampering, store passwords | Slow down reverse engineering | Prove origin, detect tampering |

### Common Mistakes

- **Using encoding for security.** Base64 is NOT encryption. Putting credentials in Base64 provides zero protection.
- **Using hashing when you need encryption.** Hashed data cannot be recovered; if you need the original data back, use encryption.
- **Using encryption when you need signing.** Encryption hides data but does not prove who sent it.
- **Using MD5 or SHA1 for security-critical hashing.** Both have known collision attacks.

### Interview Tip

> When asked "what is the difference between encryption and hashing?", lead with the reversibility distinction: encryption is a two-way function (decrypt with a key), hashing is one-way (no key, no reversal). Then explain the different security goals: confidentiality vs integrity.

---

## 2. Encryption: Asymmetric vs Symmetric

### Explanation

**Symmetric encryption** uses one shared secret key for both encryption and decryption. It is fast and suitable for bulk data. The challenge is key distribution -- both parties must securely share the key beforehand.

**Asymmetric encryption** uses a key pair: a public key (shared openly) and a private key (kept secret). Anyone can encrypt with the public key, but only the private key holder can decrypt. It solves the key distribution problem but is orders of magnitude slower than symmetric encryption.

In practice, the two are combined: asymmetric encryption establishes a shared session key, which is then used for fast symmetric encryption (this is how TLS works).

### Code Example

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import os

# === Symmetric: AES-256-GCM ===
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)  # 96-bit nonce for GCM
ciphertext = aesgcm.encrypt(nonce, b"Sensitive data", b"aad-header")
recovered = aesgcm.decrypt(nonce, ciphertext, b"aad-header")

# === Asymmetric: RSA-OAEP ===
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
public_key = private_key.public_key()
ciphertext = public_key.encrypt(
    b"Secret message",
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
)
decrypted = private_key.decrypt(
    ciphertext,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
)
```

### Common Mistakes

- **Using RSA to encrypt bulk data directly.** RSA can only encrypt data smaller than the key size minus padding. Use hybrid encryption.
- **Reusing nonces with AES-GCM.** A single nonce reuse completely breaks GCM's authentication and leaks plaintext XOR. This destroyed the PS3 ECDSA implementation.
- **Key sizes too small.** RSA-1024 is considered broken. Use RSA-2048 minimum (prefer 4096). For AES, use 256-bit keys.
- **Using ECB mode.** Identical plaintext blocks produce identical ciphertext blocks, leaking patterns (the famous "ECB penguin").
- **Using PKCS#1 v1.5 padding for RSA.** Vulnerable to Bleichenbacher's attack. Use OAEP.

### Interview Tip

> Be ready to explain why we combine asymmetric and symmetric encryption (hybrid encryption). Asymmetric is too slow for bulk data; symmetric has the key distribution problem. Together they solve both issues. This is the foundation of TLS.

### References

- [NIST SP 800-38D: AES-GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [RFC 8017: PKCS#1 RSA (OAEP)](https://datatracker.ietf.org/doc/html/rfc8017)

---

## 3. Encoding: URL, Base64, ASCII

### Explanation

Encoding transforms data into a different format for safe transport or storage. It is **not a security mechanism** -- anyone can decode without a key. Encoding schemes exist to handle constraints in transmission channels (e.g., email can only carry 7-bit ASCII, URLs cannot contain spaces).

**Base64:** Represents binary data using 64 printable ASCII characters. Every 3 bytes become 4 Base64 characters (33% increase). URL-safe variant uses `-` and `_` instead of `+` and `/`.

**URL Encoding (percent-encoding):** Replaces unsafe URL characters with `%HH` (hex value). Spaces become `%20` or `+` in form data.

**ASCII:** 7-bit character encoding (128 characters). Extended by UTF-8 for Unicode.

### Code Example

```python
import base64, urllib.parse

# Base64
data = b"Binary data: \x00\xff\x80"
encoded = base64.b64encode(data)       # b'QmluYXJ5IGRhdGE6AP+A'
decoded = base64.b64decode(encoded)
url_safe = base64.urlsafe_b64encode(data)

# URL Encoding
params = {"query": "hello world", "special": "a&b=c"}
encoded_url = urllib.parse.urlencode(params)  # 'query=hello+world&special=a%26b%3Dc'
```

### Common Mistakes

- **Treating Base64 as encryption.** Base64-encoded API keys in config files or HTTP headers are trivially readable.
- **Double encoding URLs.** Encoding an already-encoded string turns `%20` into `%2520`.
- **Not URL-encoding user input in URLs.** Leads to injection attacks (parameter pollution, SSRF).
- **Assuming Base64 output is fixed length.** Output length = `ceil(input_length / 3) * 4` (plus potential padding `=`).

### Interview Tip

> If an interviewer asks "is Base64 secure?", the answer is an emphatic no. Base64 is a reversible encoding with no key. It is purely a data representation format. A common real-world mistake is storing "encrypted" passwords that are actually just Base64-encoded.

---

## 4. Hashing: MD5, SHA1, SHA256

### Explanation

A cryptographic hash function takes arbitrary-length input and produces a fixed-length output (the "digest" or "fingerprint"). Key properties:

1. **Deterministic:** Same input always produces the same output.
2. **Pre-image resistance:** Given a hash `h`, it is computationally infeasible to find any input `m` such that `hash(m) = h`.
3. **Second pre-image resistance:** Given input `m1`, infeasible to find `m2 != m1` with `hash(m1) = hash(m2)`.
4. **Collision resistance:** Infeasible to find any two distinct inputs that hash to the same output.
5. **Avalanche effect:** A single bit change in input produces a drastically different hash.

| Algorithm | Output Size | Status | Collision Resistance |
|---|---|---|---|
| MD5 | 128 bits | **Broken** | Collisions found in seconds |
| SHA-1 | 160 bits | **Deprecated** | First collision (SHAttered, 2017) |
| SHA-256 | 256 bits | Secure | No known practical attacks |
| SHA-3 (Keccak) | 224-512 bits | Secure | Different design (sponge construction) |
| BLAKE2/3 | Variable | Secure | Faster than SHA-256, used in modern systems |

### Code Example

```python
import hashlib, os

# === Basic hashing ===
message = b"Important document content"
sha256_hash = hashlib.sha256(message).hexdigest()   # 256-bit, RECOMMENDED

# === File integrity check ===
def hash_file(filepath, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# === Password hashing (use specialized KDFs, NOT raw SHA) ===
# WRONG: hashlib.sha256(b"password123").hexdigest()
# RIGHT: Use bcrypt, scrypt, or argon2
salt = os.urandom(16)
dk = hashlib.scrypt(b"password123", salt=salt, n=2**14, r=8, p=1, dklen=32)
```

### Common Mistakes

- **Using MD5 or SHA-256 for password storage.** These are too fast. Attackers can compute billions of hashes per second on GPUs. Use bcrypt, scrypt, or Argon2 (purpose-built password hashing functions with tunable cost).
- **Not using a salt.** Without a salt, identical passwords produce identical hashes, enabling rainbow table attacks.
- **Relying on MD5 for integrity in security contexts.** MD5 collisions can be crafted in seconds. The Flame malware exploited an MD5 collision in Microsoft's code signing.
- **Hash length extension attacks.** SHA-256 (Merkle-Damgard) is vulnerable if used as `H(secret || message)`. Use HMAC instead.

### Interview Tip

> When asked about password storage, never say "hash with SHA-256." Always say: use a purpose-built password hashing function (Argon2id preferred, bcrypt or scrypt acceptable) with a unique random salt per password and a tunable work factor.

### References

- [NIST FIPS 180-4: Secure Hash Standard](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [SHAttered: SHA-1 collision](https://shattered.io/)

---

## 5. Obfuscation

### Explanation

Obfuscation transforms code or data to make it harder for humans to understand while preserving functionality. It is **not a security boundary** -- a determined attacker can always reverse-engineer obfuscated code. It is a speed bump, not a wall. Techniques include identifier renaming, control flow flattening, string encryption, dead code insertion, and packing/compression.

### Common Mistakes

- **Relying on obfuscation as the sole security measure.** If a secret (API key, encryption key) is embedded in client-side code, obfuscation only delays discovery.
- **Obfuscating server-side code unnecessarily.** If the attacker does not have access to the binary, obfuscation adds complexity with no security benefit.

### Interview Tip

> Treat obfuscation as defense-in-depth, never as a primary control. If your security model requires the client to not know a secret, the design is flawed -- the secret should stay server-side.

---

## 6. Digital Signing

### Explanation

A digital signature provides **authenticity** (proof of who created the message) and **integrity** (proof the message was not modified). The signer uses their private key to create the signature; anyone with the corresponding public key can verify it.

The process does NOT encrypt the message -- the content remains readable. It only stamps a cryptographic proof onto it.

**ECDSA** requires a random nonce `k` per signature (reuse leaks private key -- see PS3 hack). **Ed25519** (EdDSA) derives `k` deterministically from private key + message, eliminating this footgun. Ed25519 is faster, simpler, and preferred for modern systems (SSH, Signal).

### Code Example

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# === Ed25519 Signing (deterministic, modern, preferred) ===
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

signature = private_key.sign(b"Authentic message")
public_key.verify(signature, b"Authentic message")  # raises InvalidSignature if tampered
```

### Common Mistakes

- **Reusing the nonce `k` in ECDSA.** If two signatures share the same `k`, the private key can be recovered algebraically. This is how the PS3 master key was extracted (Sony used a static `k`).
- **Not verifying signatures.** Accepting a JWT without verification means anyone can forge tokens.
- **Confusing signing with encryption.** Signing does not hide data.
- **Using PKCS#1 v1.5 signatures.** Bleichenbacher-style attacks; prefer PSS for RSA signatures.

### Interview Tip

> The Sony PS3 hack is the canonical example of ECDSA nonce reuse. Be ready to explain: if `k` is reused across two signatures, the private key `d` can be computed with simple algebra. Ed25519 solves this by deriving `k` deterministically from the private key and message.

### References

- [RFC 6979: Deterministic DSA/ECDSA](https://datatracker.ietf.org/doc/html/rfc6979)
- [RFC 8032: Ed25519 and Ed448](https://datatracker.ietf.org/doc/html/rfc8032)

---

## 7. Attack Models

### Explanation

Cryptographic attack models classify the capabilities an attacker has when trying to break a cipher. Understanding these models is essential for evaluating the security of cryptographic schemes.

| Attack Model | Attacker's Capability |
|---|---|
| **Ciphertext-Only Attack (COA)** | Attacker only has ciphertexts. Must deduce plaintext or key from patterns. |
| **Known-Plaintext Attack (KPA)** | Attacker has pairs of (plaintext, ciphertext). Tries to deduce the key. |
| **Chosen-Plaintext Attack (CPA)** | Attacker can choose plaintexts and obtain their ciphertexts (encryption oracle). |
| **Chosen-Ciphertext Attack (CCA)** | Attacker can choose ciphertexts and obtain their decryptions (decryption oracle). |
| **Adaptive Chosen-Plaintext/Ciphertext** | Attacker can adaptively choose inputs based on previous outputs. |
| **Side-Channel Attack** | Attacker exploits physical leakage: timing, power consumption, EM radiation, cache behavior. |
| **Related-Key Attack** | Attacker obtains encryptions under keys with known mathematical relationships. |

### Key Attacks

- **Padding Oracle (CCA):** Attacker sends modified ciphertexts, observes "padding valid/invalid" responses. ~128 queries per byte decrypts the entire ciphertext without the key. Examples: POODLE (SSLv3), Bleichenbacher (RSA PKCS#1 v1.5, resurfaced as ROBOT 2017).
- **BEAST (2011):** Chosen-plaintext against TLS 1.0 CBC mode.
- **Side channels:** Timing attacks on string comparison (`if password == stored_hash`), Spectre/Meltdown (CPU cache timing).

### Common Mistakes

- **Assuming ciphertext-only is the only realistic model.** In web applications, attackers often have encryption or decryption oracles (chosen-plaintext/ciphertext).
- **Ignoring side channels.** Constant-time comparison is essential for password/MAC verification.
- **Using deterministic encryption where CPA security is needed.** Deterministic encryption leaks equality of plaintexts.

### Interview Tip

> When discussing attack models, emphasize that modern ciphers are designed to be CPA-secure at minimum (IND-CPA: indistinguishable under chosen-plaintext attack). Authenticated encryption (AES-GCM, ChaCha20-Poly1305) provides IND-CCA2 security, the strongest standard notion.

### References

- [Wikipedia: Attack model](https://en.wikipedia.org/wiki/Attack_model)
- [Padding oracle attacks (Vaudenay, 2002)](https://en.wikipedia.org/wiki/Padding_oracle_attack)

---

## 8. PKI and Key Exchange

### Explanation

**Public Key Infrastructure (PKI)** is the framework of policies, hardware, software, and procedures for creating, managing, distributing, storing, and revoking digital certificates. It establishes a chain of trust from a root Certificate Authority (CA) down to end-entity certificates.

**Key Exchange** protocols allow two parties to establish a shared secret over an insecure channel without ever transmitting the secret itself.

**Diffie-Hellman (DH):** Alice and Bob agree on public parameters (prime `p`, generator `g`). Each picks a private value, computes a public value (`A = g^a mod p`, `B = g^b mod p`), and exchanges them. Both compute the same shared secret `s = g^(ab) mod p` without it ever crossing the wire. **ECDH** uses elliptic curves instead, providing equivalent security with much smaller keys.

### Code Example

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# === ECDH Key Exchange ===

# Alice generates her key pair
alice_private = ec.generate_private_key(ec.SECP384R1())
alice_public = alice_private.public_key()

# Bob generates his key pair
bob_private = ec.generate_private_key(ec.SECP384R1())
bob_public = bob_private.public_key()

# Both compute the shared secret
alice_shared = alice_private.exchange(ec.ECDH(), bob_public)
bob_shared = bob_private.exchange(ec.ECDH(), alice_public)

assert alice_shared == bob_shared  # Same shared secret!

# Derive a usable symmetric key from the shared secret using HKDF
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data",
).derive(alice_shared)

# Now both parties can use derived_key for AES encryption
```

### Real-World Example

TLS 1.3 mandates ECDHE for key exchange (static RSA removed). Let's Encrypt made HTTPS ubiquitous with free automated certificates. mTLS (mutual TLS) is used in service meshes and zero-trust architectures.

### Common Mistakes

- **Not validating the certificate chain.** Disabling certificate verification (`verify=False` in Python requests) defeats the entire purpose of PKI.
- **Using static DH instead of ephemeral DH.** Static DH does not provide forward secrecy.
- **Trusting a single CA implicitly.** A compromised CA can issue fraudulent certificates (DigiNotar, 2011).
- **Not checking certificate revocation.** Expired or revoked certificates should be rejected.
- **Small DH parameters.** DH groups smaller than 2048 bits are vulnerable (Logjam attack). Prefer ECDH.

### Interview Tip

> Know the difference between DH and ECDH (same concept, different math -- finite field vs elliptic curve). Know that TLS 1.3 dropped static RSA key exchange entirely in favor of ephemeral ECDHE to guarantee forward secrecy. Be able to explain why an ephemeral key pair per session matters.

### References

- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [RFC 7748: Elliptic Curves for Security (X25519)](https://datatracker.ietf.org/doc/html/rfc7748)

---

## 9. Forward Secrecy

### Explanation

**Forward Secrecy** (also called Perfect Forward Secrecy, PFS) ensures that compromise of long-term keys does not compromise past session keys. If an attacker records encrypted traffic today and later obtains the server's private key, they still cannot decrypt the recorded sessions.

This is achieved by using **ephemeral key pairs** for each session. The session key is derived from a short-lived DH exchange, and the ephemeral private keys are deleted after the session ends.

**The Double Ratchet Algorithm** (used in Signal Protocol) takes forward secrecy to the per-message level. Each message uses a unique key, and compromising one key does not reveal past or future messages.

### Real-World Example

Signal/WhatsApp use the **Double Ratchet Algorithm** which combines DH ratcheting with symmetric-key ratcheting to provide per-message forward secrecy and break-in recovery. TLS 1.3 mandates ECDHE for per-session forward secrecy. WireGuard re-handshakes every 2 minutes.

### Common Mistakes

- **Using static RSA key exchange.** If the RSA private key is later compromised, all past sessions can be decrypted. TLS 1.3 explicitly forbids this.
- **Not deleting ephemeral keys.** Forward secrecy only works if ephemeral key material is securely erased after use.
- **Confusing E2E encryption with forward secrecy.** E2E encryption means only endpoints can read messages. Forward secrecy means past messages are safe even if keys leak later. They are complementary but distinct properties.

### Interview Tip

> Explain forward secrecy with a concrete scenario: "An attacker records all encrypted traffic for a year. Then they steal the server's private key. With forward secrecy (ephemeral DH), all those recorded sessions remain encrypted because each session used a unique ephemeral key that was deleted. Without forward secrecy (static RSA), every recorded session can now be decrypted."

### References

- [Signal Protocol: Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [RFC 8446: TLS 1.3 (forward secrecy mandate)](https://datatracker.ietf.org/doc/html/rfc8446)

---

## 10. Ciphers: Block vs Stream

### Explanation

**Block ciphers** encrypt fixed-size blocks of data (e.g., AES operates on 128-bit blocks). To encrypt data larger than one block, a **mode of operation** chains blocks together.

**Stream ciphers** encrypt data one bit/byte at a time by generating a keystream and XORing it with the plaintext. They are conceptually simpler and often faster in software.

| Property | Block Cipher | Stream Cipher |
|---|---|---|
| Unit of operation | Fixed-size block (128 bits for AES) | Bit or byte at a time |
| Examples | AES, 3DES, Blowfish | ChaCha20, RC4 (broken), Salsa20 |
| Requires padding? | Yes (in most modes) | No |
| Parallelizable? | Depends on mode | Generally yes |
| Error propagation | Depends on mode | Single bit (no propagation) |

### Block Cipher Modes of Operation

| Mode | Properties | Parallelizable? | Use Case |
|---|---|---|---|
| **ECB** | Each block encrypted independently. NEVER use. | Encrypt: yes | Never |
| **CBC** | Each block XORed with previous ciphertext. Needs IV. | Encrypt: no, Decrypt: yes | Legacy TLS |
| **CTR** | Block cipher becomes stream cipher. Nonce + counter. | Both: yes | Disk encryption |
| **GCM** | CTR mode + GHASH authentication tag. AEAD. | Both: yes | TLS 1.3, IPsec |
| **CCM** | CTR + CBC-MAC. AEAD. | Encrypt: limited | WiFi (WPA2) |

### Code Example

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import os

# === AES-GCM (AEAD - recommended) ===
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)  # 96-bit nonce

ct = aesgcm.encrypt(nonce, b"No padding needed!", b"additional_auth_data")
pt = aesgcm.decrypt(nonce, ct, b"additional_auth_data")

# === ChaCha20-Poly1305 (stream cipher AEAD) ===
key = ChaCha20Poly1305.generate_key()
chacha = ChaCha20Poly1305(key)
nonce = os.urandom(12)

ct = chacha.encrypt(nonce, b"Stream cipher, great for mobile", None)
pt = chacha.decrypt(nonce, ct, None)
```

### Real-World Example

AES-GCM is the default in TLS 1.3 and cloud KMS. ChaCha20-Poly1305 is preferred on mobile/embedded without AES-NI hardware (WireGuard, mobile browsers). RC4 is completely broken and banned in TLS since RFC 7465.

### Common Mistakes

- **Using ECB mode.** The "ECB penguin" demonstrates that identical plaintext blocks produce identical ciphertext blocks, leaking patterns.
- **Nonce reuse in GCM.** Reusing a nonce with the same key in AES-GCM catastrophically breaks both confidentiality and authenticity. Use a counter or random nonce with collision analysis.
- **CBC without MAC.** CBC alone provides confidentiality but not integrity. Without a MAC (or using MAC-then-encrypt), it is vulnerable to padding oracle attacks. Always use encrypt-then-MAC or AEAD.
- **Using AES-CBC with PKCS7 padding in a web application.** Classic padding oracle target.

### Interview Tip

> Always recommend AEAD (Authenticated Encryption with Associated Data) ciphers: AES-GCM or ChaCha20-Poly1305. These handle both confidentiality and integrity in a single primitive, eliminating the complexity and pitfalls of combining a cipher with a separate MAC.

### References

- [NIST SP 800-38D: GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [RFC 8439: ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439)

---

## 11. Integrity Primitives: Hash Functions, MACs, HMAC

### Explanation

Integrity primitives detect unauthorized modification of data. They answer: "Has this data been tampered with?"

**Hash functions** (covered in section 4) provide integrity only if the hash itself is transmitted securely. If an attacker can modify both the data and the hash, they provide no protection.

**MAC (Message Authentication Code)** provides both integrity and authenticity. It requires a shared secret key, so only parties with the key can generate or verify the MAC.

**HMAC (Hash-based MAC)** constructs a MAC from a hash function. It is the most widely used MAC construction.

```
HMAC(K, M) = H((K XOR opad) || H((K XOR ipad) || M))

  where:
  - K = secret key (padded to block size)
  - opad = 0x5c repeated to block size
  - ipad = 0x36 repeated to block size
  - H = hash function (SHA-256, etc.)
  - || = concatenation
```

Other MAC constructions: **CMAC** (block-cipher-based), **GMAC** (AES-GCM's MAC component), **Poly1305** (used with ChaCha20).

**Why HMAC, not `H(key || message)`?** Merkle-Damgard hashes (MD5, SHA-1, SHA-256) are vulnerable to length extension attacks with naive `H(key || msg)`. HMAC's double-hashing construction prevents this. Always use **encrypt-then-MAC** (verify integrity before decrypting) or AEAD.

### Code Example

```python
import hmac
import hashlib

# === Python stdlib HMAC ===
key = b"shared-secret-key-32-bytes-long!"
message = b"Important financial transaction data"

# Create HMAC-SHA256
mac = hmac.new(key, message, hashlib.sha256).digest()

# Verify (constant-time comparison -- CRITICAL for security)
is_valid = hmac.compare_digest(
    mac,
    hmac.new(key, message, hashlib.sha256).digest()
)

# WRONG: if mac == received_mac:  # timing side channel!
# RIGHT: hmac.compare_digest(mac, received_mac)  # Always use this
```

### Real-World Example

HMAC-SHA256 is used in JWT (HS256), AWS Signature V4, and TLS 1.2 PRF. TOTP/HOTP one-time passwords use HMAC internally (RFC 6238/4226).

### Common Mistakes

- **Using `H(key || message)` instead of HMAC.** Vulnerable to length extension attacks with MD5/SHA-1/SHA-256.
- **Non-constant-time MAC comparison.** `if mac == expected:` leaks timing information. Use `hmac.compare_digest()`.
- **MAC-then-encrypt.** The MAC is computed on plaintext, then both are encrypted. The receiver must decrypt before verifying the MAC, which enables padding oracle attacks. Always use **encrypt-then-MAC** or AEAD.
- **Using the same key for encryption and MAC.** Derive separate keys from a master key using a KDF.

### Interview Tip

> Be able to explain the encrypt-then-MAC vs MAC-then-encrypt debate. Encrypt-then-MAC is provably secure: you verify integrity of ciphertext before decrypting, preventing oracle attacks. MAC-then-encrypt (used in TLS pre-1.3) led to BEAST and POODLE. AEAD (AES-GCM) sidesteps the issue entirely by combining both operations.

### References

- [RFC 2104: HMAC](https://datatracker.ietf.org/doc/html/rfc2104)
- [NIST SP 800-107: Hash-Based MAC](https://csrc.nist.gov/publications/detail/sp/800-107/rev-1/final)

---

## 12. Entropy and Random Number Generation

### Explanation

**Entropy** is the measure of randomness or unpredictability in data. Cryptographic operations depend critically on high-quality randomness. Weak randomness is one of the most devastating cryptographic failures -- it undermines key generation, nonce creation, and every protocol built on them.

**PRNG (Pseudo-Random Number Generator):** A deterministic algorithm that produces a sequence of numbers that appear random, starting from a seed. Cryptographically secure PRNGs (CSPRNGs) are designed so that even knowing part of the output does not reveal other parts.

**TRNG (True Random Number Generator):** Hardware-based, derives randomness from physical phenomena (thermal noise, radioactive decay, CPU jitter). On Linux (5.18+), `/dev/random` and `/dev/urandom` are equivalent after initial seeding, both using a ChaCha20-based CSPRNG. Low-entropy environments (VMs, containers at boot) are high-risk; solutions include `haveged`, `rng-tools`, VirtIO-RNG, and the `getrandom()` syscall.

### Code Example

```python
import os, secrets

# === RIGHT: cryptographically secure ===
random_bytes = os.urandom(32)            # 256 bits from OS CSPRNG
token = secrets.token_hex(32)            # 64 hex chars (256 bits)
url_token = secrets.token_urlsafe(32)    # URL-safe base64

# === WRONG: using `random` module for security ===
# import random
# random.random()  # Mersenne Twister -- PREDICTABLE, state recoverable from 624 outputs

# === Deriving keys from passwords ===
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
salt = os.urandom(16)
kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
key = kdf.derive(b"user-password")  # Low-entropy input -> high-entropy key
```

### Real-World Example

**Debian OpenSSL bug (2008, CVE-2008-0166):** A maintainer accidentally removed entropy sources, reducing the seed space to ~32,768 possibilities. All SSH/TLS keys generated on affected systems for 2 years were predictable. **Android SecureRandom bug (2013):** Insufficient PRNG seeding led to Bitcoin wallet theft through private key collisions.

### Common Mistakes

- **Using `random.random()` (Python) or `Math.random()` (JavaScript) for security.** These are non-cryptographic PRNGs. Use `secrets` (Python), `crypto.randomBytes()` (Node.js), or `window.crypto.getRandomValues()` (browser).
- **Generating keys in low-entropy environments without waiting for the pool to seed.** VMs and containers immediately after boot are high-risk.
- **Hardcoding seeds.** `random.seed(42)` produces a deterministic sequence. Never use fixed seeds for security-relevant operations.
- **Not reseeding long-running processes.** CSPRNGs should be periodically reseeded from the OS entropy pool.
- **Rolling your own PRNG.** Always use the OS-provided CSPRNG.

### Interview Tip

> The Debian OpenSSL bug is the canonical example of entropy failure. Be ready to explain: a single line of code removed entropy collection, reducing all generated keys to a tiny keyspace. This affected SSH, TLS certificates, and VPN keys across millions of systems for two years before discovery. The lesson: never reduce entropy sources, always use the OS CSPRNG, and audit security-critical code changes carefully.

### References

- [RFC 4086: Randomness Requirements for Security](https://datatracker.ietf.org/doc/html/rfc4086)
- [CVE-2008-0166: Debian OpenSSL bug](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0166)

---

## Key Takeaways

1. **Always use AEAD ciphers** (AES-GCM or ChaCha20-Poly1305). They provide confidentiality and integrity in one primitive, eliminating the pitfalls of combining a cipher and MAC manually.

2. **Never reuse nonces.** Nonce reuse in AES-GCM or ECDSA is catastrophic. Use counters or sufficiently large random nonces with collision analysis.

3. **Asymmetric + symmetric = hybrid encryption.** Asymmetric solves key distribution; symmetric handles bulk data. This is the foundation of TLS, PGP, and virtually all real-world encryption.

4. **Hash passwords with Argon2id, bcrypt, or scrypt.** Never use raw SHA-256 or MD5 for passwords. Use a unique random salt and tunable work factor.

5. **Forward secrecy is mandatory.** Use ephemeral key exchange (ECDHE). TLS 1.3 enforces this. Delete ephemeral keys after session completion.

6. **Encoding is not encryption.** Base64, URL encoding, and hex encoding provide zero security. They are data format transformations, not cryptographic operations.

7. **Use the OS CSPRNG for all random values.** `os.urandom()` / `secrets` module in Python. Never use `random.random()` for security. The Debian OpenSSL bug shows what happens when entropy fails.

8. **Understand attack models.** Modern systems face chosen-plaintext and chosen-ciphertext attacks routinely (web encryption oracles, padding oracles). Design for IND-CCA2 security.

9. **Constant-time comparisons for MACs and secrets.** Use `hmac.compare_digest()`, never `==`. Timing side channels are real and exploitable.

10. **PKI is only as strong as its weakest CA.** Certificate Transparency, certificate pinning, and HSTS help mitigate CA compromise risks.

---

## Interview Practice Questions

1. **Explain the difference between encryption, encoding, hashing, and signing. When would you use each?**

2. **Why do we use hybrid encryption in TLS instead of encrypting everything with RSA?**

3. **What is a padding oracle attack? How does it work, and how do AEAD ciphers prevent it?**

4. **Explain forward secrecy. Why did TLS 1.3 remove static RSA key exchange?**

5. **How does the Diffie-Hellman key exchange work? What problem does it solve? What attack is it vulnerable to without authentication?** (Answer: man-in-the-middle; DH alone does not authenticate parties.)

6. **Why is ECB mode insecure? Draw a diagram comparing ECB and CBC.**

7. **What went wrong in the Sony PS3 ECDSA hack?** (Answer: static nonce `k` reuse allowed private key recovery.)

8. **Why should you never use SHA-256 directly for password hashing? What should you use instead?**

9. **What is a length extension attack? Which hash constructions are vulnerable, and how does HMAC prevent it?**

10. **Explain the Double Ratchet Algorithm at a high level. What security properties does it provide beyond standard TLS?** (Answer: per-message forward secrecy and break-in recovery.)

11. **What is the Debian OpenSSL entropy bug? What was the impact?**

12. **Compare AES-GCM and ChaCha20-Poly1305. When would you prefer one over the other?** (Answer: AES-GCM when hardware AES-NI is available; ChaCha20 on mobile/embedded without AES acceleration.)

13. **What is encrypt-then-MAC vs MAC-then-encrypt? Why does the order matter?**

14. **How does Certificate Transparency work, and what problem does it solve?**

15. **What happens if you reuse a nonce with AES-GCM?** (Answer: authentication is completely broken, and the XOR of two plaintexts is leaked.)

---

[Previous: Mitigations](mitigations.md) | [Next: Authentication](authentication.md)
