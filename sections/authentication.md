# Authentication - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#authentication)

> **Prerequisites:** [Cryptography](cryptography.md)  
> **Difficulty:** Intermediate to Advanced

---

## Table of Contents

1. [Certificates](#1-certificates)
2. [TPM (Trusted Platform Module)](#2-tpm-trusted-platform-module)
3. [OAuth](#3-oauth)
4. [Auth Cookies](#4-auth-cookies)
5. [Sessions](#5-sessions)
6. [Auth Systems: SAMLv2, OpenID, Kerberos](#6-auth-systems-samlv2-openid-kerberos)
7. [Biometrics](#7-biometrics)
8. [Password Management](#8-password-management)
9. [U2F/FIDO](#9-u2ffido)
10. [Multi-Factor Auth Comparison](#10-multi-factor-auth-comparison)

---

## 1. Certificates

### Explanation

An X.509 digital certificate binds a public key to an identity (domain name, organization, person). Certificates form the backbone of TLS/SSL and are issued by Certificate Authorities (CAs). A certificate contains:

- **Subject** -- the entity the cert identifies (e.g., `CN=example.com`)
- **Issuer** -- the CA that signed the cert
- **Public key** -- the subject's public key
- **Serial number** -- unique identifier within the issuing CA
- **Validity period** -- Not Before / Not After dates
- **Signature** -- the CA's digital signature over the cert contents
- **Extensions** -- Subject Alternative Names (SANs), Key Usage, CRL Distribution Points, OCSP responder URL

Certificates are signed using the CA's private key. Trust is established through a **chain of trust**: the end-entity cert is signed by an intermediate CA, which is signed by a root CA. Root CA certificates are pre-installed in operating systems and browsers as **trust anchors**.

### How It Works

1. Server presents its certificate during the TLS handshake.
2. Client walks the chain: end-entity cert -> intermediate CA -> root CA.
3. Client verifies each signature in the chain using the issuer's public key.
4. Client checks the cert is not expired, not revoked (via CRL or OCSP), and the subject matches the requested domain.
5. If all checks pass, the client trusts the server's public key and proceeds with the key exchange.

### Diagram

```
  Browser                     Server                  Intermediate CA         Root CA
    |                           |                           |                    |
    |--- ClientHello ---------->|                           |                    |
    |<-- ServerHello + Cert ----|                           |                    |
    |                           |                           |                    |
    |  [Cert contains:]         |                           |                    |
    |  Subject: example.com     |                           |                    |
    |  Issuer: Intermediate CA  |                           |                    |
    |  Signature: <sig_by_ICA>  |                           |                    |
    |                           |                           |                    |
    |--- Verify sig_by_ICA using Intermediate CA pubkey --->|                    |
    |--- Verify ICA cert sig using Root CA pubkey --------->|-------verify------>|
    |                                                       |                    |
    |  [Root CA is in local trust store -- TRUSTED]         |                    |
    |                                                       |                    |
    |--- Check revocation (OCSP/CRL) --------------------->|                    |
    |<-- OCSP Response: GOOD -------------------------------|                    |
    |                                                       |                    |
    |  CHAIN VALID -> proceed with TLS handshake            |                    |
```

### Real-World Example: The DigiNotar Breach (2011)

DigiNotar was a Dutch Certificate Authority. Attackers compromised DigiNotar's infrastructure and issued **over 500 fraudulent certificates**, including one for `*.google.com`. This allowed man-in-the-middle attacks against Gmail users in Iran.

**Timeline:**
- June 2011: Attackers breach DigiNotar's CA infrastructure.
- July 2011: Fraudulent `*.google.com` cert issued.
- August 2011: Google Chrome's certificate pinning detects the rogue cert. An Iranian user reports the anomaly.
- September 2011: All major browsers revoke trust in DigiNotar's root CA. DigiNotar declares bankruptcy.

**Lessons learned:**
- Certificate Transparency (CT) logs now provide public auditability of all issued certs.
- HTTP Public Key Pinning (HPKP) was introduced (later deprecated in favor of CT).
- CAA DNS records let domain owners restrict which CAs can issue certs for their domain.

### Attack Vectors

| Attack | Description |
|--------|-------------|
| **CA compromise** | Attacker gains access to a CA's signing key (DigiNotar) |
| **Rogue certificates** | Fraudulent cert issuance via compromised CA or domain validation bypass |
| **MITM with forged cert** | Corporate proxies or nation-states using locally trusted root CAs |
| **Expired cert exploitation** | Users trained to click through warnings |
| **Weak signature algorithms** | MD5 collisions (Flame malware used a forged Microsoft cert) |

### Interview Tip

> When discussing certificates, always mention the **chain of trust** model, the DigiNotar incident as a case study, and modern mitigations like **Certificate Transparency**. Interviewers want to see you understand both how the system works and how it has historically failed.

### References

- [RFC 5280 - X.509 PKI Certificate Profile](https://tools.ietf.org/html/rfc5280)
- [Certificate Transparency - RFC 6962](https://tools.ietf.org/html/rfc6962)
- [DigiNotar Incident Report (Fox-IT)](https://www.rijksoverheid.nl/documenten/rapporten/2012/08/13/diginotar-public-report-version-1)

---

## 2. TPM (Trusted Platform Module)

### Explanation

A TPM is a dedicated hardware cryptoprocessor soldered to the motherboard (or firmware-based in fTPM). It provides a tamper-resistant environment for:

- **Key generation and storage** -- private keys are generated inside the TPM and never leave it.
- **Platform integrity measurement** -- PCR (Platform Configuration Register) values record boot measurements.
- **Sealing/binding** -- encrypt data to a specific platform state so it can only be decrypted if the system hasn't been tampered with.
- **Remote attestation** -- prove to a remote party that the platform is in a trusted state.

TPM 2.0 (ISO/IEC 11889) is the current standard and is required by Windows 11.

### How It Works

1. During boot, firmware measures each component (BIOS, bootloader, OS kernel) and extends PCR values.
2. Each measurement is: `PCR_new = SHA-256(PCR_old || measurement)` -- this creates an append-only log.
3. Applications can request the TPM to sign the PCR values with its Attestation Identity Key (AIK).
4. A remote verifier checks the signed PCR values against known-good measurements.
5. Secrets sealed to specific PCR values can only be unsealed if the platform boots into the exact same measured state.

### Diagram

```
  BOOT PROCESS                          TPM CHIP
  ============                          ========
                                       +-------------------+
  [UEFI Firmware]---measure hash------>| PCR[0] = H(BIOS) |
       |                               |                   |
  [Bootloader]-----measure hash------->| PCR[4] = H(boot) |
       |                               |                   |
  [OS Kernel]------measure hash------->| PCR[8] = H(kern) |
       |                               |                   |
  [Application requests attestation]   |                   |
       |                               |  AIK signs PCRs   |
       |<------signed PCR quote--------|                   |
       |                               +-------------------+
       |
  [Send quote to remote verifier]
       |
  [Verifier checks PCRs against known-good values]
       |
  [PASS] --> platform is trusted
```

### Real-World Example

BitLocker (Windows full-disk encryption) uses the TPM to seal the volume master key to specific PCR values. If an attacker modifies the bootloader (e.g., installing a bootkit), the PCR values change and BitLocker refuses to release the decryption key, forcing a recovery key prompt.

### Attack Vectors

| Attack | Description |
|--------|-------------|
| **TPM reset attack** | Physically resetting the TPM bus to replay old PCR values (mitigated in TPM 2.0) |
| **Cold boot attack** | Extracting keys from RAM before the TPM can clear them |
| **fTPM vulnerabilities** | Firmware TPMs run in the CPU's TrustZone; firmware bugs can expose secrets (faulTPM, 2023) |
| **Evil maid** | Physical access to install a hardware keylogger before the TPM-protected boot completes |
| **ROCA vulnerability** | CVE-2017-15361 -- weak RSA key generation in Infineon TPMs allowed private key recovery |

### Interview Tip

> Explain TPM as a **hardware root of trust** that anchors the entire boot chain. Mention the difference between discrete TPMs (dedicated chip) and firmware TPMs (fTPM). Relate it to real use cases like BitLocker, Windows Hello, and measured boot.

### References

- [TCG TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [NIST SP 800-155 - BIOS Integrity Measurement](https://csrc.nist.gov/publications/detail/sp/800-155/draft)
- [Microsoft: TPM Recommendations](https://docs.microsoft.com/en-us/windows/security/information-protection/tpm/tpm-recommendations)

---

## 3. OAuth

### Explanation

OAuth 2.0 (RFC 6749) is an **authorization** framework (not authentication) that allows a third-party application to obtain limited access to a resource on behalf of the resource owner. The access is represented by a **bearer token** -- whoever holds the token can use it, similar to a cookie.

Key roles:
- **Resource Owner** -- the user
- **Client** -- the third-party app requesting access
- **Authorization Server** -- issues tokens (e.g., Google's auth server)
- **Resource Server** -- hosts the protected API

Grant types: Authorization Code, Client Credentials, Device Code (PKCE is mandatory for public clients per current best practices).

### How It Works (Authorization Code Flow with PKCE)

1. Client generates a `code_verifier` (random string) and derives `code_challenge = SHA256(code_verifier)`.
2. Client redirects user to the Authorization Server with `code_challenge`.
3. User authenticates and grants consent.
4. Authorization Server redirects back to the client with an **authorization code**.
5. Client exchanges the authorization code + `code_verifier` for an **access token** (and optionally a refresh token).
6. Client uses the access token as a Bearer token in API requests.
7. Access token expires; client uses the refresh token to obtain a new access token without user interaction.

### Diagram

```
  User          Client App        Auth Server         Resource Server
   |                |                  |                      |
   |--login-------->|                  |                      |
   |                |--redirect------->|                      |
   |                |  (code_challenge)|                      |
   |<--auth prompt--|------------------|                      |
   |--credentials-->|----------------->|                      |
   |                |                  |--validate creds      |
   |                |<--authz code-----|                      |
   |                |                  |                      |
   |                |--exchange code-->|                      |
   |                |  + code_verifier |                      |
   |                |<--access_token---|                      |
   |                |   refresh_token  |                      |
   |                |                  |                      |
   |                |--GET /api -------|---Bearer token------->|
   |                |                  |                      |--validate token
   |                |<--API response---|----------------------|
```

### Real-World Example: OAuth Token Theft

In 2022, attackers targeting GitHub users abused OAuth app consent flows. Malicious OAuth apps requested broad scopes; once a user authorized the app, the attacker obtained access tokens that gave them full access to private repositories. GitHub had to revoke tokens and notify affected users.

Another vector: access tokens stored in `localStorage` in SPAs are vulnerable to XSS. A single XSS flaw can exfiltrate the token to an attacker-controlled server.

### Attack Vectors

| Attack | Description |
|--------|-------------|
| **Token theft** | Bearer tokens are like cash -- if stolen (via XSS, logs, or network sniffing), the attacker has full access |
| **Authorization code interception** | Without PKCE, a malicious app on the same device can intercept the redirect |
| **Consent phishing** | Tricking users into granting OAuth permissions to malicious apps |
| **Refresh token abuse** | Long-lived refresh tokens stored insecurely provide persistent access |
| **Open redirect** | Manipulating the redirect_uri to leak authorization codes to attacker-controlled endpoints |
| **Scope escalation** | Requesting overly broad scopes that users don't understand |

### Interview Tip

> Emphasize that OAuth is **authorization, not authentication** (OpenID Connect adds the authentication layer). Explain why bearer tokens are dangerous -- they are equivalent to stolen cookies. Always mention PKCE when discussing modern OAuth implementations.

### References

- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://datatracker.ietf.org/doc/html/rfc9700)
- [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_Cheat_Sheet.html)

---

## 4. Auth Cookies

### Explanation

Authentication cookies are the most common mechanism for maintaining authenticated state in web applications. After a user logs in, the server issues a cookie containing a session identifier (or in some cases, a signed token like a JWT). The browser automatically attaches this cookie to every subsequent request to the same domain.

Critical cookie security attributes:
- **`HttpOnly`** -- cookie is inaccessible to JavaScript (mitigates XSS theft)
- **`Secure`** -- cookie is only sent over HTTPS
- **`SameSite`** -- controls when cookies are sent with cross-site requests (`Strict`, `Lax`, or `None`)
- **`Domain` / `Path`** -- scope the cookie to specific domains and paths
- **`Expires` / `Max-Age`** -- controls cookie lifetime

### How It Works

1. User submits credentials to `/login`.
2. Server validates credentials against the user store.
3. Server creates a session and generates a random session ID.
4. Server responds with `Set-Cookie: session_id=<random>; HttpOnly; Secure; SameSite=Lax`.
5. Browser stores the cookie and attaches it to every subsequent same-site request.
6. Server looks up the session ID to identify the user on each request.
7. On logout, server invalidates the session and instructs the browser to delete the cookie.

### Diagram

```
  Browser                              Server
    |                                    |
    |--- POST /login (user:pass) ------->|
    |                                    |--- validate credentials
    |                                    |--- create session in DB/cache
    |                                    |    session_id = random(256bit)
    |<-- 200 OK -------------------------|
    |    Set-Cookie: sid=abc123;         |
    |    HttpOnly; Secure; SameSite=Lax  |
    |                                    |
    |--- GET /dashboard ---------------->|
    |    Cookie: sid=abc123              |
    |                                    |--- lookup session abc123
    |                                    |--- user = alice, role = admin
    |<-- 200 OK (dashboard) ------------|
    |                                    |
    |--- POST /logout ------------------>|
    |                                    |--- delete session abc123
    |<-- Set-Cookie: sid=; Max-Age=0 ----|
```

### Real-World Example

The 2023 Okta breach involved attackers stealing session cookies from a support case management system. Attackers used stolen HAR files (HTTP Archive) uploaded by customers for troubleshooting; these HAR files contained valid session cookies, allowing the attackers to hijack active sessions and bypass all authentication.

### Attack Vectors

| Attack | Description |
|--------|-------------|
| **XSS cookie theft** | If `HttpOnly` is not set, JavaScript can read `document.cookie` |
| **CSRF** | Without `SameSite` protection, a malicious site can trigger authenticated requests |
| **Session fixation** | Attacker sets a known session ID before the user authenticates |
| **Cookie replay** | Intercepting and replaying cookies over unencrypted connections (no `Secure` flag) |
| **Pass-the-cookie** | Stealing cookies from disk/memory (e.g., from browser profile) to hijack sessions |

### Interview Tip

> Always list the three critical cookie flags: `HttpOnly`, `Secure`, `SameSite`. Explain that cookies are **automatically attached** by the browser, which is both their strength (no JS needed) and their weakness (CSRF). Mention that cookie theft is functionally identical to credential theft.

### References

- [RFC 6265bis - Cookies](https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

## 5. Sessions

### Explanation

Sessions are the **server-side** component of stateful authentication. While cookies carry the session identifier client-side, the actual session data (user identity, roles, CSRF tokens, expiry time) lives on the server in a session store.

Session stores can be:
- **In-memory** -- fast but lost on server restart; doesn't scale horizontally
- **Database-backed** -- persistent, queryable, but adds latency
- **Distributed cache** -- Redis, Memcached -- fast, scalable, supports expiration natively
- **Signed tokens (JWT)** -- stateless sessions where the server does not store anything; all data is in the token itself

### How It Works

1. User authenticates; server creates a session record in the session store.
2. Session record maps `session_id -> {user_id, roles, csrf_token, created_at, expires_at}`.
3. Session ID is sent to client via cookie.
4. On each request, middleware extracts the session ID from the cookie, looks up the session store, and populates the request context with user info.
5. Session expiration is enforced both by cookie `Max-Age` and server-side TTL.
6. On logout or revocation, the server deletes the session record.

### Diagram

```
                           +--------------------+
  Browser ---cookie:sid--->| Load Balancer      |
                           +--------------------+
                             /        |        \
                          Server1  Server2  Server3
                             \        |        /
                           +--------------------+
                           | Session Store      |
                           | (Redis / DB)       |
                           |                    |
                           | sid:abc -> {       |
                           |   user: alice,     |
                           |   role: admin,     |
                           |   exp: 1hr         |
                           | }                  |
                           +--------------------+

  Stateless (JWT) alternative:

  Browser ---Authorization: Bearer <JWT>---> Server
                                              |
                                       Verify signature
                                       Decode claims
                                       (no store lookup)
```

### Real-World Example

When scaling from one server to many, session affinity (sticky sessions) was a common but fragile approach -- a load balancer pinned a user to one server. Modern practice uses centralized session stores like Redis. If Redis goes down, all users are logged out. Netflix and similar services use short-lived JWTs combined with refresh tokens to avoid centralized session storage entirely.

### Attack Vectors

| Attack | Description |
|--------|-------------|
| **Session hijacking** | Stealing the session ID via network sniffing, XSS, or malware |
| **Session fixation** | Forcing a known session ID on the victim before login |
| **Session prediction** | Guessing session IDs if they lack sufficient entropy |
| **JWT algorithm confusion** | Switching from RS256 to HS256 and using the public key as the HMAC secret |
| **JWT none attack** | Setting `alg: none` to bypass signature verification on misconfigured servers |

### Interview Tip

> Contrast server-side sessions (stateful, revocable) with JWTs (stateless, not easily revocable). The tradeoff: sessions require a store but support instant revocation; JWTs avoid a store but require short lifetimes or a blacklist to handle revocation. Know both approaches and their tradeoffs.

### References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [JWT.io](https://jwt.io/)

---

## 6. Auth Systems: SAMLv2, OpenID Connect, Kerberos

### 6a. SAMLv2

#### Explanation

Security Assertion Markup Language (SAML) 2.0 is an XML-based framework for exchanging authentication and authorization data between an **Identity Provider (IdP)** and a **Service Provider (SP)**. It is the dominant SSO protocol in enterprise environments.

Key concepts:
- **Assertion** -- an XML document containing authentication statements, attribute statements, and authorization decisions.
- **SP-initiated flow** -- user visits the SP first, gets redirected to the IdP.
- **IdP-initiated flow** -- user starts at the IdP portal and clicks a link to the SP.
- **Binding** -- how SAML messages are transported: HTTP Redirect, HTTP POST, or Artifact.

#### How It Works (SP-Initiated SSO)

1. User visits `app.example.com` (SP).
2. SP generates a SAML `AuthnRequest` and redirects the user to the IdP.
3. IdP authenticates the user (login form, MFA, etc.).
4. IdP creates a SAML `Response` containing a signed `Assertion`.
5. IdP POSTs the SAML Response to the SP's Assertion Consumer Service (ACS) URL.
6. SP validates the XML signature, checks conditions (audience, timestamps), and extracts the user identity.
7. SP creates a local session for the user.

#### Diagram

```
  User/Browser              Service Provider (SP)        Identity Provider (IdP)
       |                          |                              |
       |--- GET /app ----------->|                              |
       |                          |--- generate AuthnRequest    |
       |<-- 302 Redirect --------|                              |
       |    to IdP + AuthnReq    |                              |
       |                          |                              |
       |--- GET /sso?SAMLReq ----|----------------------------->|
       |                          |                              |--- authenticate user
       |<-- login form -----------|------------------------------|
       |--- credentials ---------|----------------------------->|
       |                          |                              |--- verify credentials
       |                          |                              |--- build SAML assertion
       |                          |                              |--- sign with IdP private key
       |<-- POST /acs ------------|<---- SAML Response ----------|
       |                          |                              |
       |                          |--- validate signature       |
       |                          |--- check audience/time      |
       |                          |--- extract NameID + attrs   |
       |                          |--- create local session     |
       |<-- 200 OK (app) --------|                              |
```

### 6b. OpenID Connect (OIDC)

#### Explanation

OpenID Connect is an identity layer built **on top of OAuth 2.0**. While OAuth handles authorization (access tokens), OIDC adds authentication via the **ID Token** -- a JWT containing claims about the authenticated user (`sub`, `email`, `name`, `iss`, `aud`, `exp`).

OIDC defines standard scopes: `openid`, `profile`, `email`, `address`, `phone`.

#### How It Works

1. Client redirects user to the OpenID Provider (OP) with `scope=openid`.
2. User authenticates at the OP.
3. OP returns an authorization code.
4. Client exchanges the code for an **ID token** (JWT) + access token.
5. Client validates the ID token's signature, issuer, audience, and expiry.
6. Client extracts user identity from the ID token claims.

#### Diagram

```
  User        Client (Relying Party)       OpenID Provider
   |                |                           |
   |--login-------->|                           |
   |                |--redirect (scope=openid)->|
   |<--auth prompt--|---------------------------|
   |--credentials-->|-------------------------->|
   |                |<--authz code--------------|
   |                |--exchange code----------->|
   |                |<--id_token (JWT)----------|
   |                |   + access_token          |
   |                |                           |
   |                |--validate JWT signature   |
   |                |--check iss, aud, exp      |
   |                |--extract sub, email       |
   |<--logged in----|                           |
```

### 6c. Kerberos

#### Explanation

Kerberos is a network authentication protocol that uses **symmetric key cryptography** and a trusted third party (the **Key Distribution Center**, or KDC). It is the default authentication protocol in Active Directory environments.

Key components:
- **KDC** -- runs the Authentication Service (AS) and the Ticket-Granting Service (TGS)
- **TGT (Ticket-Granting Ticket)** -- obtained at login, encrypted with the KDC's secret key (krbtgt hash)
- **Service Ticket (TGS)** -- grants access to a specific service, encrypted with the service account's key
- **Authenticator** -- proves the client knows the session key (prevents replay attacks)

#### How It Works

1. User logs in; client sends `AS-REQ` to the KDC with the username.
2. KDC responds with `AS-REP`: a TGT (encrypted with `krbtgt` hash) + session key (encrypted with user's password hash).
3. Client decrypts the session key using the user's password hash.
4. To access a service, client sends `TGS-REQ` with the TGT to the KDC.
5. KDC returns `TGS-REP`: a service ticket (encrypted with the service's key) + a new session key.
6. Client presents the service ticket + authenticator to the target service.
7. Service decrypts the ticket and validates the authenticator.

#### Diagram

```
  Client                       KDC (AS + TGS)                Service
    |                               |                           |
    |--- AS-REQ (username) -------->|                           |
    |                               |--- lookup user hash       |
    |<-- AS-REP --------------------|                           |
    |   [TGT encrypted w/ krbtgt]   |                           |
    |   [Session key enc w/ pw]     |                           |
    |                               |                           |
    |--- decrypt session key        |                           |
    |   (using password hash)       |                           |
    |                               |                           |
    |--- TGS-REQ (TGT + target) -->|                           |
    |                               |--- decrypt TGT            |
    |                               |--- issue service ticket   |
    |<-- TGS-REP -------------------|                           |
    |   [Service ticket enc w/      |                           |
    |    service account key]       |                           |
    |                               |                           |
    |--- AP-REQ (service ticket + authenticator) -------------->|
    |                                                           |--- decrypt ticket
    |                                                           |--- validate authenticator
    |<-- AP-REP (mutual auth, optional) -----------------------|
```

#### Real-World Example: Golden and Silver Ticket Attacks

**Golden Ticket:** If an attacker obtains the `krbtgt` account's NTLM hash (e.g., via DCSync or NTDS.dit extraction), they can forge TGTs for any user with any group membership. This is the "keys to the kingdom" -- the forged TGT is valid for up to 10 years by default.

**Silver Ticket:** If an attacker obtains a service account's NTLM hash, they can forge service tickets for that specific service. Silver tickets never touch the KDC, making them harder to detect.

**Kerberoasting:** Service accounts with SPNs (Service Principal Names) have their service tickets encrypted with their password hash. Any domain user can request these tickets and crack them offline. Weak service account passwords fall quickly.

**Mimikatz** is the primary tool for these attacks:
- `sekurlsa::logonpasswords` -- dumps plaintext passwords and NTLM hashes from LSASS memory
- `kerberos::golden` -- forges golden tickets
- `kerberos::ptt` -- pass-the-ticket injection

**Pass-the-Hash (PtH):** NTLM authentication doesn't require the plaintext password, only the hash. Mimikatz's `sekurlsa::pth` injects a stolen hash into a new logon session, enabling lateral movement without knowing the actual password.

### Attack Vectors (All Three Systems)

| System | Attack | Description |
|--------|--------|-------------|
| SAML | **XML Signature Wrapping** | Manipulating XML structure to bypass signature verification |
| SAML | **Assertion replay** | Reusing a valid assertion if the SP doesn't check `InResponseTo` or enforce time windows |
| OIDC | **Token substitution** | Swapping an ID token from one client into another |
| OIDC | **Issuer confusion** | Multi-tenant apps tricked into accepting tokens from a rogue issuer |
| Kerberos | **Golden Ticket** | Forged TGT using compromised `krbtgt` hash |
| Kerberos | **Silver Ticket** | Forged service ticket using compromised service account hash |
| Kerberos | **Kerberoasting** | Offline cracking of service ticket hashes |
| Kerberos | **AS-REP Roasting** | Cracking hashes of accounts with Kerberos pre-auth disabled |
| Kerberos | **Pass-the-Hash** | Using NTLM hash directly for authentication without the password |

### Interview Tip

> For enterprise security roles, Kerberos knowledge is essential. Be ready to explain the Golden Ticket attack end-to-end: how the attacker gets the `krbtgt` hash, how they forge the TGT, and how to detect/mitigate it (rotate `krbtgt` password twice, monitor event ID 4769 anomalies). For web-focused roles, compare SAML vs OIDC: SAML is XML-heavy and enterprise-focused; OIDC is JSON/JWT-based and developer-friendly.

### References

- [RFC 4120 - Kerberos V5](https://tools.ietf.org/html/rfc4120)
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [Mimikatz Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [MITRE ATT&CK - Kerberoasting (T1558.003)](https://attack.mitre.org/techniques/T1558/003/)

---

## 7. Biometrics

### Explanation

Biometric authentication uses unique physical or behavioral characteristics to verify identity. Common modalities include fingerprint, facial recognition, iris scan, voice recognition, and behavioral biometrics (typing patterns, gait).

The fundamental problem with biometrics: **they cannot be rotated**. If a password is compromised, you change it. If a fingerprint template is compromised, you cannot change your finger. This makes biometric data a high-value, irreplaceable credential.

Biometric systems measure two key metrics:
- **FAR (False Acceptance Rate)** -- probability of accepting an impostor
- **FRR (False Rejection Rate)** -- probability of rejecting a legitimate user
- **EER (Equal Error Rate)** -- the point where FAR = FRR; lower is better

### How It Works

1. **Enrollment:** User presents biometric sample. The sensor captures it and the system extracts a feature template (not a raw image). The template is stored.
2. **Verification (1:1):** User claims an identity and presents a biometric. The system compares the live template against the stored template for that identity. If the similarity score exceeds the threshold, authentication succeeds.
3. **Identification (1:N):** No identity claim. The system compares the live template against all stored templates to find a match.

### Diagram

```
  ENROLLMENT:
  +--------+     +---------+     +-----------+     +----------+
  | Finger |---->| Sensor  |---->| Feature   |---->| Template |
  |        |     | (scan)  |     | Extractor |     | Database |
  +--------+     +---------+     +-----------+     +----------+

  VERIFICATION:
  +--------+     +---------+     +-----------+
  | Finger |---->| Sensor  |---->| Feature   |---> Live Template
  +--------+     +---------+     +-----------+           |
                                                         v
                                                  +-----------+
  Template DB ---stored template----------------->| Matcher   |
                                                  +-----------+
                                                         |
                                                  Score > Threshold?
                                                   YES -> ACCEPT
                                                   NO  -> REJECT
```

### Real-World Example

The 2015 US Office of Personnel Management (OPM) breach exposed 5.6 million fingerprint records of government employees, including those with security clearances. Unlike passwords, these fingerprints cannot be reset. Affected individuals will carry this exposure for life.

Apple's Face ID uses a 3D infrared dot projector (30,000 dots) and a neural engine to create a mathematical representation of the face. The template is stored in the Secure Enclave (a hardware security module on the SoC) and never leaves the device. Apple quotes a FAR of 1 in 1,000,000 for Face ID vs 1 in 50,000 for Touch ID.

### Attack Vectors

| Attack | Description |
|--------|-------------|
| **Presentation attack (spoofing)** | Fake fingers (gelatin molds), printed photos, 3D-printed faces |
| **Template theft** | Stolen biometric templates from the server (OPM breach) |
| **Replay attack** | Injecting a previously captured biometric signal into the system |
| **Coercion** | Physically forcing someone to authenticate (legal: border agents can compel fingerprint unlock) |
| **Liveness detection bypass** | Defeating anti-spoofing measures with high-fidelity replicas |

### Interview Tip

> The key talking point is **non-revocability**. Always frame biometrics as "something you are" that should be used as one factor alongside something you know or have -- never as the sole authentication method. Mention that best practice is to store templates locally (on-device, like Apple's Secure Enclave) rather than centrally.

### References

- [NIST SP 800-76-2 - Biometric Specifications](https://csrc.nist.gov/publications/detail/sp/800-76/2/final)
- [FIDO Alliance - Biometrics](https://fidoalliance.org/how-fido-works/)

---

## 8. Password Management

### Explanation

Password-based authentication remains the most widespread method, despite its well-documented weaknesses. Effective password management encompasses password policies, storage (hashing), rotation strategies, and password managers.

**Password hashing:** Passwords must be stored as salted hashes using memory-hard functions:
- **bcrypt** -- adjustable work factor, 128-bit salt, widely supported
- **scrypt** -- memory-hard, configurable CPU and memory cost
- **Argon2id** -- winner of the Password Hashing Competition (2015), recommended by OWASP. Combines resistance to side-channel attacks (Argon2i) and GPU cracking (Argon2d).

**The rotation problem:** NIST SP 800-63B (2017) reversed decades of guidance by recommending **against** mandatory periodic password rotation. Research showed forced rotation leads to predictable patterns (Password1! -> Password2! -> Password3!), weaker passwords, and increased helpdesk costs. Rotation should occur only on evidence of compromise.

### How It Works (Password Locker / Manager)

1. User creates a master password to encrypt the password vault.
2. The vault key is derived from the master password using a KDF (PBKDF2, Argon2).
3. Each stored credential is encrypted with the vault key (AES-256-GCM typically).
4. When the user needs a password, they unlock the vault with the master password.
5. The manager auto-fills credentials and can generate high-entropy random passwords.
6. Cloud-synced vaults use zero-knowledge architecture: the server never sees the master password or unencrypted vault.

### Diagram

```
  USER REGISTRATION:
  password: "hunter2"
  salt: random(128bit) = 0xABCD...
  hash: Argon2id(password, salt, time=3, mem=64MB, threads=4)
  store: {username, salt, hash}

  USER LOGIN:
  input: "hunter2"
  retrieve: {salt, stored_hash} for username
  computed_hash: Argon2id(input, salt, time=3, mem=64MB, threads=4)
  compare: computed_hash == stored_hash?
    YES -> authenticated
    NO  -> rejected

  PASSWORD MANAGER ARCHITECTURE:
  +------------------+        +-------------------+
  | Master Password  |------->| KDF (Argon2)      |
  +------------------+        +-------------------+
                                       |
                                   Vault Key
                                       |
                               +-------v--------+
                               | Encrypted Vault |
                               | (AES-256-GCM)   |
                               |                 |
                               | site1: user/pass|
                               | site2: user/pass|
                               +-----------------+
```

### Real-World Example

The 2022 LastPass breach exposed encrypted password vaults. While the vaults were protected by master passwords, users with weak master passwords were vulnerable to brute-force attacks. LastPass's historical use of low PBKDF2 iteration counts (5,000 for older accounts vs. the recommended 600,000+) made offline cracking feasible for weak master passwords.

### Attack Vectors

| Attack | Description |
|--------|-------------|
| **Credential stuffing** | Using leaked username/password pairs from one breach to attack other services |
| **Password spraying** | Trying a few common passwords against many accounts to avoid lockout |
| **Brute force** | Exhaustive search, feasible for short or low-entropy passwords |
| **Rainbow tables** | Precomputed hash lookup (defeated by salting) |
| **Phishing** | Social engineering to capture passwords directly |
| **Keylogging** | Malware capturing keystrokes |
| **Master password compromise** | Single point of failure for password managers |

### Interview Tip

> Reference NIST 800-63B explicitly when discussing password policies. Know the key recommendations: minimum 8 characters, no composition rules, no mandatory rotation, check against breached password lists (haveibeenpwned), use Argon2id for hashing. This shows you follow current best practices, not outdated ones.

### References

- [NIST SP 800-63B - Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Have I Been Pwned](https://haveibeenpwned.com/)

---

## 9. U2F/FIDO

### Explanation

FIDO2 is a set of standards from the FIDO Alliance and W3C that enables strong, phishing-resistant authentication. It comprises:

- **WebAuthn** (W3C) -- the browser API for creating and using public key credentials.
- **CTAP2** (Client to Authenticator Protocol) -- communication between the browser and an external authenticator (e.g., YubiKey, platform biometrics).
- **U2F** (Universal 2nd Factor) -- the predecessor protocol, now subsumed by FIDO2/CTAP2.

Key properties:
- **Origin-bound** -- the credential is cryptographically bound to the website's origin (e.g., `https://example.com`). A phishing site at `https://examp1e.com` will not receive the credential. This is why FIDO2 is **phishing-resistant**.
- **Public key cryptography** -- the private key never leaves the authenticator. The server only stores the public key.
- **No shared secrets** -- unlike passwords or TOTP, there is no secret to steal from the server.

### How It Works

**Registration:**
1. User initiates registration; server sends a challenge + relying party ID (the origin).
2. Browser passes the challenge to the authenticator via CTAP2.
3. Authenticator generates a new key pair, stores the private key internally, and returns the public key + signed challenge.
4. Server stores the public key associated with the user's account.

**Authentication:**
1. Server sends a challenge + credential ID.
2. Browser passes the challenge to the authenticator.
3. Authenticator verifies the relying party ID matches the stored origin, signs the challenge with the private key.
4. Server verifies the signature with the stored public key.

### Diagram

```
  REGISTRATION:
  User        Browser             Authenticator (YubiKey)      Server
   |              |                        |                      |
   |--register--->|                        |                      |
   |              |--- request challenge --|---------------------->|
   |              |<-- challenge + rpId ---|----------------------|
   |              |--- create credential ->|                      |
   |              |   (challenge, rpId)    |                      |
   |              |                        |--generate keypair    |
   |              |                        |  store private key   |
   |              |<-- pubkey + signed ----|                      |
   |              |    challenge           |                      |
   |              |--- send attestation ---|--------------------->|
   |              |                        |                      |--store pubkey
   |<-- success --|                        |                      |

  AUTHENTICATION:
   |              |                        |                      |
   |--login------>|                        |                      |
   |              |--- request challenge --|---------------------->|
   |              |<-- challenge + credId -|----------------------|
   |              |--- sign challenge ---->|                      |
   |              |   (check rpId match)   |                      |
   |              |                        |--sign with privkey   |
   |              |<-- signed assertion ---|                      |
   |              |--- send assertion -----|--------------------->|
   |              |                        |                      |--verify signature
   |<-- success --|                        |                      |
```

### Real-World Example

Google deployed FIDO U2F security keys internally in 2017. After deploying keys to over 85,000 employees, Google reported **zero successful phishing attacks** against any employee using a security key. Previously, phishing was a persistent problem even with TOTP-based MFA. This result led Google to create the Titan Security Key product.

Passkeys (FIDO2 discoverable credentials) are now supported by Apple, Google, and Microsoft as a password replacement. They sync across devices via cloud keychain, making the YubiKey-style hardware token optional for consumer use cases.

### Attack Vectors

| Attack | Description |
|--------|-------------|
| **Physical theft of authenticator** | Attacker steals the YubiKey; mitigated by PIN/biometric on the key |
| **Supply chain attack** | Compromised authenticator firmware during manufacturing |
| **Downgrade attack** | Forcing fallback to a weaker authentication method (password + OTP) |
| **Authenticator cloning** | Theoretically possible with side-channel attacks on cheap hardware keys |
| **Social engineering** | Convincing user to register attacker's key on the account |

### Interview Tip

> The killer feature of FIDO2 is **origin binding** -- explain how the authenticator cryptographically verifies the site's origin, making phishing structurally impossible (not just harder). Contrast this with TOTP/SMS codes, which are trivially phishable since the user manually enters them on whatever site they're looking at.

### References

- [W3C WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [FIDO Alliance Specifications](https://fidoalliance.org/specifications/)
- [Google Security Blog - Security Keys](https://security.googleblog.com/2019/05/new-research-how-effective-is-basic.html)

---

## 10. Multi-Factor Auth Comparison

### Explanation

Multi-factor authentication (MFA) combines two or more factors from different categories:

- **Something you know** -- password, PIN
- **Something you have** -- hardware key, phone, smart card
- **Something you are** -- fingerprint, face, iris

The strength of MFA depends heavily on which factors and which implementations are used. Not all MFA is created equal.

### Comparison Matrix

| Method | Factor Type | Phishing Resistant | Replay Resistant | Offline Attack | User Experience | Cost |
|--------|-------------|-------------------|-----------------|----------------|----------------|------|
| SMS OTP | Have (phone) | No | Partially | N/A | Easy | Low |
| TOTP (Google Auth) | Have (device) | No | 30s window | N/A | Easy | Free |
| Push notification | Have (device) | Partially | Yes | N/A | Easy | Medium |
| FIDO2/WebAuthn | Have (key) | **Yes** | Yes | N/A | Easy | Medium |
| Smart card + PIN | Have + Know | Yes | Yes | PIN brute force | Moderate | High |
| Biometric + PIN | Are + Know | Partially | Yes | Template theft | Easy | Varies |

### Diagram: MFA Decision Matrix

```
  Is phishing your primary threat?
       |
       YES                          NO
       |                             |
  Use FIDO2/WebAuthn           Budget constraint?
       |                        |            |
   Hardware key              YES             NO
   (YubiKey) for             |               |
   high-value accounts    TOTP app      Push notification
                          (Authy,       (Duo, MS Authenticator
                           Google        with number matching)
                           Authenticator)
                                |
                          NEVER use SMS OTP
                          if alternatives exist
                                |
                          SMS OTP is better
                          than no MFA at all

  ATTACK RESISTANCE HIERARCHY:

  FIDO2 > Smart Card > Push (w/ number match) > TOTP > SMS > Password only
  |                                                              |
  Most resistant                                    Least resistant
```

### Real-World Example

The 2022 Uber breach demonstrated the weakness of push-based MFA. The attacker (a teenager from the Lapsus$ group) used **MFA fatigue** -- repeatedly sending push notifications to the victim's phone until the victim approved one to stop the bombardment. This is why Microsoft and Duo now require **number matching** in push notifications: the user must type a number displayed on the login screen into the phone app.

In contrast, Cloudflare was targeted by a similar phishing campaign in the same timeframe. Because Cloudflare required FIDO2 hardware keys, the attack failed entirely -- the phishing page could not obtain a valid FIDO2 assertion because the origin didn't match.

### Attack Vectors by MFA Type

| MFA Type | Attack | Mitigation |
|----------|--------|------------|
| SMS OTP | SIM swapping, SS7 interception | Don't use SMS; use TOTP or FIDO2 |
| TOTP | Real-time phishing proxy (evilginx2) | Use FIDO2 instead |
| Push | MFA fatigue bombing | Number matching, rate limiting |
| FIDO2 | Physical key theft | Require PIN on key, register backup keys |
| All MFA | Social engineering helpdesk to reset MFA | Strict identity verification for resets |

### Interview Tip

> Rank the MFA methods from weakest to strongest and explain **why**: SMS is weakest because it's phishable and vulnerable to SIM swaps. FIDO2 is strongest because it's cryptographically bound to the origin. The Uber (push fatigue) and Cloudflare (FIDO2 blocked phishing) incidents from 2022 are perfect contrasting case studies to cite.

### References

- [NIST SP 800-63B Section 5.1 - Authenticator Types](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5)
- [CISA MFA Guidance](https://www.cisa.gov/mfa)
- [OWASP MFA Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [Cloudflare Blog - Phishing Attack Thwarted by FIDO2](https://blog.cloudflare.com/2022-07-sms-phishing-attacks/)

---

## Key Takeaways

1. **Authentication is only as strong as its weakest factor.** SMS-based MFA is dramatically weaker than FIDO2, yet both are called "MFA."
2. **Bearer tokens (OAuth, cookies, session IDs) are like cash** -- whoever holds them can use them. Treat them with the same security posture as passwords.
3. **Certificates and PKI are foundational** but depend on the trustworthiness of CAs. Certificate Transparency is the modern safeguard against rogue issuance.
4. **Kerberos attacks (Golden/Silver Tickets, Kerberoasting) dominate Active Directory compromise.** Understanding these is essential for any enterprise security role.
5. **Biometrics cannot be rotated.** Use them as a local convenience factor, not as a sole remote authentication mechanism. Store templates on-device, never centrally.
6. **NIST 800-63B changed the game on passwords** -- no forced rotation, no composition rules, check against breached lists, use Argon2id.
7. **FIDO2/WebAuthn is the gold standard** for phishing-resistant authentication. Origin binding is the critical differentiator.
8. **Stateful sessions (server-side) support instant revocation; stateless tokens (JWT) do not.** Choose based on your threat model and architecture constraints.

## Interview Practice Questions

1. **Walk me through the TLS certificate validation process. What happens if one CA in the chain is compromised?**
   - Cover chain of trust, CRL/OCSP, and mention DigiNotar as the canonical CA compromise example.

2. **Explain the Kerberos Golden Ticket attack. How would you detect and mitigate it?**
   - Cover krbtgt hash compromise, TGT forging, detection via event log anomalies (4769), and mitigation via double krbtgt password rotation.

3. **Why is FIDO2 considered phishing-resistant while TOTP is not?**
   - Origin binding vs. user-entered codes. A real-time phishing proxy can relay TOTP codes but cannot obtain a FIDO2 assertion for a different origin.

4. **Compare server-side sessions vs. JWTs. When would you choose one over the other?**
   - Sessions: revocable, require a store. JWTs: stateless, scalable, but hard to revoke. Discuss the token blacklist/short-lived token tradeoff.

5. **A developer proposes storing OAuth access tokens in localStorage. What's your response?**
   - XSS can exfiltrate tokens. Recommend httpOnly cookies with SameSite=Lax for web apps, or use the Backend-for-Frontend (BFF) pattern.

6. **Your organization wants to deploy biometric authentication. What concerns do you raise?**
   - Non-revocability, template storage (on-device vs. central), liveness detection, legal/privacy considerations, FAR/FRR tradeoffs.

7. **Explain the difference between SAML and OpenID Connect. When would you recommend each?**
   - SAML: XML-based, enterprise SSO, mature but complex. OIDC: JSON/JWT, built on OAuth 2.0, developer-friendly, better for APIs and mobile.

8. **How does MFA fatigue work, and what are the mitigations?**
   - Repeated push notifications until user approves. Mitigations: number matching, rate limiting, anomaly detection, prefer FIDO2.

---

[Previous: Cryptography](cryptography.md) | [Next: Identity](identity.md)
