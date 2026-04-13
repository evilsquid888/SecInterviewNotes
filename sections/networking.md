# Networking - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#networking)

> **Prerequisites:** Basic understanding of how computers communicate  
> **Difficulty:** Beginner to Advanced (varies by topic)

---

## Table of Contents

1. [OSI Model](#osi-model)
2. [Firewalls](#firewalls)
3. [NAT (Network Address Translation)](#nat-network-address-translation)
4. [DNS (Domain Name System)](#dns-domain-name-system)
5. [DNS Record Types and Configs](#dns-record-types-and-configs)
6. [DNS Exfiltration](#dns-exfiltration)
7. [ARP (Address Resolution Protocol)](#arp-address-resolution-protocol)
8. [DHCP (Dynamic Host Configuration Protocol)](#dhcp-dynamic-host-configuration-protocol)
9. [TCP vs UDP](#tcp-vs-udp)
10. [ICMP](#icmp)
11. [HTTP and HTTPS](#http-and-https)
12. [HTTP Request and Response Headers](#http-request-and-response-headers)
13. [SSL/TLS](#ssltls)
14. [SSH](#ssh)
15. [Telnet](#telnet)
16. [Mail Protocols (SMTP, IMAP, POP3)](#mail-protocols-smtp-imap-pop3)
17. [FTP and SFTP](#ftp-and-sftp)
18. [RPC (Remote Procedure Call)](#rpc-remote-procedure-call)
19. [Firewalls (Advanced)](#firewalls-advanced)
20. [VPN, Tor, and Proxy](#vpn-tor-and-proxy)
21. [BGP (Border Gateway Protocol)](#bgp-border-gateway-protocol)
22. [Nmap](#nmap)
23. [Traceroute](#traceroute)
24. [Person-in-the-Middle (PitM) Attacks](#person-in-the-middle-pitm-attacks)
25. [Network Traffic Analysis Tools](#network-traffic-analysis-tools)
26. [Multiplexing](#multiplexing)
27. [IRC and Botnets](#irc-and-botnets)
28. [Service Port Ranges](#service-port-ranges)
29. [UDP Header Structure](#udp-header-structure)
30. [Broadcast and Collision Domains](#broadcast-and-collision-domains)
31. [Root Stores and Certificate Authorities](#root-stores-and-certificate-authorities)
32. [CAM Table Overflow](#cam-table-overflow)

---

## OSI Model

### Explanation

The OSI model is a conceptual framework that standardises network communication into seven layers. While the TCP/IP model (4 layers) is what the internet actually uses, the OSI model remains the standard reference for discussing network concepts.

```
 Layer    Name            Protocols/Examples        PDU
 -----    ----            ------------------        ---
   7      Application     HTTP, DNS, SMTP, SSH      Data
   6      Presentation    SSL/TLS, JPEG, ASCII      Data
   5      Session         NetBIOS, RPC, SOCKS       Data
   4      Transport       TCP, UDP                  Segment/Datagram
   3      Network         IP, ICMP, IPsec           Packet
   2      Data Link       Ethernet, ARP, Wi-Fi      Frame
   1      Physical        Cables, Hubs, Fiber       Bits
```

### Security Implications

- **Layer 1 (Physical):** Wiretapping, physical cable interception, jamming wireless signals.
- **Layer 2 (Data Link):** ARP spoofing, MAC flooding (CAM table overflow), VLAN hopping.
- **Layer 3 (Network):** IP spoofing, ICMP attacks, route manipulation.
- **Layer 4 (Transport):** SYN floods, TCP session hijacking, port scanning.
- **Layer 7 (Application):** SQL injection, XSS, DNS poisoning, protocol-specific exploits.

Defenders apply security controls at each layer: physical locks at L1, 802.1X at L2, firewalls at L3/L4, WAFs at L7.

### Hands-On

```bash
# Capture packets showing all layers with tcpdump
sudo tcpdump -i eth0 -vvv -c 5
```

### Interview Tip

Interviewers love asking "Walk me through what happens when you type google.com into a browser." This touches every OSI layer. Start from Layer 7 (DNS resolution, HTTP request) and work down to Layer 1 (electrical signals on wire), then describe the reverse on the server side. Mention ARP resolution, TCP handshake, TLS negotiation, and DNS lookup.

### References

- [ISO/IEC 7498-1:1994 - OSI Basic Reference Model](https://www.iso.org/standard/20269.html)
- [RFC 1122 - Requirements for Internet Hosts](https://datatracker.ietf.org/doc/html/rfc1122)

---

## Firewalls

### Explanation

A firewall monitors and controls network traffic based on security rules. **Types:** Packet-filtering (L3/4, stateless), Stateful inspection (tracks connections in a state table), Application-layer/proxy (L7, inspects content), NGFW (firewall + IPS + DPI + application awareness). Rules are processed top-to-bottom; first match wins.

### Security Implications

Misconfigured or overly permissive rules negate the firewall. Rule ordering matters -- a broad ALLOW above a specific DENY renders the DENY useless. Evasion techniques include fragmentation, tunneling, and protocol encapsulation. Many orgs neglect egress filtering, allowing malware to communicate outbound freely.

### Hands-On

```bash
# List current iptables rules (Linux)
sudo iptables -L -v -n
```

### Interview Tip

Be ready to discuss the difference between stateful and stateless firewalls, and why default-deny is the recommended posture. Know the difference between ingress and egress filtering. Interviewers may ask you to design a firewall ruleset for a given scenario.

### References

- [NIST SP 800-41 Rev 1 - Guidelines on Firewalls and Firewall Policy](https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final)
- [iptables man page](https://linux.die.net/man/8/iptables)

---

## NAT (Network Address Translation)

### Explanation

NAT translates private (RFC 1918) IP addresses to public IPs, allowing many devices to share a single public IP. **Private ranges:** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`. **NAT types:** Static (1:1 mapping), Dynamic (pool of public IPs), PAT/NAT Overload (many:1 using ports, most common). **IPv6** makes NAT largely unnecessary since every device gets a globally routable address.

### Security Implications

NAT provides obscurity but is **not a security boundary** -- it is not a substitute for a firewall. NAT breaks end-to-end connectivity, complicating IPsec and P2P. IPv6 removes the NAT obscurity layer, making host-based firewalls and segmentation critical. In forensics, correlating a NAT gateway's public IP to the internal host requires the NAT translation table or DHCP logs.

### Hands-On

```bash
# View NAT translations on a Linux router
sudo iptables -t nat -L -v -n
```

### Interview Tip

The key point: NAT is an address translation mechanism, not a security control. Be ready to explain why IPv6 makes NAT less necessary and what new security considerations IPv6 introduces (globally routable addresses = larger attack surface).

### References

- [RFC 3022 - Traditional IP Network Address Translator](https://datatracker.ietf.org/doc/html/rfc3022)
- [RFC 8200 - IPv6 Specification](https://datatracker.ietf.org/doc/html/rfc8200)

---

## DNS (Domain Name System)

### Explanation

DNS translates domain names to IP addresses. It operates on **port 53** using **UDP** for standard queries and **TCP** for zone transfers and responses larger than 512 bytes. Resolution chain: browser cache -> OS cache/hosts file -> recursive resolver -> root NS (.) -> TLD NS (.com) -> authoritative NS -> returns IP.

**Reverse DNS:** Uses PTR records under `in-addr.arpa`. IP is reversed: `208.80.152.2` becomes `2.152.80.208.in-addr.arpa` (DNS lookups start at the end of the string). **DNS Sinkholes:** Return a false IP for known malicious domains to block malware C2 without touching the endpoint.

### Security Implications

**DNS cache poisoning (Kaminsky attack)** injects forged responses to redirect traffic. **DNS amplification DDoS** uses small spoofed queries to generate large responses at the victim. **DNSSEC** adds cryptographic signatures but adoption is incomplete. **DoH/DoT** encrypt queries but complicate network monitoring. Using raw IPs bypasses DNS entirely -- no DNS logs generated.

### Hands-On

```bash
# Trace the full DNS resolution path
dig +trace example.com
```

### Interview Tip

Know the full DNS resolution chain. Be prepared to explain DNS exfiltration, how DNS sinkholes work, why DNS uses UDP by default but falls back to TCP, and the security tradeoffs of DoH/DoT (privacy vs enterprise visibility). Also understand why PTR records have the IP reversed.

### References

- [RFC 1035 - Domain Names](https://datatracker.ietf.org/doc/html/rfc1035)
- [RFC 4033 - DNSSEC](https://datatracker.ietf.org/doc/html/rfc4033)

---

## DNS Record Types and Configs

### Explanation

| Record | Purpose | Example |
|--------|---------|---------|
| **SOA** | Start of Authority - defines the primary nameserver, admin email, zone serial number, and timing parameters | `example.com. SOA ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 86400` |
| **A** | Maps hostname to IPv4 address | `www.example.com. A 93.184.216.34` |
| **AAAA** | Maps hostname to IPv6 address | `www.example.com. AAAA 2606:2800:220:1:248:1893:25c8:1946` |
| **MX** | Mail exchanger - directs email to the correct mail server, with priority values | `example.com. MX 10 mail.example.com.` |
| **NS** | Nameserver - delegates a zone to a specific nameserver | `example.com. NS ns1.example.com.` |
| **PTR** | Pointer - reverse DNS, maps IP to hostname | `34.216.184.93.in-addr.arpa. PTR www.example.com.` |
| **CNAME** | Canonical name - alias that points one domain to another | `blog.example.com. CNAME www.example.com.` |
| **TXT** | Text records - used for SPF, DKIM, DMARC, domain verification | `example.com. TXT "v=spf1 include:_spf.google.com ~all"` |
| **SRV** | Service locator - specifies host and port for specific services | `_sip._tcp.example.com. SRV 10 5 5060 sip.example.com.` |

### Security Implications

- **CNAME hijacking (subdomain takeover):** If a CNAME points to a decommissioned service (e.g., old S3 bucket), an attacker can register that resource and serve content under your domain.
- **Zone transfers (AXFR):** If misconfigured, an attacker can download the entire DNS zone. Always restrict AXFR to authorized secondary nameservers.
- **TXT records** often leak information (SPF ranges, cloud providers). **NS delegation attacks** give attackers full control over domain resolution.

### Hands-On

```bash
# Attempt a zone transfer (tests for misconfiguration)
dig axfr @ns1.example.com example.com
```

### Interview Tip

Know the purpose of each record type cold. Be able to explain subdomain takeover attacks via dangling CNAMEs, and how SPF/DKIM/DMARC records in TXT entries protect against email spoofing.

### References

- [RFC 1035 - Domain Names](https://datatracker.ietf.org/doc/html/rfc1035)
- [RFC 7208 - SPF](https://datatracker.ietf.org/doc/html/rfc7208)

---

## DNS Exfiltration

### Explanation

DNS exfiltration encodes stolen data into DNS queries as subdomains. Because DNS is almost always allowed through firewalls, it is an attractive covert channel. Example: base64-encode data -> query `cGFzc3dvcmQ9UzNjcmV0IQ==.evil.com` -> attacker's authoritative NS logs the subdomain. This does NOT appear in HTTP logs. The attacker can also return commands via TXT records (C2 channel).

### Security Implications

Bypasses most firewalls since DNS is rarely blocked. Detection: unusually long subdomain labels, high query volume to a single domain, high entropy in hostnames. Tools like `iodine` and `dnscat2` automate full TCP-over-DNS tunneling.

### Hands-On

```bash
# Detect DNS exfiltration with tcpdump
sudo tcpdump -i eth0 port 53 -vv

# In Wireshark: filter with "dns.qry.name.len > 50"
```

### Interview Tip

Favorite interview topic. Know how it works, how to detect it (query length, entropy, volume anomalies), and why it is effective (DNS queries don't appear in HTTP logs, DNS is rarely blocked).

### References

- [SANS - Detecting DNS Tunneling](https://www.sans.org/white-papers/detecting-dns-tunneling/)

---

## ARP (Address Resolution Protocol)

### Explanation

ARP maps Layer 3 IP addresses to Layer 2 MAC addresses within a local network segment. Host broadcasts "Who has IP X?" and the owner replies with its MAC address. The result is cached. ARP operates only within a broadcast domain -- it does not cross routers.

### Security Implications

- **ARP Spoofing:** ARP has no authentication. Any host can send unsolicited ARP replies claiming to own any IP, poisoning other hosts' ARP caches and enabling Person-in-the-Middle attacks.
- **Defense:** Dynamic ARP Inspection (DAI) on managed switches, static ARP entries for critical hosts, `arpwatch` monitoring.

### Hands-On

```bash
# Detect ARP spoofing (look for duplicate IP -> different MAC)
sudo arpwatch -i eth0
```

### Interview Tip

Be able to explain why ARP spoofing works (no authentication in the protocol), how it enables PitM attacks, and what defenses exist. Know that ARP is Layer 2 only and does not work across routers.

### References

- [RFC 826 - An Ethernet Address Resolution Protocol](https://datatracker.ietf.org/doc/html/rfc826)

---

## DHCP (Dynamic Host Configuration Protocol)

### Explanation

DHCP automatically assigns IP addresses and network configuration parameters to hosts on a network. It uses **UDP port 67 (server)** and **UDP port 68 (client)**. For IPv6, DHCPv6 uses ports 546 (client) and 547 (server).

**Three allocation modes:**
- **Dynamic:** IP leased for a period, returned to pool when lease expires.
- **Automatic:** Router remembers MAC-to-IP pairings and re-assigns the same IP.
- **Manual (Static):** Administrator statically maps MAC addresses to specific IPs.

**DORA process:** Discover (client broadcasts) -> Offer (server proposes IP) -> Request (client accepts) -> Acknowledge (server confirms). Assigned parameters include IP address, subnet mask, default gateway, DNS servers, and lease duration.

### Security Implications

**DHCP Starvation** exhausts the IP pool with spoofed DHCPDISCOVER messages. **Rogue DHCP Server** hands out malicious config (attacker as gateway, malicious DNS). **Defense:** DHCP snooping creates a binding table and blocks rogue servers; port security limits MACs per port.

### Hands-On

```bash
# Release and renew DHCP lease
sudo dhclient -r eth0 && sudo dhclient eth0
```

### Interview Tip

Know the DORA process cold. Be ready to explain DHCP starvation and rogue DHCP server attacks plus their mitigations (DHCP snooping, port security).

### References

- [RFC 2131 - DHCP](https://datatracker.ietf.org/doc/html/rfc2131)

---

## TCP vs UDP

### Explanation

TCP (Transmission Control Protocol) and UDP (User Datagram Protocol) are the two primary Layer 4 transport protocols.

| Feature | TCP | UDP |
|---------|-----|-----|
| Connection | Connection-oriented (3-way handshake) | Connectionless |
| Reliability | Guaranteed delivery, ordering, retransmission | Best-effort, no guarantees |
| Flow control | Yes (sliding window) | No |
| Congestion control | Yes (throttles on packet loss) | No |
| Header size | 20-60 bytes | 8 bytes |
| Speed | Slower (overhead) | Faster (minimal overhead) |
| Use cases | HTTP, SSH, SMTP, FTP | DNS, VoIP, streaming, gaming, DHCP |

### How It Works

**TCP Three-Way Handshake:**

```
Client                    Server
  |                          |
  |------ SYN ------------->|   Seq=100
  |                          |
  |<----- SYN-ACK ---------|   Seq=300, Ack=101
  |                          |
  |------ ACK ------------->|   Seq=101, Ack=301
  |                          |
  |== Connection Established ==|
```

### Security Implications

- **SYN Flood:** Sends many SYNs without completing handshake, filling the half-open connection table. Mitigation: SYN cookies.
- **TCP Session Hijacking:** Predicting sequence numbers allows injecting packets into active sessions.
- **UDP amplification:** No handshake makes source IP spoofing trivial, enabling massive DDoS (DNS, NTP, memcached).
- **TCP RST attacks:** Injecting RST packets to tear down connections (used in censorship).

The 2018 memcached DDoS reached 1.7 Tbps via UDP amplification -- small spoofed requests generated responses 50,000x larger.

### Hands-On

```bash
# See active TCP/UDP connections
ss -tuln

# Capture TCP handshake
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0' -c 20
```

### Interview Tip

Know the three-way handshake sequence numbers. Explain why UDP is used for DNS (speed, small queries) and when DNS falls back to TCP (responses > 512 bytes, zone transfers). Understand SYN floods and SYN cookies. Be able to explain why streaming over UDP can degrade TCP performance on shared networks.

### References

- [RFC 793 - TCP](https://datatracker.ietf.org/doc/html/rfc793)
- [RFC 768 - UDP](https://datatracker.ietf.org/doc/html/rfc768)

---

## ICMP

### Explanation

Internet Control Message Protocol (ICMP) is a Layer 3 protocol used for diagnostic and error-reporting purposes. It does not carry application data. Common uses include `ping` (Echo Request/Reply) and `traceroute`.

**Key ICMP message types:**
- Type 0: Echo Reply
- Type 3: Destination Unreachable
- Type 5: Redirect
- Type 8: Echo Request
- Type 11: Time Exceeded (used by traceroute)

### Security Implications

- **ICMP Flood/Smurf attack:** Overwhelming a target with Echo Requests.
- **ICMP Tunneling:** Encoding data in ICMP payloads for covert channels (tools: `icmptunnel`, `ptunnel`).
- **Reconnaissance:** Ping sweeps reveal live hosts; many orgs block ICMP at the perimeter (`nmap -Pn` skips ping discovery).

### Hands-On

```bash
# Ping sweep a subnet to find live hosts
nmap -sn 192.168.1.0/24
```

### Interview Tip

Know the difference between ICMP types used in ping vs traceroute. Understand why some networks block ICMP and the implications (Path MTU Discovery breaks without ICMP Type 3 Code 4).

### References

- [RFC 792 - ICMP](https://datatracker.ietf.org/doc/html/rfc792)

---

## HTTP and HTTPS

### Explanation

HTTP (Hypertext Transfer Protocol) operates on **port 80** and transmits data in cleartext. HTTPS operates on **port 443** and wraps HTTP inside a TLS tunnel, providing confidentiality, integrity, and authentication.

**HTTP Methods:** GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT.

### Security Implications

HTTP transmits everything in cleartext. **HTTPS stripping** downgrades connections to HTTP (`sslstrip`); defense is HSTS. Mixed content (HTTP resources on HTTPS pages) can expose data. HTTP verb tampering (PUT/DELETE) may bypass WAFs that only check GET/POST.

### Hands-On

```bash
# Make an HTTPS request and inspect headers/certificate
curl -vI https://example.com
```

### Interview Tip

Know HTTP methods, status codes (especially 200, 301, 302, 400, 401, 403, 404, 500, 503), and security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options). Be prepared to explain the full HTTPS connection flow including DNS lookup, TCP handshake, TLS handshake, and HTTP request.

### References

- [RFC 9110 - HTTP Semantics](https://datatracker.ietf.org/doc/html/rfc9110)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

---

## HTTP Request and Response Headers

### Explanation

**HTTP Request Structure:**

```
GET /index.html HTTP/1.1        <-- Verb | Path | HTTP Version
Host: www.example.com           <-- Domain
Accept: text/html,application/xhtml+xml
Accept-Language: en-US,en;q=0.9
Accept-Charset: utf-8
Accept-Encoding: gzip, deflate  <-- Compression type
Connection: keep-alive           <-- keep-alive or close
Referer: https://google.com     <-- Where the request came from
User-Agent: Mozilla/5.0 ...     <-- Browser identification
Cookie: session=abc123           <-- Session cookies
Content-Length: 0                <-- Expected size of body
```

**HTTP Response Structure:**

```
HTTP/1.1 200 OK                 <-- HTTP Version | Status Code
Content-Type: text/html; charset=utf-8   <-- Type of data
Content-Encoding: gzip                    <-- Encoding
Content-Language: en                      <-- Language
Content-Length: 1256                       <-- Size of body
Set-Cookie: session=xyz789; Secure; HttpOnly
Strict-Transport-Security: max-age=31536000
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

**Status Code Categories:**

| Range | Category | Common Codes |
|-------|----------|-------------|
| 1xx | Informational | 100 Continue, 101 Switching Protocols |
| 2xx | Success | 200 OK, 201 Created, 204 No Content |
| 3xx | Redirection | 301 Moved Permanently, 302 Found, 304 Not Modified |
| 4xx | Client Error | 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found |
| 5xx | Server Error | 500 Internal Server Error, 502 Bad Gateway, 503 Service Unavailable |

### Security Implications

User-Agent is trivially spoofed. Referer headers can leak sensitive URL parameters to third parties. Missing security headers (HSTS, CSP, X-Frame-Options) enable downgrade, clickjacking, and XSS attacks. Cookies without `Secure`, `HttpOnly`, and `SameSite` flags are vulnerable to interception and CSRF.

### Interview Tip

Be able to sketch out a request and response from memory. Know which headers are security-critical and why. Understand the difference between 401 (authentication required) and 403 (authenticated but not authorized).

---

## SSL/TLS

### Explanation

SSL (Secure Sockets Layer) and its successor TLS (Transport Layer Security) provide encrypted communication over networks. TLS operates on **port 443** for HTTPS. SSL is deprecated -- only TLS 1.2 and TLS 1.3 should be used in production.

### How It Works

**TLS 1.2 Handshake:**

```
Client                                Server
  |                                      |
  |--- ClientHello ------------------->|  (supported ciphers, random, TLS version)
  |                                      |
  |<-- ServerHello --------------------|  (chosen cipher, random, session ID)
  |<-- Certificate --------------------|  (server's X.509 certificate)
  |<-- ServerKeyExchange ---------------|  (DH parameters if using DHE/ECDHE)
  |<-- ServerHelloDone ----------------|
  |                                      |
  |--- ClientKeyExchange -------------->|  (pre-master secret, encrypted with server pubkey)
  |--- ChangeCipherSpec --------------->|  (switching to encrypted communication)
  |--- Finished ---------------------->|  (encrypted verify)
  |                                      |
  |<-- ChangeCipherSpec ----------------|
  |<-- Finished ------------------------|
  |                                      |
  |==== Encrypted Application Data =====|
```

**TLS 1.3** reduces the handshake to 1-RTT (or 0-RTT for resumed sessions) and removes insecure ciphers. The handshake uses **asymmetric encryption** (ECDHE) to exchange a **symmetric session key** (AES-GCM, ChaCha20-Poly1305) because symmetric encryption is orders of magnitude faster.

### Security Implications

**Historical TLS/SSL vulnerabilities:**

| Vulnerability | Year | What It Attacks | Summary |
|--------------|------|-----------------|---------|
| **POODLE** | 2014 | SSLv3 | Padding oracle attack on CBC mode in SSLv3. Forces protocol downgrade then exploits padding. Fix: disable SSLv3. |
| **BEAST** | 2011 | TLS 1.0 | Exploits predictable IVs in CBC mode. Fix: use TLS 1.1+ or RC4 (later deprecated too). |
| **CRIME** | 2012 | TLS compression | Uses response size differences to guess session cookies byte-by-byte. Fix: disable TLS compression. |
| **BREACH** | 2013 | HTTP compression | Similar to CRIME but targets HTTP-level compression. Harder to mitigate. |
| **HEARTBLEED** | 2014 | OpenSSL | Buffer over-read in heartbeat extension leaked up to 64KB of server memory per request (private keys, passwords). Fix: patch OpenSSL. CVE-2014-0160. |

### Hands-On

```bash
# Test TLS configuration and view certificate details
openssl s_client -connect example.com:443 </dev/null 2>/dev/null | openssl x509 -text -noout

# Test for weak ciphers with nmap
nmap --script ssl-enum-ciphers -p 443 example.com
```

### Interview Tip

This is one of the most important topics. Be able to walk through the TLS handshake step by step. Know why asymmetric crypto is used for key exchange but symmetric crypto is used for data transfer. Be able to explain each major vulnerability (POODLE, BEAST, CRIME, BREACH, HEARTBLEED) in one or two sentences. Know the difference between TLS 1.2 and 1.3.

### References

- [RFC 8446 - TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [Heartbleed.com](https://heartbleed.com/)

---

## SSH

### Explanation

SSH (Secure Shell) provides encrypted remote access and operates on **port 22**. It replaced Telnet and rlogin by providing confidentiality and integrity for remote sessions.

Like TLS, SSH uses **asymmetric encryption** (Diffie-Hellman key exchange) to establish a **symmetric session key** for data encryption. The client verifies the server's host key against `known_hosts` (TOFU model), then authenticates via password, public key, or certificate.

### Security Implications

SSH on port 22 is heavily targeted for brute force -- use key-based auth, disable password auth, use fail2ban. SSH tunneling/port forwarding can be used legitimately or by attackers for exfiltration and pivoting. Skipping host key verification opens the door to PitM attacks.

### Hands-On

```bash
# Generate SSH key pair (Ed25519)
ssh-keygen -t ed25519 -C "user@example.com"

# SSH with local port forwarding (tunneling)
ssh -L 8080:internal-server:80 user@jump-host
```

### Interview Tip

Understand the key exchange process, why asymmetric is used to bootstrap symmetric encryption, and what happens when you connect to a host for the first time (TOFU - Trust On First Use). Know how SSH tunneling works for both legitimate and malicious purposes.

### References

- [RFC 4253 - SSH Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4253)

---

## Telnet

### Explanation

Telnet provides remote command-line access on **port 23** (or 992 for Telnet over TLS). Unlike SSH, Telnet transmits everything in **cleartext**, including credentials.

### Security Implications

- All data sent in plaintext -- trivially intercepted.
- Still found in legacy systems, IoT devices, network equipment.
- The Mirai botnet (2016) exploited default Telnet credentials on IoT devices to build a massive DDoS botnet.
- **Telnet should never be used in production.** Always use SSH instead.

### Hands-On

```bash
# Test if Telnet is open on a host (for recon, not for use)
nmap -p 23 target.com
```

### Interview Tip

Know why Telnet is insecure and what replaced it (SSH). Mention the Mirai botnet as a real-world example of Telnet exploitation at scale.

---

## Mail Protocols (SMTP, IMAP, POP3)

### Explanation

| Protocol | Ports | Purpose |
|----------|-------|---------|
| **SMTP** | 25 (relay), 587 (submission), 465 (SMTPS) | Sending email between servers and from client to server |
| **IMAP** | 143, 993 (TLS) | Retrieving email, messages stay on server, supports folders |
| **POP3** | 110, 995 (TLS) | Retrieving email, typically downloads and deletes from server |

### Security Implications

Open SMTP relays enable spam. SMTP has no built-in sender authentication -- defenses are SPF, DKIM, DMARC. Unencrypted IMAP/POP3 expose passwords on the wire. Attackers set up SMTP servers with valid SPF/DKIM for convincing phishing.

### Hands-On

```bash
# Check SPF, DKIM, and DMARC records
dig example.com TXT | grep spf
dig _dmarc.example.com TXT
```

### Interview Tip

Know the ports for each protocol and their secure variants. Be able to explain SPF, DKIM, and DMARC and how they work together to prevent email spoofing. Understand the difference between IMAP and POP3.

### References

- [RFC 5321 - SMTP](https://datatracker.ietf.org/doc/html/rfc5321)

---

## FTP and SFTP

### Explanation

- **FTP** (port 21 for control, port 20 for data in active mode): File transfer protocol. Sends credentials and data in cleartext. Uses two connections: control channel and data channel.
- **SFTP** (port 22): SSH File Transfer Protocol. Runs over SSH, providing encryption for both authentication and data transfer. Not the same as FTPS (FTP over TLS).

### Security Implications

FTP credentials are sent in cleartext. Anonymous FTP servers can leak sensitive files. Always prefer SFTP or SCP over FTP.

### Hands-On

```bash
# Check for anonymous FTP (common misconfiguration)
nmap --script ftp-anon -p 21 target.com
```

---

## RPC (Remote Procedure Call)

### Explanation

RPC allows a program to execute a procedure on a remote server as if it were a local function call. The client sends a request with function name and parameters; the server executes and returns the result.

Common implementations: Sun RPC (ONC RPC), DCE/RPC (used by Windows for SMB, DCOM), gRPC (modern, uses HTTP/2 and Protocol Buffers).

### Security Implications

RPC services often run with elevated privileges. Windows RPC vulnerabilities have been devastating (MS08-067/Conficker, MS03-026/Blaster, PrintNightmare). RPC should not be exposed to the internet.

### Hands-On

```bash
# Enumerate RPC services
rpcinfo -p target
nmap -sV -p 135 --script=msrpc-enum target
```

---

## VPN, Tor, and Proxy

### Explanation

**VPN (Virtual Private Network):**
Encrypts traffic between the client and VPN server, creating a secure tunnel. Traffic is hidden from the local network and ISP but is fully visible to the VPN provider. Common protocols: WireGuard, OpenVPN, IPsec/IKEv2.

**Tor (The Onion Router):**
Routes traffic through three relays (guard, middle, exit), with each layer of encryption removed at each hop. Provides anonymity but not end-to-end encryption (exit node can see unencrypted traffic to non-HTTPS sites).

**Proxy:**
Intermediary server that forwards requests. Types: HTTP proxy, SOCKS proxy, transparent proxy. Unlike a VPN, a proxy typically handles specific application traffic, not all system traffic.

### Security Implications

- **VPN:** Trust shifts from ISP to VPN provider. "No-log" claims are unverifiable. VPN does not equal anonymity.
- **Tor:** Exit nodes can sniff unencrypted traffic. Law enforcement deanonymizes users via traffic correlation, browser exploits, and operational security mistakes -- not by breaking the crypto.
- **Proxy chains:** Each proxy is a point of failure. Timing correlation and legal compulsion make chains unreliable for anonymity.

### Hands-On

```bash
# Set up a SOCKS proxy via SSH and test
ssh -D 1080 user@remote-server
curl --socks5 127.0.0.1:1080 https://ifconfig.me
```

### Interview Tip

Understand the trust model differences. VPN shifts trust, Tor distributes trust, proxies provide no inherent trust. Know how law enforcement deanonymizes Tor users (not by breaking crypto, but through operational mistakes, browser exploits, and traffic correlation).

---

## BGP (Border Gateway Protocol)

### Explanation

BGP is the routing protocol that holds the internet together. It exchanges routing information between Autonomous Systems (ASes) -- large networks operated by ISPs, enterprises, and cloud providers. BGP runs on **TCP port 179**.

BGP is a **path-vector** protocol: each route advertisement includes the full AS path, which is used for loop detection and routing decisions.

### Security Implications

**BGP Hijacking:** An AS announces routes it doesn't own, diverting traffic -- no built-in authentication. **BGP Leak:** Accidental re-announcement causing unintended routing. **Defense:** RPKI allows prefix owners to cryptographically authorize originating ASes. BGP hijacking has been used for cryptocurrency theft, traffic interception, and surveillance.

In 2018, a BGP hijack redirected Amazon Route 53 DNS traffic to steal cryptocurrency from MyEtherWallet users. In 2008, Pakistan Telecom accidentally hijacked YouTube's prefix, causing a global outage.

### Hands-On

```bash
# Look up BGP/ASN information for an IP
whois -h whois.radb.net 93.184.216.34
```

### Interview Tip

Know that BGP is trust-based with no built-in authentication, making it vulnerable to hijacking. Understand the difference between a BGP hijack and a BGP leak. Mention RPKI/ROA as the emerging defense. This topic demonstrates understanding of internet-scale infrastructure.

### References

- [RFC 4271 - BGP-4](https://datatracker.ietf.org/doc/html/rfc4271)
- [RFC 6480 - RPKI](https://datatracker.ietf.org/doc/html/rfc6480)

---

## Nmap

### Explanation

Nmap (Network Mapper) is the most widely used network scanning tool. It discovers hosts, services, operating systems, and vulnerabilities on a network.

### Key Scan Types

| Scan | Flag | How It Works | Use Case |
|------|------|-------------|----------|
| TCP Connect | `-sT` | Full TCP handshake | Default unprivileged scan |
| SYN Scan | `-sS` | Sends SYN, waits for SYN-ACK (half-open) | Default privileged scan, stealthier |
| UDP Scan | `-sU` | Sends UDP packets, waits for ICMP unreachable | Discover UDP services |
| ACK Scan | `-sA` | Sends ACK, checks for RST | Map firewall rules |
| FIN/Xmas/Null | `-sF/-sX/-sN` | Sends unusual flag combinations | Evade some firewalls |
| Ping Scan | `-sn` | No port scan, just host discovery | Find live hosts |
| Version Detection | `-sV` | Probes open ports for service/version | Identify running software |
| OS Detection | `-O` | Analyzes TCP/IP stack fingerprint | Identify operating system |

### Hands-On

```bash
# SYN scan with version detection, OS detection, output to all formats
sudo nmap -sS -sV -O -oA scan_results 192.168.1.1

# Scan all 65535 ports
nmap -p- 192.168.1.1

# Run vulnerability scripts
nmap --script vuln 192.168.1.1
```

### Security Implications

Port scanning is often the first step in an attack. Defenders use nmap for asset discovery. IDS/IPS detect scans; attackers use timing options (-T0 to -T5) and decoys to evade detection.

### Interview Tip

Know the difference between SYN scan and TCP connect scan. Understand what each port state means (open, closed, filtered, unfiltered). Be comfortable with common nmap flags and when to use them.

### References

- [Nmap Official Documentation](https://nmap.org/book/man.html)
- [Nmap NSE Scripts](https://nmap.org/nsedoc/)

---

## Traceroute

### Explanation

Traceroute maps the network path from source to destination by exploiting the TTL (Time To Live) field in IP packets. Each router that forwards a packet decrements the TTL by 1. When TTL reaches 0, the router sends back an ICMP Time Exceeded (Type 11) message.

Traceroute sends packets with incrementing TTL values; each router that decrements TTL to 0 replies with ICMP Time Exceeded, revealing the path. **Linux** uses UDP by default (ICMP with `-I`, TCP SYN with `-T`); **Windows `tracert`** uses ICMP. Default TTL differs by OS (Windows=128, Linux=64), useful for OS fingerprinting.

### Security Implications

Reveals internal network topology. Some networks block traceroute by filtering ICMP Time Exceeded. Attackers use it to map paths and find firewall boundaries.

### Hands-On

```bash
# TCP SYN traceroute (useful when UDP/ICMP is blocked)
sudo traceroute -T -p 443 example.com
```

### Interview Tip

Know the three protocols traceroute can use (UDP, ICMP, TCP SYN). Understand TTL/hop-limit mechanics and the default TTL differences between Windows (128) and Linux (64) for OS fingerprinting.

---

## Person-in-the-Middle (PitM) Attacks

### Explanation

A PitM attack occurs when an attacker secretly intercepts and potentially modifies communication between two parties who believe they are communicating directly. The attacker is positioned between the victim and the legitimate destination.

### Attack Vectors

| Method | Layer | Technique |
|--------|-------|-----------|
| ARP Spoofing | L2 | Poison ARP cache to redirect local traffic |
| DNS Spoofing | L7 | Return false DNS responses |
| DHCP Spoofing | L3 | Rogue DHCP server sets attacker as gateway |
| BGP Hijacking | L3 | Divert internet-scale traffic |
| SSL Stripping | L7 | Downgrade HTTPS to HTTP |
| Rogue Wi-Fi AP | L1/L2 | Evil twin access point |

PKI is the primary defense: the client verifies the server's certificate is signed by a trusted CA, so an attacker cannot substitute their own certificate without triggering a warning. Certificate pinning and HSTS provide additional protection.

### Hands-On

```bash
# Verify TLS certificate manually
openssl s_client -connect example.com:443 | openssl x509 -noout -issuer -subject
```

### Interview Tip

Always connect PitM attacks back to the defense mechanisms: PKI, certificate validation, HSTS, DNSSEC. Know multiple attack vectors at different layers. Interviewers like to ask "How does TLS prevent PitM?" -- the answer is certificate verification through the PKI trust chain.

---

## Network Traffic Analysis Tools

### Explanation

**Wireshark:** GUI-based packet analyzer. Captures and interactively analyzes network traffic with powerful filtering, protocol dissection, and visualization.

**Tcpdump:** Command-line packet analyzer. Lightweight, available on nearly all Unix systems. Uses Berkeley Packet Filter (BPF) syntax.

**Burp Suite:** Web application security testing proxy. Intercepts, inspects, and modifies HTTP/S traffic between browser and server. Used for web app pentesting, not general network analysis.

### Hands-On

```bash
# Capture traffic to a file for Wireshark analysis
sudo tcpdump -i eth0 -w capture.pcap

# Capture HTTP traffic in ASCII (shows cleartext content)
sudo tcpdump -i eth0 -A port 80 -c 50

# Key Wireshark display filters:
#   tcp.flags.syn == 1          (TCP handshakes)
#   ip.addr == 192.168.1.100    (traffic to/from IP)
#   http.request.method == "POST" (HTTP POSTs)
#   tls.handshake               (TLS negotiation)
```

### Interview Tip

Be comfortable describing when you would use each tool. Tcpdump for quick command-line captures and scripted analysis. Wireshark for deep interactive analysis with protocol dissection. Burp Suite specifically for web application testing. Know basic BPF filter syntax for tcpdump.

### References

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [tcpdump man page](https://www.tcpdump.org/manpages/tcpdump.1.html)

---

## Multiplexing

### Explanation

Multiplexing allows multiple signals or data streams to share a single communication channel.

**Time-Division Multiplexing (TDM):** Each connection gets a fixed time slot. Simple but wasteful if a slot goes unused.

**Statistical Multiplexing:** Bandwidth is allocated dynamically based on demand. More efficient than TDM because idle connections don't waste capacity. Used in packet-switched networks (the internet).

### Security Implications

In shared multiplexed channels, side-channel attacks may be possible by analyzing timing and bandwidth usage patterns, even without reading the actual data.

### Interview Tip

This is a minor topic. Just know the difference between time-division and statistical multiplexing and that the internet uses statistical multiplexing (packet switching). You likely won't be asked about this in depth.

---

## IRC and Botnets

### Explanation

IRC (Internet Relay Chat) is a text-based communication protocol from 1988. While legitimate use has declined, IRC remains historically significant in security because it was the dominant Command and Control (C2) mechanism for botnets for over a decade.

Bots connect to a predefined IRC server/channel, and the botmaster issues commands (DDoS, spam, data theft) through the channel.

### Security Implications

Modern botnets use HTTP/S, P2P, DNS, and Tor for C2 to blend in. IRC traffic on a corporate network is a strong IoC since legitimate use is rare. Detectable by monitoring IRC ports (6667, 6697).

### Interview Tip

Know the evolution of botnet C2: IRC -> HTTP -> P2P -> DNS -> Tor/encrypted channels. Each evolution makes detection harder. Mention specific botnets: Storm (P2P), Zeus (HTTP), Mirai (Telnet propagation, custom C2).

---

## Service Port Ranges

### Explanation

TCP and UDP port numbers range from 0 to 65535, divided into three ranges:

| Range | Name | Description |
|-------|------|-------------|
| **0 - 1023** | Well-Known / System Ports | Reserved for common services. Binding requires root/admin privileges on most OS. |
| **1024 - 49151** | Registered Ports | Assigned by IANA to specific services upon request. No root required. |
| **49152 - 65535** | Dynamic / Ephemeral Ports | Used for temporary client-side connections. Assigned by the OS. |

**Common well-known ports:**

| Port | Service | Protocol |
|------|---------|----------|
| 20/21 | FTP (data/control) | TCP |
| 22 | SSH / SFTP | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | TCP/UDP |
| 67/68 | DHCP | UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 143 | IMAP | TCP |
| 443 | HTTPS | TCP |
| 445 | SMB | TCP |
| 3389 | RDP | TCP |

### Security Implications

Services on well-known ports require root privileges -- a compromise gives root access. Attackers run services on non-standard ports to evade detection.

### Interview Tip

Memorize common port numbers. Interviewers frequently ask "what port does X run on?" Know why well-known ports require root and the security implications.

### References

- [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/)

---

## UDP Header Structure

### Explanation

The UDP header is minimal at just 8 bytes, reflecting UDP's simplicity:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Data (payload)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Four fields, 8 bytes total: source port, destination port, length, and checksum. Compare to TCP's 20-60 byte header -- UDP's simplicity is what makes it fast but unreliable.

### Interview Tip

Be able to draw the UDP header from memory. Know why it is so small (no connection state, no reliability) and contrast it with the TCP header.

---

## Broadcast and Collision Domains

### Explanation

**Collision Domain:** A network segment where data collisions can occur if two devices transmit simultaneously. In modern switched networks, each switch port is its own collision domain (switches solved the collision problem).

**Broadcast Domain:** A network segment where a broadcast frame reaches all devices. A broadcast domain is bounded by routers (Layer 3 devices). Switches and hubs do not break broadcast domains.

Each switch port is its own collision domain. Each VLAN/router segment is a broadcast domain.

### Security Implications

Large broadcast domains increase the attack surface for ARP/DHCP attacks. VLANs segment broadcast domains, limiting Layer 2 attack reach.

### Interview Tip

Know that hubs share a collision domain, switches separate collision domains but share broadcast domains, and routers separate broadcast domains. This is a fundamental networking concept that interviewers use to test foundational knowledge.

---

## Root Stores and Certificate Authorities

### Explanation

A **root store** is a collection of trusted root CA (Certificate Authority) certificates built into browsers, operating systems, and applications. When a server presents a TLS certificate, the client traces the certificate chain back to a root CA in its trust store.

The certificate chain goes: Root CA (self-signed, in trust store) -> Intermediate CA -> Server Certificate -> domain.

**Major root store programs:**
- Mozilla NSS (Firefox)
- Microsoft Root Certificate Program (Windows/Edge)
- Apple Root Certificate Program (macOS/iOS/Safari)
- Google Chrome Root Store

### Security Implications

A compromised root CA can issue certificates for any domain, enabling PitM attacks (DigiNotar, 2011). Certificate Transparency (CT) logs provide public auditing. Organizations can add their own root CAs for TLS inspection (corporate proxy), effectively enabling authorized PitM.

### Interview Tip

Understand the certificate chain of trust. Know what happens if a root CA is compromised (DigiNotar is the canonical example). Be able to explain Certificate Transparency and certificate pinning as additional defenses.

### References

- [Mozilla CA Certificate Policy](https://wiki.mozilla.org/CA)
- [Certificate Transparency](https://certificate.transparency.dev/)

---

## CAM Table Overflow

### Explanation

A CAM (Content Addressable Memory) table in a network switch maps MAC addresses to physical switch ports. The table has a finite size. In a **CAM table overflow** (MAC flooding) attack, the attacker floods the switch with frames containing thousands of fake source MAC addresses, filling the CAM table.

When the CAM table fills with fake entries, the switch can't learn new legitimate MACs and fails open -- flooding all traffic to all ports like a hub, allowing the attacker to sniff all VLAN traffic. Attack tool: `macof` (dsniff suite).

### Security Implications

Turns a switch into a hub, enabling traffic sniffing. Often precedes ARP spoofing or PitM. **Defense:** Port security (limit MACs per port), 802.1X, VLAN segmentation.

### Hands-On

```bash
# Detect MAC flooding with tcpdump (look for massive broadcast traffic)
sudo tcpdump -i eth0 ether broadcast -c 1000
```

### Interview Tip

Know the attack mechanism (fill CAM table -> switch floods -> attacker sniffs). Know the defense (port security). This demonstrates understanding of Layer 2 security, which is a gap for many candidates.

---

## Key Takeaways

- **OSI model is the framework** -- every attack and defense maps to one or more layers.
- **DNS is essential and exploitable** -- cleartext by default, enables exfiltration, almost always allowed through firewalls.
- **TLS is the most important defensive protocol** -- know the handshake, historical vulns (POODLE, BEAST, HEARTBLEED), and why TLS 1.3 is better.
- **Layer 2 attacks are underestimated** -- ARP spoofing, CAM overflow, DHCP spoofing are devastating and often poorly defended.
- **BGP has no built-in authentication** -- route hijacking remains a persistent internet-scale threat.
- **Always think both sides** -- for every protocol, know how attackers exploit it AND how defenders protect it.
- **Encryption shifts trust, not eliminates it** -- VPNs shift to provider, TLS to CAs, Tor distributes across relays.

## Interview Practice Questions

1. **Walk me through what happens when a user types `https://google.com` into a browser.** (DNS, ARP, TCP handshake, TLS handshake, HTTP -- the "grand unifying question.")
2. **An analyst sees unusually long DNS queries to a single external domain. What's happening?** (DNS exfiltration, investigation methodology.)
3. **How would you detect and prevent a PitM attack on a corporate LAN?** (ARP/DHCP spoofing, PKI, HSTS, DAI, DHCP snooping.)
4. **Explain the TLS 1.2 handshake and how HEARTBLEED worked.** (TLS mechanics, asymmetric vs symmetric crypto.)
5. **Your org suspects BGP hijacking. How do you confirm and mitigate?** (BGP, RPKI, incident response.)
6. **Design a firewall ruleset for a web app with public web server, internal DB, and SSH jump box.** (Least privilege, default-deny, rule ordering.)

---

[Previous: Interviewing Tips](interviewing-tips.md) | [Next: Web Application](web-application.md)
