# Attack Structure - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#attack-structure)

> **Prerequisites:** [Exploits](exploits.md), [Networking](networking.md)  
> **Difficulty:** Intermediate to Advanced

---

## Table of Contents

1. [Overview](#overview)
2. [Phase 1 - Reconnaissance](#phase-1---reconnaissance)
3. [Phase 2 - Resource Development](#phase-2---resource-development)
4. [Phase 3 - Initial Access](#phase-3---initial-access)
5. [Phase 4 - Execution](#phase-4---execution)
6. [Phase 5 - Persistence](#phase-5---persistence)
7. [Phase 6 - Privilege Escalation](#phase-6---privilege-escalation)
8. [Phase 7 - Defense Evasion](#phase-7---defense-evasion)
9. [Phase 8 - Credential Access](#phase-8---credential-access)
10. [Phase 9 - Discovery](#phase-9---discovery)
11. [Phase 10 - Lateral Movement](#phase-10---lateral-movement)
12. [Phase 11 - Collection](#phase-11---collection)
13. [Phase 12 - Exfiltration](#phase-12---exfiltration)
14. [Phase 13 - Command and Control](#phase-13---command-and-control)
15. [Phase 14 - Impact](#phase-14---impact)
16. [Full Campaign Walkthrough - SolarWinds / SUNBURST](#full-campaign-walkthrough---solarwinds--sunburst)
17. [Key Takeaways](#key-takeaways)
18. [Interview Practice Questions](#interview-practice-questions)

---

## Overview

The MITRE ATT&CK framework organizes adversary behavior into **14 tactical phases** that represent the goals an attacker tries to achieve during an intrusion. These phases are not strictly linear -- attackers loop back, skip phases, and operate in multiple phases simultaneously. Understanding each phase, its associated techniques, and the detection opportunities it presents is foundational knowledge for any security engineer.

**Key principle:** Every phase is a detection opportunity. The more phases an attacker must traverse, the more chances defenders have to catch them.

---

## Phase 1 - Reconnaissance

**MITRE ATT&CK Tactic ID:** TA0043

### Explanation

Reconnaissance is the information-gathering phase where attackers identify targets, map attack surfaces, and collect data that will inform later phases. This happens before any contact with victim infrastructure. It splits into **passive** (no direct interaction with the target) and **active** (direct probing that could generate logs).

### Key Techniques

- **OSINT Collection (Passive):** Harvest employee names and email formats from LinkedIn, search public code repos for leaked credentials/API keys, scrape job postings to identify technologies in use.
- **Google Dorking (Passive):** `site:target.com filetype:pdf`, `intitle:"index of" site:target.com`, `inurl:admin site:target.com`.
- **Shodan / Censys Scanning:** Query internet-wide scan databases for exposed services, banners, SSL certs, and shadow IT assets.
- **DNS Enumeration (Active):** Zone transfers, subdomain brute-forcing, certificate transparency log mining. Tools: `subfinder`, `amass`, `crt.sh`.

### Real-World Example

**APT29 (Cozy Bear) - SolarWinds Campaign:** Before compromising SolarWinds, APT29 conducted extensive reconnaissance on SolarWinds' build infrastructure, developer workflows, and the Orion product's update mechanism. They identified that the Orion build process could be hijacked to distribute malicious code to thousands of customers.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1595 | Active Scanning |
| T1589 | Gather Victim Identity Information |
| T1590 | Gather Victim Network Information |
| T1593 | Search Open Websites/Domains |

### Interview Tip

> When asked about reconnaissance, demonstrate that you understand the attacker's perspective. Mention that defenders often underestimate this phase because it generates few or no logs on the victim side. Emphasize proactive measures: attack surface management, credential leak monitoring, and canary tokens.

### References

- [MITRE ATT&CK - Reconnaissance](https://attack.mitre.org/tactics/TA0043/)
- [OSINT Framework](https://osintframework.com/)

---

## Phase 2 - Resource Development

**MITRE ATT&CK Tactic ID:** TA0042

### Explanation

Resource Development is the phase where attackers acquire or build the infrastructure, tools, and capabilities needed for the operation. This includes setting up C2 servers, developing or purchasing malware, registering domains, compromising third-party accounts, and obtaining code signing certificates.

### Key Techniques

- **Infrastructure Acquisition:** Register typosquatting domains, purchase VPS with cryptocurrency, compromise legitimate websites as C2 redirectors, set up cloud infrastructure using stolen accounts.
- **Malware Development / Acquisition:** Develop custom malware, purchase commodity tools (Cobalt Strike, Brute Ratel, Sliver), modify open-source tools to evade signatures.
- **Compromised Accounts:** Purchase stolen credentials from dark web marketplaces, acquire valid cloud API keys from public code repos.
- **Staging:** Pre-position payloads on legitimate services (GitHub, Google Drive, Pastebin).

### Real-World Example

**APT29 - SolarWinds:** APT29 set up dedicated C2 infrastructure using hostnames that mimicked legitimate SolarWinds and Microsoft services (e.g., `avsvmcloud[.]com`). They registered domains months in advance and used legitimate cloud services (AWS, Azure) as part of their C2 chain to blend with normal traffic.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1583 | Acquire Infrastructure |
| T1584 | Compromise Infrastructure |
| T1587 | Develop Capabilities |
| T1588 | Obtain Capabilities |

### Interview Tip

> Resource Development is often overlooked in interviews. If you mention it, you demonstrate depth. Explain that understanding what the attacker does before touching your network is crucial for threat intelligence and proactive defense.

### References

- [MITRE ATT&CK - Resource Development](https://attack.mitre.org/tactics/TA0042/)
- [Mandiant APT29 Report](https://www.mandiant.com/resources/blog/tracking-apt29-phishing-campaigns)

---

## Phase 3 - Initial Access

**MITRE ATT&CK Tactic ID:** TA0001

### Explanation

Initial Access is where the attacker gains their first foothold inside the target environment. This is typically the most visible phase and the one defenders invest the most in preventing. The method chosen depends heavily on the intelligence gathered during reconnaissance.

### Key Techniques

- **Phishing (Spearphishing):** Malicious Office documents with macros, ISO/IMG files with LNK shortcuts, HTML smuggling, credential harvesting pages, targeting collaboration platforms (Slack, Teams).
- **Exploiting Public-Facing Applications:** Known vulns in VPNs (Pulse Secure, Fortinet), web servers, mail servers (ProxyShell, ProxyLogon), exposed management interfaces.
- **Supply Chain Compromise:** Inject malicious code into trusted vendor updates, compromise open-source packages (dependency confusion, typosquatting on npm/PyPI).
- **Valid Accounts:** Credential stuffing from previous breaches, default credentials, compromised VPN/SSO accounts.

### Real-World Example

**NotPetya (2017):** Initial access was achieved through a supply chain compromise of M.E.Doc, a Ukrainian tax accounting software. Attackers compromised the software update server and pushed a malicious update containing the NotPetya wiper. Every organization running M.E.Doc received the payload automatically.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1566 | Phishing |
| T1190 | Exploit Public-Facing Application |
| T1195 | Supply Chain Compromise |
| T1078 | Valid Accounts |

### Interview Tip

> Be prepared to discuss trade-offs. For example, "MFA stops credential stuffing but not real-time phishing proxies like Evilginx2 -- for that you need FIDO2/WebAuthn." Show you understand the arms race between attackers and defenders at each layer.

### References

- [MITRE ATT&CK - Initial Access](https://attack.mitre.org/tactics/TA0001/)
- [CISA Advisory on Pulse Secure](https://www.cisa.gov/news-events/cybersecurity-advisories)

---

## Phase 4 - Execution

**MITRE ATT&CK Tactic ID:** TA0002

### Explanation

Execution is where the attacker runs malicious code on the victim system. This is the transition from "I have access" to "I can do things." Techniques vary depending on the OS, available interpreters, and access level.

### Key Techniques

- **Command and Scripting Interpreters:** PowerShell (`powershell -enc <base64>`, AMSI bypass), Bash (`curl | bash`), Python/Perl/Ruby on Linux.
- **Scheduled Tasks / Cron Jobs:** `schtasks /create` on Windows, cron entries and systemd timers on Linux.
- **WMI:** `wmic process call create` for remote process spawning, WMI event subscriptions for fileless execution.
- **LOLBins:** `mshta.exe`, `regsvr32.exe`, `certutil.exe`, `rundll32.exe` for living-off-the-land execution.

### Real-World Example

**APT29 - SolarWinds:** The SUNBURST backdoor executed within the legitimate `SolarWinds.Orion.Core.BusinessLayer.dll`. Because it ran inside the trusted Orion process, it inherited all trust and permissions. The malicious code waited 12-14 days before activating, checking for analysis environments first.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1059 | Command and Scripting Interpreter |
| T1053 | Scheduled Task/Job |
| T1047 | Windows Management Instrumentation |
| T1204 | User Execution |

### Interview Tip

> When discussing execution, always tie it back to detection. "An attacker using PowerShell can be detected through script block logging (Event ID 4104), constrained language mode enforcement, and AMSI." This shows you think like a defender, not just an attacker.

### References

- [MITRE ATT&CK - Execution](https://attack.mitre.org/tactics/TA0002/)
- [LOLBAS Project](https://lolbas-project.github.io/)

---

## Phase 5 - Persistence

**MITRE ATT&CK Tactic ID:** TA0003

### Explanation

Persistence ensures the attacker maintains access even after reboots, credential changes, or partial remediation. Sophisticated attackers establish multiple persistence mechanisms across different systems so that removing one does not eliminate their access entirely.

### Key Techniques

- **Account Manipulation:** Create new admin accounts, add SSH keys to `authorized_keys`, modify existing accounts with backdoor recovery methods.
- **Startup Scripts and Registry:** Windows Run keys, Startup folder, GPO scripts. Linux `.bashrc`, systemd services, init scripts. macOS LaunchAgents/Daemons.
- **DLL Side-Loading:** Place a malicious DLL where a legitimate application searches for dependencies, executing attacker code in a trusted process context.
- **Webshells:** Deploy webshells (China Chopper, ASPX) on compromised web servers for persistent HTTP/S access.
- **UEFI / Firmware Implants:** Persist below the OS level, surviving reinstallation. Examples: LoJax, MosaicRegressor.

### Real-World Example

**APT28 (Fancy Bear) - LoJax:** APT28 deployed the first known UEFI rootkit in the wild. LoJax modified the system's UEFI firmware to ensure the malicious agent survived OS reinstalls and hard drive replacements.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1547 | Boot or Logon Autostart Execution |
| T1574 | Hijack Execution Flow (DLL Side-Loading) |
| T1505 | Server Software Component (Webshells) |
| T1542 | Pre-OS Boot (UEFI/Firmware) |

### Interview Tip

> Discuss persistence in layers. "A sophisticated adversary will establish persistence at the user level (scheduled tasks), system level (services), network level (webshells), and potentially firmware level. Remediation must address all layers, which is why 'nuke and rebuild' is often preferable to surgical cleanup."

### References

- [MITRE ATT&CK - Persistence](https://attack.mitre.org/tactics/TA0003/)
- [ESET - LoJax Analysis](https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild/)

---

## Phase 6 - Privilege Escalation

**MITRE ATT&CK Tactic ID:** TA0004

### Explanation

Privilege Escalation is where attackers elevate their permissions from a low-privilege foothold to administrative or root-level access. Without elevated privileges, the attacker's ability to move laterally and access sensitive data is severely limited.

### Key Techniques

- **Sudo / SUID Exploitation (Linux):** Misconfigured sudoers, abusable SUID binaries (GTFOBins), kernel exploits (Dirty Pipe CVE-2022-0847, Dirty COW CVE-2016-5195).
- **Token Manipulation (Windows):** Steal/impersonate tokens from higher-privileged processes, `SeImpersonatePrivilege` abuse (JuicyPotato, PrintSpoofer, GodPotato).
- **IAM / Cloud Privilege Escalation:** Exploit overly permissive IAM policies, assume roles via `sts:AssumeRole`, modify IAM policies to self-grant permissions, confused deputy attacks.
- **Container Escape:** Exploit privileged containers, mounted Docker sockets, or kernel vulnerabilities. Abuse Kubernetes RBAC misconfigurations.

### Real-World Example

**Capital One Breach (2019):** The attacker exploited an SSRF vulnerability in a WAF misconfiguration to access the EC2 instance metadata service. From there, they obtained temporary IAM credentials for a role with overly permissive S3 access, accessing over 100 million customer records without ever needing OS-level privilege escalation.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1548 | Abuse Elevation Control Mechanism (sudo, UAC bypass) |
| T1134 | Access Token Manipulation |
| T1068 | Exploitation for Privilege Escalation |
| T1611 | Escape to Host (container escape) |

### Interview Tip

> For cloud roles, emphasize IAM privilege escalation. "In cloud environments, privilege escalation is fundamentally an IAM problem. Tools like Pacu (AWS) and ScoutSuite enumerate excessive permissions. The principle of least privilege and regular IAM access reviews are the primary mitigations."

### References

- [MITRE ATT&CK - Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [GTFOBins](https://gtfobins.github.io/)

---

## Phase 7 - Defense Evasion

**MITRE ATT&CK Tactic ID:** TA0005

### Explanation

Defense Evasion encompasses all techniques attackers use to avoid detection by security tools, analysts, and automated systems. This is the broadest tactic in MITRE ATT&CK, reflecting the constant arms race between attackers and defenders.

### Key Techniques

- **Disable or Tamper with Logging:** Stop event log service, clear logs (`wevtutil cl`), disable Sysmon, kill EDR agents (Backstab, EDRSilencer, BYOVD).
- **Process Injection / Hollowing:** Create a legitimate process in suspended state and replace its memory, force DLL injection, thread hijacking, process doppelganging.
- **Obfuscation and Encoding:** Base64 encoding, custom packers/crypters, timestomping, rename system utilities.
- **AMSI Bypass (Windows):** Patch `amsi.dll` in memory, use obfuscation to evade AMSI signatures, reflective assembly loading.

### Real-World Example

**APT29 - SolarWinds:** SUNBURST checked for analysis tools and sandboxes before activating, used legitimate SolarWinds processes to blend in, communicated C2 via DNS mimicking legitimate Orion traffic, and waited 12-14 days to evade sandbox detonation. The build compromise tool (SUNSPOT) injected code only during compilation and replaced clean source afterward.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1562 | Impair Defenses |
| T1055 | Process Injection |
| T1027 | Obfuscated Files or Information |
| T1070 | Indicator Removal |

### Interview Tip

> "Defense evasion is why defense-in-depth matters. No single control is sufficient because attackers specifically engineer their tools to bypass each one. The key is overlapping detection -- if AMSI is bypassed, script block logging may still catch it. If both are bypassed, behavioral EDR heuristics might flag the anomaly."

### References

- [MITRE ATT&CK - Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
- [EDRSilencer and EDR Bypass Techniques](https://www.trendmicro.com/en_us/research.html)

---

## Phase 8 - Credential Access

**MITRE ATT&CK Tactic ID:** TA0006

### Explanation

Credential Access is where attackers steal authentication material -- passwords, hashes, tokens, tickets, and certificates. Credentials are the keys to lateral movement and privilege escalation. In Active Directory environments, a single domain admin credential can compromise the entire forest.

### Key Techniques

- **Password Spraying:** Try a few common passwords against many accounts (avoids lockout). Tools: Hydra, CrackMapExec.
- **Credential Dumping:** LSASS dump (Mimikatz, comsvcs.dll MiniDump), SAM database extraction, NTDS.dit via Volume Shadow Copy.
- **DCSync Attack:** Abuse Directory Replication Service to request password hashes from a DC. Mimikatz: `lsadump::dcsync /domain:corp.local /user:krbtgt` to retrieve the KRBTGT hash for Golden Ticket creation.
- **Kerberos Attacks:** Kerberoasting (request TGS for SPNs, crack offline), AS-REP Roasting, Golden Ticket (forge TGTs with KRBTGT hash), Silver Ticket (forge service tickets).

### Real-World Example

**NotPetya (2017):** NotPetya combined Mimikatz (credential dumping from LSASS) with EternalBlue (SMB exploit) for propagation. The credential harvesting component dumped credentials from each infected machine and used them to authenticate via WMI and PsExec, creating exponential spread even on patched systems.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1110 | Brute Force |
| T1003 | OS Credential Dumping |
| T1558 | Steal or Forge Kerberos Tickets |
| T1555 | Credentials from Password Stores |

### Interview Tip

> Kerberoasting is an interview favorite. Walk through it completely: "The attacker requests a TGS for any SPN. The ticket is encrypted with the service account's NTLM hash. The attacker takes it offline and cracks it with hashcat. Defense: use long, random passwords for service accounts (25+ chars), use Group Managed Service Accounts (gMSA), and monitor for anomalous TGS requests."

### References

- [MITRE ATT&CK - Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [Harmj0y - Kerberoasting](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)

---

## Phase 9 - Discovery

**MITRE ATT&CK Tactic ID:** TA0007

### Explanation

Discovery is the internal reconnaissance phase where the attacker maps the compromised environment -- users, groups, systems, network topology, security tools, and sensitive data locations. This information guides lateral movement decisions and ultimate objectives.

### Key Techniques

- **Network Scanning:** Internal port scanning (`nmap`, `masscan`), ARP scanning for live hosts, SNMP community string guessing.
- **Active Directory Enumeration:** `BloodHound` / `SharpHound` to map AD relationships and find shortest path to Domain Admin. `ldapsearch` / `ADFind` for users, groups, computers, GPOs, trusts.
- **Cloud Resource Discovery:** Enumerate S3 buckets, Azure blobs, IAM roles/policies. Tools: Pacu (AWS), ScoutSuite, Prowler.
- **Security Tool Discovery:** Identify EDR agents, SIEM forwarders, network monitoring to inform evasion techniques.

### Real-World Example

**APT29 - SolarWinds:** After SUNBURST activated, APT29 performed careful, slow discovery using native Windows tools to avoid detection, specifically targeting organizations with valuable intelligence and identifying high-value email accounts and ADFS servers as primary targets.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1046 | Network Service Discovery |
| T1087 | Account Discovery |
| T1082 | System Information Discovery |
| T1069 | Permission Groups Discovery |

### Interview Tip

> Mention BloodHound both offensively and defensively. "BloodHound is used by attackers to find attack paths to Domain Admin, but defenders should run it proactively to identify and eliminate those paths before attackers do. It's one of the most impactful tools for AD security hardening."

### References

- [MITRE ATT&CK - Discovery](https://attack.mitre.org/tactics/TA0007/)
- [BloodHound](https://github.com/SpecterOps/BloodHound)

---

## Phase 10 - Lateral Movement

**MITRE ATT&CK Tactic ID:** TA0008

### Explanation

Lateral Movement is how attackers move from one compromised system to others within the network. The goal is to reach systems containing target data or accounts with higher privileges. This phase heavily depends on credentials and network knowledge gathered previously.

### Key Techniques

- **Remote Services:** RDP (port 3389), SSH with stolen keys, SMB/Windows Admin Shares (`C$`, `ADMIN$`), WinRM/PSRemoting.
- **Pass-the-Hash (PtH):** Use a stolen NTLM hash to authenticate without the cleartext password. Tools: Mimikatz, CrackMapExec, Impacket.
- **Pass-the-Ticket (PtT):** Use stolen Kerberos tickets (TGT/TGS). Overpass-the-Hash converts NTLM hash to Kerberos ticket. Golden/Silver tickets provide forged authentication.
- **Exploitation of Remote Services:** Exploit internal vulns (EternalBlue, PrintNightmare, BlueKeep) on unpatched internal systems.

### Real-World Example

**NotPetya (2017):** NotPetya combined three lateral movement methods simultaneously: EternalBlue for unpatched systems, credential harvesting via Mimikatz with PsExec for patched systems, and WMI for additional reach. This multi-vector approach meant any single defense was insufficient.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1021 | Remote Services (RDP, SSH, SMB, WinRM) |
| T1550 | Use Alternate Authentication Material (PtH, PtT) |
| T1210 | Exploitation of Remote Services |
| T1563 | Remote Service Session Hijacking |

### Interview Tip

> "Lateral movement is where network segmentation proves its value. Microsegmentation, zero-trust network architecture, and tiered admin models (Red Forest / Enhanced Security Admin Environment) significantly increase the cost of lateral movement for attackers."

### References

- [MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [Microsoft - Enhanced Security Admin Environment](https://learn.microsoft.com/en-us/security/privileged-access-workstations/esae-retirement)

---

## Phase 11 - Collection

**MITRE ATT&CK Tactic ID:** TA0009

### Explanation

Collection is the phase where attackers gather the data they came for -- intellectual property, PII, financial data, credentials, emails, or strategic intelligence. The method depends on where the data resides and in what format.

### Key Techniques

- **Database Dumps:** SQL extraction from production databases, `mysqldump`/`pg_dump`, targeting analytics databases (often less monitored).
- **Email Collection:** Access mailboxes via Outlook/Exchange API or EWS, targeting executives, legal, finance, and IT admin mailboxes.
- **Internal Document Access:** Access SharePoint, Confluence, file shares, source code repositories.
- **Staged Collection:** Compress and encrypt into archives (7z, tar.gz with AES), stage centrally before exfiltration, split into chunks.

### Real-World Example

**APT29 - SolarWinds:** APT29 specifically targeted email systems via Microsoft Graph API and EWS. They also accessed SAML signing certificates from ADFS servers, enabling Golden SAML attacks to forge authentication tokens and access any cloud resource without additional credentials.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1005 | Data from Local System |
| T1114 | Email Collection |
| T1074 | Data Staged |
| T1560 | Archive Collected Data |

### Interview Tip

> "Collection is where DLP solutions shine, but they need proper tuning. The real defensive challenge is distinguishing between legitimate bulk data access (a DBA running reports) and attacker exfil staging. Behavioral baselines and user entity behavior analytics (UEBA) are essential."

### References

- [MITRE ATT&CK - Collection](https://attack.mitre.org/tactics/TA0009/)

---

## Phase 12 - Exfiltration

**MITRE ATT&CK Tactic ID:** TA0010

### Explanation

Exfiltration is the process of stealing collected data out of the victim environment. Attackers must balance speed (getting data out before detection) with stealth (avoiding network monitoring and DLP). The exfiltration channel is often different from the C2 channel.

### Key Techniques

- **Exfiltration Over C2 Channel:** Transmit data through the existing C2 connection. Simple but detectable due to increased volume.
- **Exfiltration Over Alternative Protocol:** DNS exfiltration (data encoded in subdomain queries, ~253 bytes per query), ICMP tunneling, HTTPS uploads to Google Drive/Dropbox/OneDrive.
- **Cloud Storage Exfiltration:** Sync data to attacker-controlled cloud storage, abuse installed cloud sync clients, cloud-to-cloud transfers from compromised SaaS.
- **Steganography:** Hide data within images, audio, or video files; embed in PDF metadata or EXIF data.

### Real-World Example

**APT1 (Comment Crew):** Mandiant's 2013 report documented APT1 exfiltrating terabytes of data from over 140 organizations using custom tools that compressed and encrypted data before sending over HTTP, using multiple simultaneous exfiltration channels with rotating C2 domains.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1041 | Exfiltration Over C2 Channel |
| T1048 | Exfiltration Over Alternative Protocol |
| T1567 | Exfiltration Over Web Service |
| T1537 | Transfer Data to Cloud Account |

### Interview Tip

> "DNS exfiltration is a classic interview topic. Explain how it works (data encoded in subdomain labels, limited to ~253 bytes per query), why it is effective (DNS is rarely blocked or inspected), and how to detect it (entropy analysis, query length thresholds, monitoring for high-frequency queries to newly registered domains)."

### References

- [MITRE ATT&CK - Exfiltration](https://attack.mitre.org/tactics/TA0010/)
- [Mandiant APT1 Report](https://www.mandiant.com/resources/apt1-exposing-one-of-chinas-cyber-espionage-units)

---

## Phase 13 - Command and Control

**MITRE ATT&CK Tactic ID:** TA0011

### Explanation

Command and Control (C2) is the communication channel between attacker infrastructure and compromised systems, allowing the attacker to issue commands, receive output, deploy tools, and coordinate the operation. C2 design is a critical factor in an operation's success.

### Key Techniques

- **Web Service-Based C2:** Use Slack, Discord, Telegram, GitHub as C2 intermediaries. Traffic blends with legitimate usage and uses trusted TLS certificates.
- **Domain Fronting / CDN Abuse:** Route C2 through legitimate CDNs so monitoring sees connections to trusted domains; actual destination is hidden in the HTTP Host header.
- **Protocol Tunneling:** Tunnel C2 over DNS, ICMP, or WebSockets for persistent bidirectional communication appearing as normal web traffic.
- **DGA (Domain Generation Algorithm):** Malware generates pseudo-random domain names daily; attacker only needs to register one.

### Real-World Example

**APT29 - SolarWinds (SUNBURST):** Multi-layer C2: initial DNS communication to `avsvmcloud.com` with encoded victim info as subdomain queries, then transition to HTTP-based C2 using legitimate-seeming API endpoints, then compromised Azure infrastructure and SAML token forgery to access targets directly through Microsoft 365 APIs.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1071 | Application Layer Protocol |
| T1573 | Encrypted Channel |
| T1568 | Dynamic Resolution (DGA, Fast Flux) |
| T1102 | Web Service |

### Interview Tip

> "When discussing C2 detection, talk about beacon analysis. Most C2 frameworks (Cobalt Strike, Sliver, Mythic) use a beaconing model where the implant checks in at regular intervals. Even with jitter, statistical analysis of connection intervals can identify C2 traffic. Tools like RITA (Real Intelligence Threat Analytics) automate this analysis on Zeek logs."

### References

- [MITRE ATT&CK - Command and Control](https://attack.mitre.org/tactics/TA0011/)
- [RITA - Real Intelligence Threat Analytics](https://github.com/activecm/rita)

---

## Phase 14 - Impact

**MITRE ATT&CK Tactic ID:** TA0040

### Explanation

Impact is the final phase where the attacker achieves their ultimate objective -- data destruction, service disruption, financial extortion, or manipulation of business operations. Not all operations reach this phase; espionage campaigns may operate indefinitely in the Collection phase.

### Key Techniques

- **Ransomware Deployment:** Encrypt files (AES-256 + RSA), delete Volume Shadow Copies, disable Windows Recovery, deploy ransom notes. Double/triple extortion: encrypt + exfiltrate + DDoS threat.
- **Data Destruction / Wiping:** Overwrite MBR/GPT partition tables, delete/corrupt databases and backups, use legitimate tools for plausible deniability.
- **Data Manipulation:** Subtly alter financial records, scientific data, or election systems without detection. More insidious than destruction.
- **Account Lockout / Access Disruption:** Mass password resets, revoke MFA tokens, delete cloud IAM roles and service accounts.

### Real-World Example

**NotPetya (2017):** Despite appearing as ransomware, NotPetya was a destructive wiper -- encryption was irreversible by design. It caused an estimated $10 billion in damages worldwide, crippling Maersk, Merck, FedEx/TNT, and Mondelez. Maersk rebuilt 45,000 PCs and 4,000 servers from scratch in 10 days.

### MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1486 | Data Encrypted for Impact (Ransomware) |
| T1485 | Data Destruction |
| T1490 | Inhibit System Recovery |
| T1565 | Data Manipulation |

### Interview Tip

> "When discussing ransomware defense, go beyond 'have backups.' Discuss immutable backups, backup testing, network segmentation to protect backup infrastructure, detection of pre-ransomware indicators (Cobalt Strike beacons, mass reconnaissance, shadow copy deletion), and incident response playbooks that include executive decision-making on ransom payment."

### References

- [MITRE ATT&CK - Impact](https://attack.mitre.org/tactics/TA0040/)
- [Wired - The Untold Story of NotPetya](https://www.wired.com/story/notpetya-cyberattack-ukraine-russia-code-crashed-the-world/)

---

## Full Campaign Walkthrough - SolarWinds / SUNBURST

This section maps the SolarWinds/SUNBURST campaign (APT29 / Cozy Bear / Nobelium, Russian SVR-linked) across all 14 MITRE ATT&CK phases. Discovered by FireEye in December 2020.

### Phase 1 - Reconnaissance

APT29 identified SolarWinds as a high-value target because Orion was deployed across ~18,000 organizations including US government agencies and cybersecurity firms. They studied the build process, development environment, and update distribution mechanism.

### Phase 2 - Resource Development

Registered `avsvmcloud[.]com` and built C2 mimicking legitimate SolarWinds communications. Developed custom malware: SUNBURST (backdoor), TEARDROP/Raindrop (loaders), and SUNSPOT (build system implant). Infrastructure hosted on US cloud services to avoid geolocation alerts.

### Phase 3 - Initial Access

Initial access to SolarWinds likely via compromised credentials. Subsequent victim access via supply chain: trojanized Orion update (versions 2019.4 HF 5 through 2020.2.1), digitally signed with SolarWinds' legitimate certificate.

### Phase 4 - Execution

SUNBURST executed within the legitimate `SolarWinds.Orion.Core.BusinessLayer.dll` as part of normal Orion startup. Code matched surrounding coding style. A 12-14 day dormancy period ensured sandboxes would not observe malicious behavior.

### Phase 5 - Persistence

Persistence was inherent in the supply chain compromise. In later stages, APT29 added persistence via Golden SAML token forgery, federation trusts, Azure AD application credentials, and new service principals.

### Phase 6 - Privilege Escalation

SUNBURST ran with SolarWinds Orion service privileges (typically highly privileged with broad network access). APT29 escalated further by compromising ADFS servers for SAML signing certificates, enabling impersonation of any user in cloud environments.

### Phase 7 - Defense Evasion

The most impressive aspect: code matched legitimate codebase style, SUNBURST checked for security tools before activating, SUNSPOT injected code only during compilation then replaced clean source, C2 mimicked legitimate Orion telemetry, and attackers used legitimate APIs throughout.

### Phase 8 - Credential Access

APT29 extracted SAML token signing certificates from ADFS servers for Golden SAML attacks, granting persistent cloud access without individual credentials. They also harvested credentials from memory for on-premises lateral movement.

### Phase 9 - Discovery

SUNBURST profiled victim environments via DNS and APT29 triaged victims to select high-value targets. In selected environments, they enumerated AD, identified key systems (ADFS, Exchange), and mapped cloud infrastructure.

### Phase 10 - Lateral Movement

Moved from Orion servers to ADFS servers and domain controllers using WMI, PowerShell remoting, and token-based authentication. In cloud environments, forged SAML tokens provided direct Microsoft 365 access.

### Phase 11 - Collection

Primary target was email via Microsoft 365 mailboxes of government and security firm personnel. Also accessed documents, code repos, and internal comms. At FireEye, they specifically targeted Red Team tools.

### Phase 12 - Exfiltration

Data exfiltrated through C2 channels and cloud APIs. Legitimate cloud infrastructure made exfiltration traffic appear as normal cloud communication. Volume and frequency were carefully limited.

### Phase 13 - Command and Control

Three-stage C2: (1) DNS CNAME queries to `avsvmcloud[.]com` for triage, (2) HTTPS C2 mimicking legitimate Orion API calls, (3) direct operation through legitimate cloud APIs using forged tokens.

### Phase 14 - Impact

Primarily an espionage operation. Strategic intelligence collection rather than disruption. Broader impact: exposed supply chain security weaknesses, forced massive incident response, led to Executive Order 14028, and cost SolarWinds ~$100 million.

### Key Lessons from the SolarWinds Campaign

| Lesson | Detail |
|---|---|
| Supply chain attacks bypass perimeter security | Traditional defenses are useless when malware arrives via trusted vendor updates. |
| Trust is the ultimate vulnerability | APT29 exploited trust at every level: software, certificates, protocols, cloud services. |
| Dwell time matters | Attackers operated undetected for ~9 months (March to December 2020). |
| Build systems are critical infrastructure | Compromise of SolarWinds' build pipeline was the key enabling factor. |

---

## Key Takeaways

1. **The kill chain is not linear.** Attackers loop between phases, revisit earlier stages, and operate in multiple phases simultaneously.

2. **Every phase is a detection opportunity.** The more phases an attacker must traverse, the more chances defenders have to detect them. This is why defense-in-depth remains the foundational security principle.

3. **Assume breach.** Modern security architecture should assume that initial access will eventually succeed and focus on limiting the blast radius through segmentation, least privilege, and rapid detection/response.

4. **Know the ATT&CK framework.** Being able to discuss specific technique IDs, map real incidents to the framework, and articulate detection strategies for each phase demonstrates the depth senior security roles require.

5. **Credentials are king.** Credential Access enables Lateral Movement, which enables Collection, which enables Impact. Protecting authentication material (MFA, Credential Guard, LAPS, gMSA, PAM) has outsized defensive value.

6. **Supply chain is the hardest problem.** SolarWinds demonstrated that you can do everything right and still be compromised through a trusted vendor.

## Interview Practice Questions

1. **Walk me through the MITRE ATT&CK kill chain. How does it differ from the Lockheed Martin Cyber Kill Chain?**
   - ATT&CK has 14 tactics vs. 7 in the Cyber Kill Chain. ATT&CK is non-linear and provides granular technique-level detail. The Cyber Kill Chain is more abstract and models a single intrusion linearly. ATT&CK includes post-exploitation phases in much more detail.

2. **You discover Cobalt Strike beacons on three workstations. Map out what likely happened using ATT&CK phases and describe your response for each phase.**
   - Initial Access (likely phishing or exploitation), Execution (beacon loader), Persistence (check for additional persistence mechanisms), C2 (analyze beacon config for C2 servers), Discovery (check if AD enumeration occurred), Credential Access (check for LSASS dumps), Lateral Movement (determine if the three workstations were independently compromised or if the attacker moved between them).

3. **How would you detect a Golden Ticket attack? Map it to the relevant ATT&CK phases.**
   - Credential Access (T1558.001): Monitor for DCSync (Event ID 4662 on domain controllers). Defense Evasion/Lateral Movement: Golden Tickets bypass normal authentication logging -- look for TGS requests without corresponding AS requests, anomalous ticket lifetimes, and logon events from impossible source systems.

4. **Describe three different methods an attacker could use to exfiltrate data from a network that has DLP on email and web traffic. How would you detect each?**
   - DNS exfiltration (detect via DNS entropy analysis), physical USB (detect via endpoint USB monitoring), cloud-to-cloud transfer from compromised SaaS (detect via CASB and cloud audit logs).

5. **An attacker has compromised a SolarWinds-like monitoring tool in your environment. What makes this particularly dangerous, and how would you respond?**
   - Monitoring tools typically have broad network access, credential storage, and elevated privileges. They are trusted by security tools and whitelisted in many detection rules. Response: isolate the monitoring infrastructure, assume all monitored systems are potentially compromised, reset all credentials the tool had access to, conduct forensic analysis of the monitoring server, and engage threat intelligence to determine if this is targeted or opportunistic.

6. **Explain Kerberoasting end-to-end: the technique, the prerequisites, the detection, and the mitigation.**
   - Any domain user can request a TGS for any SPN. The ticket is encrypted with the service account's NTLM hash. Offline cracking recovers the password. Detect: monitor for Event ID 4769 with encryption type 0x17 (RC4) from non-service accounts. Mitigate: long random passwords on service accounts, use AES encryption, gMSA accounts, honeypot SPNs.

7. **How does defense evasion affect your SIEM strategy? Give three specific examples of evasion techniques and how you would architect detection to be resilient against them.**
   - Log deletion (send logs to immutable storage immediately), AMSI bypass (layer with script block logging and ETW), EDR tampering (health-check heartbeats and canary processes that alert when killed).

---

[Previous: Exploits](exploits.md) | [Next: Threat Modelling](threat-modelling.md)
