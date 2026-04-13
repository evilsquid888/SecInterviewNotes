# Digital Forensics - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#digital-forensics)

> **Prerequisites:** [OS Systems](os-systems.md), [Detection](detection.md)  
> **Difficulty:** Intermediate to Advanced

---

## Table of Contents

1. [Evidence Volatility](#evidence-volatility)
2. [Network Forensics](#network-forensics)
3. [Disk Forensics](#disk-forensics)
4. [Memory Forensics](#memory-forensics)
5. [Mobile Forensics](#mobile-forensics)
6. [Anti-Forensics](#anti-forensics)
7. [Chain of Custody](#chain-of-custody)
8. [Key Takeaways](#key-takeaways)
9. [Interview Practice Questions](#interview-practice-questions)

---

## Evidence Volatility

### Explanation

The **order of volatility** (RFC 3227) dictates which evidence sources must be collected first because they disappear the fastest. Failing to respect this order means losing critical artifacts permanently.

| Priority | Source | Persistence | Example Artifacts |
|----------|--------|-------------|-------------------|
| 1 | CPU registers, cache | Nanoseconds | Current instruction pointer |
| 2 | Routing tables, ARP cache, process table | Seconds | `arp -a`, `netstat -an` |
| 3 | RAM / System memory | Minutes (power-dependent) | Running processes, encryption keys, network connections |
| 4 | Temporary filesystems | Minutes to hours | `/tmp`, pagefile, swap |
| 5 | Disk / persistent storage | Days to years | Files, logs, registry hives |
| 6 | Remote logging and monitoring | Days to years (policy-dependent) | SIEM data, Netflow, DNS logs |
| 7 | Physical configuration, network topology | Archival | Rack diagrams, VLAN configs |
| 8 | Backups and archival media | Years | Tape backups, cold storage |

### Command/Tool Example

Quick live-state capture on Linux before imaging:

```bash
# Network state
netstat -antup > /mnt/evidence/netstat.txt
arp -a > /mnt/evidence/arp_cache.txt

# Memory acquisition (using LiME)
insmod /mnt/tools/lime.ko "path=/mnt/evidence/memory.lime format=lime"

# Hash all collected artifacts
sha256sum /mnt/evidence/* > /mnt/evidence/hashes.sha256
```

### Real-World Example

In the **2013 Target breach**, volatile network data helped trace lateral movement from the HVAC vendor to POS systems. Without live-state capture, the in-memory RAM scraper and C2 connections would have been permanently lost.

### Best Practices

- Always collect from most volatile to least volatile; use a forensically clean external drive.
- Run collection tools from trusted external media, never from the suspect system's own binaries.
- Hash every artifact at collection time and again upon analysis to prove integrity.

### Interview Tip

When asked about evidence collection order, cite **RFC 3227** by name. Interviewers want to hear that you understand *why* the order matters (data loss) and not just *what* the order is.

### References

- RFC 3227 - Guidelines for Evidence Collection and Archiving
- NIST SP 800-86 - Guide to Integrating Forensic Techniques

---

## Network Forensics

### Explanation

Network forensics is the capture, recording, and analysis of network traffic to detect intrusions, data exfiltration, and lateral movement. Unlike disk evidence, network evidence is **transient by default** -- if you are not already capturing it, it is gone. Key data sources include full packet capture (PCAP) for highest fidelity, NetFlow/IPFIX for metadata at scale, DNS logs for C2/DGA/tunneling detection, passive DNS (pDNS) for historical resolutions, proxy/firewall logs for URL-level visibility, and Zeek logs for structured protocol-level analysis.

### Command/Tool Example

**Zeek log analysis for DNS tunneling:**

```bash
# Find suspiciously long DNS queries (potential tunneling)
cat dns.log | zeek-cut query | awk '{ if (length($1) > 60) print $1 }' | sort | uniq -c | sort -rn | head -20

# tcpdump: capture DNS traffic live
tcpdump -i eth0 -w /evidence/dns_capture.pcap port 53

# Query Farsight DNSDB for historical resolutions
curl -s -H "X-API-Key: $DNSDB_KEY" \
  "https://api.dnsdb.info/lookup/rrset/name/suspicious-domain.com" | jq .
```

### Real-World Example

The **SolarWinds (SUNBURST)** investigation relied heavily on passive DNS to map C2 domains. The malware encoded victim identifiers in subdomain queries to `avsvmcloud[.]com`, making DNS logs the primary IOC.

### Best Practices

- Retain DNS logs for a minimum of 90 days (1 year ideal); deploy Zeek at egress points.
- Use unsampled NetFlow where possible; encrypt and hash PCAP files immediately upon capture.

### Interview Tip

Be prepared to discuss the **tradeoff between PCAP and NetFlow**: PCAP gives full content but is expensive; NetFlow gives metadata at scale. A mature SOC uses both: NetFlow for broad visibility and hunting, PCAP for targeted deep-dives on suspicious flows.

### References

- SANS SEC503 - Intrusion Detection In-Depth
- Zeek documentation: https://docs.zeek.org

---

## Disk Forensics

### Explanation

Disk forensics involves the acquisition, preservation, and analysis of data stored on persistent media (HDDs, SSDs, USB drives, etc.). A forensic image is a **bit-for-bit copy** of the entire device including unallocated and slack space, created in formats like raw (dd/dc3dd), E01 (EnCase/FTK Imager), or AFF4. Key filesystem artifacts include the NTFS MFT/$UsnJrnl/$LogFile, ext3/4 journals, and APFS snapshots. File carving recovers files from unallocated space using magic bytes, and slack space can contain remnants of deleted files. SSD TRIM complicates recovery as trimmed blocks may be zeroed before acquisition.

**Key Log Sources:**

| Platform | Log | Location | Content |
|----------|-----|----------|---------|
| Windows | Security Event Log | `Security.evtx` | Logons (4624/4625), privilege use |
| Windows | PowerShell Logs | `Microsoft-Windows-PowerShell%4Operational.evtx` | Script block logging |
| Linux | auth.log / secure | `/var/log/auth.log` | SSH logins, sudo usage |
| Linux | syslog / journal | `/var/log/syslog` or `journalctl` | System events |

### Command/Tool Example

**Forensic imaging with dc3dd:**

```bash
# Create forensic image with hashing
dc3dd if=/dev/sdb of=/evidence/case001/disk.dd \
  hash=sha256 log=/evidence/case001/imaging.log
```

**Timeline analysis with plaso/log2timeline:**

```bash
# Extract timestamps into plaso storage file
log2timeline.py --storage-file /evidence/case001/timeline.plaso \
  /evidence/case001/disk.dd

# Filter and export to CSV
psort.py -o l2tcsv /evidence/case001/timeline.plaso \
  "date > '2026-03-01' AND date < '2026-04-01'" \
  -w /evidence/case001/timeline_march.csv
```

**Key Windows Event IDs:** 4624 (logon), 4625 (failed logon), 4648 (explicit credential/pass-the-hash), 4672 (admin logon), 4688 (process creation), 7045 (service installed).

### Real-World Example

In the **BTK Killer** case (2005), forensic examiners recovered a deleted Word document from a floppy disk. Metadata revealed the author name "Dennis" and "Christ Lutheran Church," directly leading to Dennis Rader's arrest.

### Best Practices

- **Always use a write-blocker** (hardware preferred); create two independent forensic images.
- Work only on copies; use **plaso/log2timeline** for super-timeline creation.
- For SSDs, image as quickly as possible; TRIM and garbage collection destroy evidence over time.

### Interview Tip

Know the difference between **allocated space**, **unallocated space**, **slack space**, and **volume slack**. Be able to explain why an examiner might find evidence in each. Also be ready to discuss why SSD forensics is harder than HDD forensics (TRIM, wear leveling, controller-level encryption).

### References

- SANS FOR500 - Windows Forensic Analysis
- Eric Zimmerman's Tools: https://ericzimmerman.github.io

---

## Memory Forensics

### Explanation

Memory forensics is the analysis of a computer's volatile memory (RAM) to extract artifacts that exist only at runtime. It is essential for detecting fileless malware, recovering encryption keys, identifying injected code, and understanding the exact state of a system at the time of capture. Key acquisition concepts include **memory smear** (RAM changes during dump), **acquisition footprint** (tool itself overwrites memory), and alternative sources like `hiberfil.sys`, `pagefile.sys`/swap, and crash dumps (`MEMORY.DMP`).

**Key Memory Structures (Windows):**

| Structure | Purpose | Forensic Value |
|-----------|---------|----------------|
| EPROCESS | Process descriptor | Process list, PID, PPID, creation time, image name |
| PEB | Per-process user-mode data | Command line, environment variables, loaded DLLs |
| VAD tree | Memory region map | Injected code detection (RWX regions), mapped files |
| Handle Table | Open handles | Open files, registry keys, network connections |

User space contains per-process code/heap/stack; kernel space (shared across processes) contains the OS kernel, drivers, and kernel objects where rootkits operate. Forensic tools translate virtual addresses to physical addresses using page tables.

### Command/Tool Example

**Volatility 3 Commands (most asked in interviews):**

```bash
# Identify the OS and recommend plugins
vol3 -f /evidence/memory.raw windows.info

# List all processes (EPROCESS linked list traversal)
vol3 -f /evidence/memory.raw windows.pslist

# Scan for processes including hidden/unlinked ones (DKOM detection)
vol3 -f /evidence/memory.raw windows.psscan

# Network connections (like netstat from the dead)
vol3 -f /evidence/memory.raw windows.netscan

# Detect injected code (VAD regions with PAGE_EXECUTE_READWRITE)
vol3 -f /evidence/memory.raw windows.malfind

# Extract command-line arguments for all processes
vol3 -f /evidence/memory.raw windows.cmdline

# Check registry Run keys for persistence
vol3 -f /evidence/memory.raw windows.registry.printkey \
  --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Dump a suspicious process for analysis
vol3 -f /evidence/memory.raw windows.pslist --pid 4892 --dump
```

**Linux memory acquisition with LiME:**

```bash
# Acquire memory (output to external media)
insmod lime.ko "path=/mnt/usb/memory.lime format=lime compress=no"

# Analyze with Volatility 3
vol3 -f /mnt/usb/memory.lime linux.pslist
vol3 -f /mnt/usb/memory.lime linux.bash  # recover bash history from memory
```

### Real-World Example

The **Stuxnet** investigation (2010) was a landmark case for memory forensics. Volatility's `malfind` identified RWX regions with injected payloads in `lsass.exe` and `services.exe`, while `psscan` vs `pslist` comparison revealed rootkit-hidden processes.

### Best Practices

- **Acquire memory before disk**; always run both `pslist` and `psscan` (the delta reveals hidden processes).
- Use `malfind` on every investigation; injected code is the most common modern malware technique.
- Build a profile matching the exact OS version and patch level; keep symbol tables updated.

### Interview Tip

Know the difference between `pslist` (walks the EPROCESS linked list, misses unlinked processes) and `psscan` (scans physical memory for EPROCESS pool tags, finds hidden processes). This is the classic "how do you detect a rootkit using DKOM?" question. Also be prepared to explain what `malfind` looks for: VAD entries with `PAGE_EXECUTE_READWRITE` protection that contain PE headers, which indicates injected code.

### References

- Volatility Foundation: https://volatilityfoundation.org
- The Art of Memory Forensics (Hale Ligh, Case, Levy, Walters)

---

## Mobile Forensics

### Explanation

Mobile forensics presents unique challenges due to hardware diversity, encryption-by-default, cloud synchronization, and platform-specific security architectures. Evidence is split between device, cloud (iCloud/Google), and carrier. Acquisition methods range from logical (app-level backup) to physical (bit-for-bit) to chip-off (destructive, last resort).

**Android vs. iPhone Forensics:**

| Feature | Android | iPhone (iOS) |
|---------|---------|--------------|
| Encryption | FDE or FBE since Android 7+ | Data Protection (hardware-bound keys) since iOS 8 |
| Acquisition | ADB backup (limited), root, chip-off, JTAG | iTunes backup, Cellebrite/GrayKey, checkm8 (A5-A11) |
| Cloud evidence | Google Takeout | iCloud warrants, Apple legal process |

**checkm8 (iOS):** A bootrom exploit for A5-A11 chips that enables forensic extraction without modifying the filesystem -- forensically preferred. Jailbreaking/rooting grants full filesystem access but **modifies the device**, which defense attorneys can challenge.

### Command/Tool Example

**Android acquisition via ADB:**

```bash
adb devices
adb backup -apk -shared -all -f /evidence/android_backup.ab

# Extract specific app database (requires root)
adb shell su -c "cp /data/data/com.whatsapp/databases/msgstore.db /sdcard/"
adb pull /sdcard/msgstore.db /evidence/whatsapp.db
```

**iOS extraction with libimobiledevice:**

```bash
idevicepair pair
idevicebackup2 backup --full /evidence/ios_backup/
ideviceinfo > /evidence/device_info.txt
```

### Real-World Example

In the **San Bernardino case (2016)**, the FBI used a third-party exploit to bypass an iPhone 5c lock screen after Apple refused to assist. This case highlighted the tension between law enforcement access and device encryption.

### Best Practices

- **Faraday bag immediately** upon seizure to prevent remote wipe; document device state with photographs.
- Use the least invasive acquisition method; always acquire cloud data in parallel via legal process.

### Interview Tip

Be ready to discuss the **acquisition hierarchy** (logical < filesystem < physical < chip-off) and when each is appropriate. Also understand checkm8's significance: it is a hardware-level (bootrom) vulnerability that cannot be patched via software, making it a reliable forensic tool for affected devices.

### References

- SANS FOR585 - Smartphone Forensic Analysis In-Depth
- NIST SP 800-101 Rev 1 - Guidelines on Mobile Device Forensics

---

## Anti-Forensics

### Explanation

Anti-forensics encompasses techniques used by attackers to hinder forensic investigation by destroying, hiding, or manipulating evidence. Key techniques include process injection (detect with `malfind`), fileless malware via PowerShell/WMI (detect with memory forensics and script block logs), rootkits using DKOM (detect with `psscan` vs `pslist` delta), DLL side-loading, bootkits, and living-off-the-land binaries (LOLBins like certutil, mshta, regsvr32).

**Timestomping:**

Timestomping is the deliberate modification of file timestamps to mislead forensic timeline analysis. Attackers modify MACE values (Modified, Accessed, Created, Entry-modified) to make malicious files appear old or blend in with legitimate system files.

- **NTFS dual timestamps:** NTFS stores timestamps in both the `$STANDARD_INFORMATION` (SI) attribute and the `$FILE_NAME` (FN) attribute. Common timestomping tools only modify SI timestamps. Comparing SI vs FN timestamps reveals tampering.
- **Detection:** If the `$STANDARD_INFORMATION` Created timestamp is *older* than the `$FILE_NAME` Created timestamp, timestomping has occurred (because FN is set at file creation and is harder to modify).

Other techniques include log clearing (leaves Event ID 1102), secure deletion (SDelete, shred), encryption of payloads/C2, steganography, and trail obfuscation via Tor/VPNs.

### Command/Tool Example

**Detecting timestomping with Volatility 3 and MFTECmd:**

```bash
# Extract MFT from forensic image
vol3 -f /evidence/memory.raw windows.mftscan.MFTScan > /evidence/mft_entries.txt

# Use Eric Zimmerman's MFTECmd for detailed analysis
MFTECmd.exe -f '$MFT' --csv /evidence/ --csvf mft_parsed.csv

# In the CSV output, compare these columns:
# SI_Created vs FN_Created
# If SI_Created < FN_Created --> TIMESTOMPING DETECTED
# (Because $FILE_NAME created timestamp is set when the file
#  is actually created and is much harder to modify)
```

**Detecting log clearing and fileless malware:**

```powershell
# Check for Event ID 1102 (audit log was cleared)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102}

# Check PowerShell script block logging for encoded commands (Event ID 4104)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
  Where-Object { $_.Message -match 'encodedcommand|frombase64|iex' }
```

### Real-World Example

**APT28 (Fancy Bear)** timestomped files to match legitimate Windows system files and selectively cleared event logs. Analysts used `$UsnJrnl` to recover evidence of deleted files and Event ID 1102 to prove log clearing.

### Best Practices

- Assume anti-forensics in any sophisticated intrusion; always check `$SI` vs `$FN` timestamps for timestomping.
- Use `$UsnJrnl` as a secondary timeline source (harder to tamper with); memory forensics is the primary counter to fileless malware.
- Anti-forensic activity is evidence of **intent and consciousness of guilt**, which is legally significant.

### Interview Tip

Timestomping is a favorite interview question. Explain the NTFS dual-timestamp mechanism (`$STANDARD_INFORMATION` vs `$FILE_NAME`) and how comparing them reveals tampering. Also mention that the `$UsnJrnl` maintains its own timestamps that are very difficult to manipulate without detection.

### References

- SANS FOR508 - Advanced Incident Response
- MITRE ATT&CK: Defense Evasion (TA0005)

---

## Chain of Custody

### Explanation

Chain of custody is the documented, unbroken record of who handled evidence, when, where, and what they did with it. It is the legal foundation that ensures evidence is admissible in court. A break allows defense attorneys to argue tampering. Required documentation at every handover includes: evidence ID, description, UTC timestamp, releasing/receiving party signatures, purpose, location, hash values, and storage conditions.

### Command/Tool Example

```bash
# Hash at acquisition
sha256sum /dev/sdb > /evidence/case001/source_hash.txt
dc3dd if=/dev/sdb of=/evidence/case001/disk.E01 hash=sha256

# Verify at each handover
sha256sum -c /evidence/case001/MANIFEST.sha256
```

### Real-World Example

In **United States v. Comprehensive Drug Testing (2009)**, the Ninth Circuit established that chain of custody must document not just physical handling but also what data was accessed, searched, and copied during analysis.

### Best Practices

- Every person who touches evidence must sign the custody form; use tamper-evident seals.
- Hash everything at acquisition and verify at every subsequent step; work only on forensic copies.
- Store in access-controlled rooms; maintain digital evidence logs with immutable audit trails.

### Interview Tip

Chain of custody questions test whether you understand that forensics is not just technical analysis but also a **legal process**. Emphasize that a technically perfect analysis is worthless if the evidence is inadmissible due to a broken chain of custody. Mention cryptographic hashing as the digital equivalent of a tamper-evident seal.

### References

- NIST SP 800-86 - Guide to Integrating Forensic Techniques into Incident Response
- SWGDE (Scientific Working Group on Digital Evidence) best practices

---

## Key Takeaways

1. **Volatility order matters:** Always collect evidence from most volatile (memory, network state) to least volatile (disk, backups). Once volatile evidence is gone, it is gone forever.

2. **Memory forensics is non-negotiable:** Modern malware operates in memory. Fileless attacks, process injection, and DKOM rootkits are invisible to disk-only analysis. Volatility's `pslist` vs `psscan` comparison is the cornerstone of rootkit detection.

3. **Network forensics provides context:** DNS logs, passive DNS, and NetFlow data reveal C2 infrastructure, lateral movement, and exfiltration that may leave no trace on the endpoint.

4. **Timestamps lie -- verify them:** NTFS `$STANDARD_INFORMATION` timestamps can be trivially modified. Always cross-reference with `$FILE_NAME` timestamps and `$UsnJrnl` entries.

5. **Anti-forensics is evidence too:** Log clearing, timestomping, and secure deletion all leave their own traces and demonstrate intent.

6. **Chain of custody is the foundation:** The most brilliant forensic analysis is meaningless in court without an unbroken, documented chain of custody and verified cryptographic hashes.

7. **Mobile is a different world:** Full-device encryption, cloud-split evidence, and proprietary hardware require specialized tools and legal processes beyond traditional disk forensics.

8. **Document everything:** Every command run, every tool version used, every hash computed, every handover. Forensics is science, and science requires reproducibility.

---

## Interview Practice Questions

1. **You arrive at a potentially compromised Linux server. Walk me through your evidence collection process in order. Why that order?**
   *Focus: RFC 3227 volatility order, live memory acquisition before disk imaging, network state capture, documentation.*

2. **A process appears in Volatility's `psscan` output but not in `pslist`. What does this indicate and how would you investigate further?**
   *Focus: DKOM rootkit hiding processes by unlinking EPROCESS, using `malfind` to check for injected code, dumping the hidden process for analysis.*

3. **How would you detect timestomping on an NTFS filesystem?**
   *Focus: Compare `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamps, check `$UsnJrnl`, look for timestamps predating OS install.*

4. **What is the difference between full packet capture and NetFlow? When would you use each?**
   *Focus: Tradeoff between fidelity and scale, PCAP for content analysis vs NetFlow for broad traffic pattern analysis, sampling rate implications.*

5. **You need to forensically acquire an iPhone that is locked with a passcode. What are your options?**
   *Focus: Acquisition hierarchy (logical/filesystem/physical/chip-off), checkm8 for A5-A11, legal process for iCloud, Cellebrite/GrayKey capabilities.*

6. **A defense attorney argues that your forensic image may have been tampered with. How do you counter this?**
   *Focus: Chain of custody documentation, cryptographic hash verification at every step, write-blockers, working only on copies, audit trail.*

7. **How does fileless malware evade traditional disk forensics, and how would you detect it?**
   *Focus: PowerShell in-memory execution, WMI persistence, LOLBins, memory forensics with Volatility, script block logging, ETW traces.*

8. **Explain memory smear and acquisition footprint. Why do they matter?**
   *Focus: RAM changes during acquisition creating temporal inconsistencies, acquisition tool consuming memory and potentially overwriting evidence, minimizing footprint with lightweight tools.*

9. **You discover that Windows Security event logs were cleared on a compromised system. What evidence of this action might remain?**
   *Focus: Event ID 1102, $UsnJrnl entries for .evtx file changes, remote log copies (SIEM), Volume Shadow Copies, plaso timeline reconstruction.*

10. **Walk through the life of an executable from disk to running in memory. What artifacts does each stage leave?**
    *Focus: File creation on disk, Prefetch/Shimcache/Amcache, process creation (EPROCESS), DLL loading, VAD tree population, network connections, registry modifications.*

---

[Previous: Detection](detection.md) | [Next: Incident Management](incident-management.md)
