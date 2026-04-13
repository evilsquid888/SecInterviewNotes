# Detection - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#detection)

> **Prerequisites:** [Networking](networking.md), [Attack Structure](attack-structure.md)  
> **Difficulty:** Intermediate to Advanced

---

## Table of Contents

1. [Intrusion Detection Systems (IDS)](#1-intrusion-detection-systems-ids)
2. [SIEM - Security Information and Event Management](#2-siem---security-information-and-event-management)
3. [Indicators of Compromise (IOC)](#3-indicators-of-compromise-ioc)
4. [Signal Creation](#4-signal-creation)
5. [Signal Triage](#5-signal-triage)
6. [Alerting and Decision Systems](#6-alerting-and-decision-systems)
7. [Signature-Based Detection](#7-signature-based-detection)
8. [Anomaly and Behaviour Detection](#8-anomaly-and-behaviour-detection)
9. [Firewall Rules for Detection](#9-firewall-rules-for-detection)
10. [Honeypots and Deception Technology](#10-honeypots-and-deception-technology)
11. [Attacker Evasion Knowledge](#11-attacker-evasion-knowledge)
12. [Logs to Examine](#12-logs-to-examine)
13. [Detection Tooling](#13-detection-tooling)

---

## 1. Intrusion Detection Systems (IDS)

### Explanation

An Intrusion Detection System monitors network traffic or host activity for malicious behaviour. **Network-based IDS (NIDS)** inspects packets on the wire at chokepoints (Snort, Suricata). **Host-based IDS (HIDS)** monitors system-level events like file integrity, registry changes, and process execution (OSSEC, Wazuh). Detection logic is either **signature-based** (matching known patterns, low FP, blind to novel threats) or **behaviour/anomaly-based** (modelling normal and flagging deviation, can detect zero-day, higher FP rate).

### Configuration Example

**Snort rule -- detect Cobalt Strike default beacon:**

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"MALWARE-CNC Cobalt Strike Beacon default URI";
    flow:to_server,established;
    content:"/pixel.gif"; http_uri;
    content:"Cookie:"; http_header;
    pcre:"/Cookie:\s[a-zA-Z0-9+/]{64,}/Hi";
    classtype:trojan-activity;
    sid:1000001; rev:3;
)
```

**YARA rule -- detect Mimikatz strings in memory or on disk:**

```yara
rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz credential dumper"
        author = "detection-engineering"
        severity = "high"

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "sekurlsa::wdigest" ascii wide nocase
        $s3 = "privilege::debug" ascii wide nocase
        $s4 = "lsadump::sam" ascii wide nocase
        $s5 = "kerberos::golden" ascii wide nocase
        $pdb = "mimikatz.pdb" ascii
        $banner = "gentilkiwi" ascii wide

    condition:
        (uint16(0) == 0x5A4D) and (3 of ($s*) or $pdb or $banner)
}
```

### Real-World Example

During **SolarWinds SUNBURST** (2020), signature-based IDS was initially useless because the implant came through a trusted update. Once FireEye published IOCs, Snort/Suricata rules were rapidly deployed to detect DGA domain patterns and encoded HTTP cookie C2 values. YARA rules targeting `OrionImprovementBusinessLayer.dll` strings became the primary endpoint scanning tool.

### Interview Tip

> Know the difference between IDS and IPS (prevention). IDS is passive -- it copies and inspects traffic. IPS sits inline and can drop packets. Deploy IDS on a SPAN/TAP port for visibility without risking availability, and IPS inline only after extensive tuning.

### References

- [Snort 3 Documentation](https://docs.snort.org/)
- [YARA Documentation](https://yara.readthedocs.io/)

---

## 2. SIEM - Security Information and Event Management

### Explanation

A SIEM collects, normalises, correlates, and stores security events from across the environment -- firewalls, endpoints, servers, applications, cloud services. Core functions: **log aggregation** from heterogeneous sources, **normalisation** to a common schema (CIM in Splunk, ECS in Elastic), **correlation** rules connecting related events across sources and time, **alerting** on rule matches, and **retention/search** for compliance and forensics. Major SIEMs: Splunk ES, IBM QRadar, Microsoft Sentinel, Elastic Security, Google Chronicle.

### Configuration Example

**Splunk SPL -- detect lateral movement via PsExec:**

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688
| where match(New_Process_Name, "(?i)\\\\psexe(c|svc)\.exe$")
| stats count min(_time) as first_seen max(_time) as last_seen
        values(Creator_Process_Name) as parent
        dc(ComputerName) as host_count
        values(ComputerName) as hosts
        by Account_Name
| where host_count > 2
| sort -host_count
```

### Real-World Example

The **Target breach** (2013) demonstrated what happens when SIEM alerts are ignored. FireEye's monitoring tool generated alerts about malware activity, but alerts were not acted upon due to alert fatigue. Attackers exfiltrated 40 million credit card records. This incident accelerated industry focus on triage automation and SOC processes.

### Interview Tip

> When asked about SIEM, go beyond "it collects logs." Discuss data normalisation challenges (every vendor has a different log format), the cost of ingestion (Splunk licenses by daily volume), and the importance of detection-as-code -- storing correlation rules in version control and testing them against historical data before deployment.

### References

- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- SANS Reading Room: "Benchmarking SIEM Effectiveness"

---

## 3. Indicators of Compromise (IOC)

### Explanation

IOCs are forensic artefacts indicating a system or network has been compromised. Common types: IP addresses, domains, file hashes (MD5/SHA256), URL paths, email addresses, mutex names, registry keys, User-Agent strings, and JA3/JA3S TLS fingerprints. IOCs are shared in structured formats (STIX/TAXII, OpenIOC) and consumed by detection tools.

The **Pyramid of Pain** (David Bianco) ranks IOCs by how much pain removing them causes attackers: Hash values (trivial) < IP addresses (easy) < Domain names (moderate) < Network/host artefacts (harder) < Tools (significant) < TTPs (hardest -- forces retooling).

### Configuration Example

**Splunk lookup-based IOC matching:**

```spl
| inputlookup threat_intel_ip.csv
| rename ioc_ip as src_ip
| join type=inner src_ip
    [search index=firewall sourcetype=pan:traffic action=allowed
     | fields src_ip dest_ip dest_port bytes_out]
| table _time src_ip dest_ip dest_port bytes_out ioc_source ioc_campaign
| sort -bytes_out
```

### Real-World Example

After **NotPetya** (2017), responders published IOC lists including the malicious `perfc.dat` hash, SMB exploitation patterns, and scheduled task names. Organisations with automated IOC ingestion into SIEM and EDR could scan their estate within hours and identify compromised hosts before encryption completed.

### Interview Tip

> Mention the Pyramid of Pain. Explain that you should not rely solely on hash-based IOCs because attackers change a single byte to produce a new hash. The most durable detections target TTPs (MITRE ATT&CK techniques), not atomic indicators.

### References

- David Bianco, "The Pyramid of Pain" (2013)
- [MISP Project](https://www.misp-project.org/)

---

## 4. Signal Creation

### Explanation

Signal creation is the process of generating security-relevant telemetry that does not exist by default. You are instrumenting your environment so attacker activity produces observable events. Key techniques: **honeypots** (fake services/credentials with zero legitimate use), **canary tokens** (DNS names, AWS keys, URLs that alert when accessed), **custom IDS rules** for your environment, **Sysmon deployment** for process/network/registry telemetry, and **custom application logging** for auth events and sensitive data access.

### Configuration Example

**Canary token -- AWS access key (honeypot credential):**

Place in `~/.aws/old_credentials` on a server:
```ini
[legacy-backup]
aws_access_key_id = AKIAIOSFODNN7HONEYTOKEN
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYTOKEN
```

Then create a CloudTrail alert:
```spl
index=aws sourcetype=aws:cloudtrail
    userIdentity.accessKeyId="AKIAIOSFODNN7HONEYTOKEN"
| stats count by eventName sourceIPAddress userAgent
| eval alert_reason="Canary AWS key used - likely credential theft"
```

### Real-World Example

A financial institution deployed **honey credentials** (fake AD accounts like `svc_backup_admin`) with logon auditing. When APT41 ran `net user /domain` and attempted authentication with the honey account, the SOC received an immediate high-fidelity alert -- zero false positives because the account should never authenticate.

### Interview Tip

> Signal creation demonstrates proactive security thinking. Explain that you would plant signals that guarantee visibility into specific attack phases rather than waiting for attackers to hit existing detections. This shows you think like a detection engineer, not just a rule writer.

### References

- [Canarytokens.org](https://canarytokens.org/)
- [Sysmon Configuration Guide (SwiftOnSecurity)](https://github.com/SwiftOnSecurity/sysmon-config)

---

## 5. Signal Triage

### Explanation

Signal triage determines which of the thousands of daily SIEM alerts require human investigation. The process involves **deduplication** (grouping repeated alerts), **enrichment** (threat feeds, asset criticality, user context), **scoring** (priority based on severity, confidence, asset value), and **routing** (high-priority to analysts, auto-close known FPs). Mature SOCs use SOAR playbooks for automated enrichment and risk-based alerting (RBA) that aggregates per-entity risk scores so analysts are only paged when multiple signals converge on the same target.

### Configuration Example

**Splunk ES risk-based alerting (RBA):**

```spl
| from datamodel:"Risk"."All_Risk"
| stats sum(risk_score) as total_risk
        values(risk_message) as risk_messages
        values(source) as detections
        dc(source) as detection_count
        latest(_time) as last_seen
        by risk_object risk_object_type
| where total_risk > 100 AND detection_count >= 3
| sort -total_risk
```

### Real-World Example

Splunk ES's **Risk-Based Alerting** was adopted by a large financial services firm drowning in 10,000+ alerts/day. By shifting to entity-centric risk scoring, they reduced their alert-to-investigation ratio by 80% and dropped MTTD for true positives from 4 hours to 45 minutes.

### Interview Tip

> Discuss analyst fatigue as a real operational problem. More detections is not necessarily better -- if your team writes 500 rules but 490 produce noise, analysts stop trusting the system. Quality over quantity. Talk about tuning as an ongoing process.

### References

- Splunk: "Risk-Based Alerting" documentation
- SANS: "SOC Metrics That Matter"

---

## 6. Alerting and Decision Systems

### Explanation

Mature SOCs use layered decision systems combining automation, ML, and human judgement. **Auto-triage** via SOAR playbooks closes known FPs automatically. **ML-based scoring** uses models trained on analyst verdicts to predict alert value. **Decision systems** use runbooks guiding analysts through consistent investigation steps. The critical element is the **feedback loop** -- analyst TP/FP determinations feed back into rule tuning and model retraining.

### Configuration Example

**SOAR playbook pseudocode (Phantom / XSOAR):**

```python
def triage_snort_alert(alert):
    src_ip = alert["src_ip"]

    # Check if source is a known scanner
    if src_ip in asset_db.get_scanners():
        return close_alert(alert, reason="Known vulnerability scanner")

    # Enrich with threat intel
    vt_result = virustotal.lookup_ip(src_ip)
    if vt_result["malicious_votes"] > 5:
        alert["risk_score"] += 40

    # Check if destination is a high-value asset
    dest_asset = asset_db.lookup(alert["dest_ip"])
    if dest_asset["criticality"] == "crown_jewel":
        alert["risk_score"] += 50

    # Route based on score
    if alert["risk_score"] >= 80:
        page_oncall(alert)
    elif alert["risk_score"] >= 40:
        add_to_queue(alert, priority="high")
    else:
        add_to_queue(alert, priority="low")
```

### Interview Tip

> When asked about alert fatigue, propose solutions: (1) tuning rules to reduce FPs, (2) risk-based alerting to aggregate weak signals, (3) SOAR automation for known-good dispositions, (4) feedback loops so analyst verdicts improve future detection.

### References

- SANS: "Automating the SOC with SOAR"
- Google: "Autonomic Security Operations" whitepaper

---

## 7. Signature-Based Detection

### Explanation

Signatures are deterministic patterns matching known malicious activity. **Host-based signatures** detect registry modifications, file changes, malware strings, and suspicious process behaviour (e.g., `cmd.exe` spawned by `winword.exe`). **Network-based signatures** detect C2 domains, DGA patterns, DNS tunnelling, specific HTTP patterns, JA3 TLS fingerprints, and protocol anomalies. **Sigma** is a vendor-agnostic signature format that compiles to Splunk SPL, Elastic KQL, QRadar AQL, and other SIEM query languages.

### Configuration Example

**Sigma rule -- detect Mimikatz via Sysmon:**

```yaml
title: Mimikatz Credential Dumping
id: 0d7b4c3a-1e2f-4a5b-8c9d-0e1f2a3b4c5d
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmdline:
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'sekurlsa::wdigest'
            - 'lsadump::sam'
            - 'lsadump::dcsync'
    selection_image:
        Image|endswith: '\mimikatz.exe'
        OriginalFileName: 'mimikatz.exe'
    condition: selection_cmdline or selection_image
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
```

### Real-World Example

**WannaCry** (2017) was rapidly signatured. Snort rules detected the EternalBlue SMB exploitation pattern. YARA rules targeted the ransom note text and kill-switch domain check. Network signatures on port 445 allowed organisations to isolate infected hosts before lateral movement completed.

### Interview Tip

> Mention **Sigma** as a vendor-agnostic signature format. Sigma rules can be compiled to Splunk SPL, Elastic KQL, QRadar AQL, and other SIEM query languages. This is the future of portable detection engineering.

### References

- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [Emerging Threats Ruleset](https://rules.emergingthreats.net/)

---

## 8. Anomaly and Behaviour Detection

### Explanation

Anomaly detection complements signatures by identifying deviations from established baselines of normal behaviour. The process requires **baselining** (30-90 days of normal data per entity), **feature extraction** (login times, data volumes, process frequency, DNS patterns), **deviation scoring** (z-scores, isolation forests, autoencoders), and **threshold alerting**. Key behavioural indicators: unset HISTFILE (attacker hiding commands), unusual `/proc` access (memory scraping), rapid recon commands (`whoami`, `net user`), off-hours logins, data volume spikes, and anomalous process lineage (`outlook.exe` spawning `powershell.exe`).

### Configuration Example

**Splunk query -- detect unusual outbound data volume per host:**

```spl
index=firewall sourcetype=pan:traffic direction=outbound
| bin _time span=1h
| stats sum(bytes_out) as hourly_bytes by src_ip _time
| eventstats avg(hourly_bytes) as avg_bytes stdev(hourly_bytes) as stdev_bytes by src_ip
| eval z_score=round((hourly_bytes - avg_bytes) / stdev_bytes, 2)
| where z_score > 3
| sort -z_score
| table _time src_ip hourly_bytes avg_bytes z_score
```

### Real-World Example

**Darktrace** detected an insider threat at a manufacturing firm. An employee who normally accessed only their departmental file shares began browsing R&D directories at unusual hours. The behavioural model flagged the lateral access pattern. Investigation revealed IP theft being exfiltrated to a competitor. No signature-based tool would have caught this -- no malware was involved.

### Interview Tip

> Emphasise that anomaly detection requires **context**. An anomaly is not automatically malicious -- it could be a developer deploying a hotfix at 2 AM. The key is combining multiple weak signals: unusual time + unusual access pattern + unusual data volume = high confidence alert. Mention UEBA (User and Entity Behaviour Analytics) as the product category.

### References

- MITRE ATT&CK: [Defense Evasion - Indicator Removal](https://attack.mitre.org/techniques/T1070/)
- SANS: "User and Entity Behaviour Analytics"

---

## 9. Firewall Rules for Detection

### Explanation

Firewalls are primarily enforcement tools, but their logs are a rich detection source. Detection-oriented firewall rules target: **brute force** (excessive connection attempts), **port scanning** (single source touching many ports), **anomalous upload traffic** (potential exfiltration), and **protocol violations** (SSH on port 443, DNS on port 80). The key concept is **egress filtering** -- most organisations focus on inbound rules but neglect outbound. A compromised host needs to phone home; restricting outbound to HTTP/HTTPS through a proxy and blocking direct outbound DNS breaks many C2 channels.

### Configuration Example

**iptables -- detect and log port scanning (Linux):**

```bash
# Create a chain for scan detection
iptables -N SCAN_DETECT

# Log and drop hosts that hit more than 10 different ports in 60 seconds
iptables -A SCAN_DETECT -m recent --name portscan --rcheck --seconds 60 --hitcount 10 \
    -j LOG --log-prefix "PORT_SCAN_DETECTED: " --log-level 4
iptables -A SCAN_DETECT -m recent --name portscan --rcheck --seconds 60 --hitcount 10 \
    -j DROP

# Track new connection attempts
iptables -A INPUT -p tcp --syn -m recent --name portscan --set
iptables -A INPUT -p tcp --syn -j SCAN_DETECT
```

### Real-World Example

During an investigation of a compromised web server, firewall logs revealed outbound connections to TCP port 4444 (Metasploit default) for three weeks before discovery. A simple rule logging outbound connections from DMZ servers to non-standard ports would have detected this immediately.

### Interview Tip

> Explain **egress filtering** -- describe how you would implement egress controls (only allow outbound HTTP/HTTPS through a proxy, block direct outbound DNS) and log violations. Most organisations neglect this and it breaks many C2 channels.

### References

- SANS: "Egress Filtering FAQ"
- CIS Benchmarks for firewall configurations

---

## 10. Honeypots and Deception Technology

### Explanation

Honeypots are decoy systems with no production function -- any interaction is suspicious by definition, giving near-zero false positive rates. Types: **low-interaction** (emulate services, e.g., Cowrie for SSH), **high-interaction** (full OS with monitoring), **canary tokens** (tripwires in documents, credentials, DNS, URLs), and **honey networks** (full decoy network segments). Deploy internally on production VLANs for lateral movement detection, in the DMZ for threat intelligence, and as honey credentials/files throughout the environment.

### Configuration Example

**Cowrie SSH honeypot -- docker-compose.yml:**

```yaml
version: '3'
services:
  cowrie:
    image: cowrie/cowrie:latest
    ports:
      - "2222:2222"
    volumes:
      - cowrie-logs:/cowrie/cowrie-git/var/log/cowrie
    environment:
      - COWRIE_TELNET_ENABLED=no
    restart: unless-stopped

volumes:
  cowrie-logs:
```

### Real-World Example

A healthcare organisation deployed **Thinkst Canary** devices disguised as medical imaging servers. When a ransomware operator gained initial access and began scanning, the canary detected the port scan within seconds. The SOC isolated the compromised workstation before lateral movement to patient data systems. Total dwell time: 4 minutes.

### Interview Tip

> Honeypots demonstrate depth of defence thinking. They are valuable precisely because of their near-zero false positive rate -- unlike IDS rules that require tuning. Also mention legal/ethical considerations: internal honeypots are generally fine, but in some jurisdictions external honeypots must not entrap.

### References

- [Thinkst Canary](https://canary.tools/)
- [Canarytokens](https://canarytokens.org/)

---

## 11. Attacker Evasion Knowledge

### Explanation

Understanding how attackers evade detection is essential for writing durable detections. Common evasion techniques: **slow attacks** (1 packet/minute evades rate-based thresholds), **noise/spoofing** (decoy alerts to overwhelm analysts), **TTL manipulation** (packets reach IDS but expire before target -- insertion attack), **fragmentation** (split payloads across fragments to evade pattern matching), **encryption** (TLS-encrypted C2 prevents content inspection), **LOLBins** (built-in tools avoid AV signatures), **timestomping** (alter file timestamps), and **log clearing** (delete event logs, clear `.bash_history`).

The defender response: build cumulative detections over longer windows (24h port scan detection, not just rate-per-minute), normalise before inspection (stream reassembly, defragmentation), treat evasion as its own signal (log clearing is suspicious), and layer network + host + behavioural detection.

### Configuration Example

**Splunk query -- detect log clearing on Windows:**

```spl
index=windows sourcetype=WinEventLog:Security
    (EventCode=1102 OR EventCode=104)
| eval action=case(
    EventCode==1102, "Security log cleared",
    EventCode==104, "System log cleared")
| table _time ComputerName Account_Name action
| eval severity="CRITICAL"
```

### Real-World Example

APT29 during **SolarWinds** waited 12-14 days after implant deployment before lateral movement. C2 used legitimate cloud services mimicking normal Orion traffic. Rate-based detections were useless (beacon interval set to hours). Detection ultimately came from anomaly analysis of authentication patterns -- SAML token forging that produced unusual Azure AD logs.

### Interview Tip

> When discussing detection rules, always address evasion. If you describe a brute-force rule, also explain how an attacker might slow below the threshold, then describe a complementary cumulative detection (e.g., 24-hour failed auth count). This demonstrates adversarial thinking.

### References

- Ptacek & Newsham, "Insertion, Evasion, and Denial of Service" (1998)
- MITRE ATT&CK: [Defense Evasion](https://attack.mitre.org/tactics/TA0005/)

---

## 12. Logs to Examine

### Explanation

Knowing which logs to examine is a core detection engineering skill.

### DNS Logs

DNS is one of the highest-value sources because virtually all network activity involves DNS and attackers frequently abuse it. Look for: queries to known-bad domains, DNS tunnelling (subdomains >50 chars, high query volume to single domains, TXT records with encoded data), fast flux (domain resolving to many IPs rapidly), and queries to newly registered domains (<30 days).

### HTTP Headers and Metadata

Look for: unusual User-Agent strings (e.g., `python-requests/2.28` from a server), unexpected referer chains (exploit kit redirects), oversized cookies (Cobalt Strike data encoding), and 404 bursts (directory brute-forcing).

### Execution Logs

**Windows Event Logs:** Event IDs 4688 (process creation), 4624/4625 (logon success/failure), 4672 (special privileges), 7045 (service install). **Sysmon:** Event IDs 1 (process create), 3 (network connect), 7 (image load), 11 (file create), 13 (registry), 22 (DNS query). **PowerShell:** Script block logging (Event ID 4104) captures actual commands even if encoded.

### Configuration Example

**Splunk query -- detect DNS beaconing:**

```spl
index=dns sourcetype=bro:dns
| bin _time span=10s
| stats count by src_ip query _time
| streamstats current=f window=10 avg(count) as avg_count stdev(count) as std_count by src_ip query
| eval consistency=if(std_count<1 AND avg_count>0, "beacon_likely", "normal")
| where consistency="beacon_likely"
| stats count as beacon_intervals dc(_time) as time_slots by src_ip query
| where beacon_intervals > 50
| sort -beacon_intervals
```

### Real-World Example

During the **Equifax breach** (2017), attackers exfiltrated 148 million records over 76 days. Post-incident analysis showed encrypted traffic on non-standard ports was not inspected because the SSL certificate on the monitoring appliance had expired. The traffic volume anomaly was visible in netflow data but not monitored -- demonstrating the need to monitor traffic metadata (volume, destination, timing) even without content inspection.

### Interview Tip

> If asked "what logs would you look at first?", prioritise: (1) DNS logs -- nearly all attacks touch DNS, (2) authentication logs -- credential abuse is the most common initial access, (3) process execution logs -- see what the attacker ran, (4) network flow data -- detect lateral movement and exfiltration.

### References

- SANS: "Detecting DNS Tunnelling"
- Microsoft: "Windows Security Event Log Reference"

---

## 13. Detection Tooling

### Explanation

| Tool | Type | Primary Use |
|---|---|---|
| **Splunk** | SIEM | Log aggregation, search, correlation, dashboarding |
| **QRadar** | SIEM | Flow analysis, offence management, built-in threat intel |
| **Darktrace** | NDR / AI | Anomaly detection, autonomous response |
| **Tcpdump** | Packet capture | Quick CLI-based traffic inspection |
| **Wireshark** | Packet analyser | Deep protocol analysis with GUI |
| **Zeek** | NSM | Network metadata generation (conn, DNS, HTTP, TLS logs) |
| **Snort** | NIDS | Signature-based network intrusion detection |
| **Suricata** | NIDS/IPS | Multi-threaded IDS/IPS with protocol-aware detection |

**Splunk** is most commonly encountered in enterprise. Strength is SPL search language. Splunk ES adds pre-built correlation rules and risk-based alerting.

**QRadar** differentiates with built-in network flow analysis -- detect threats from flow data without full packet capture.

**Zeek** generates structured log files (conn.log, dns.log, http.log, ssl.log) ideal for SIEM ingestion. Rich metadata without full packet capture storage.

### Configuration Example

**Wireshark display filters for common investigations:**

```
# HTTP POST requests (potential exfiltration)
http.request.method == "POST" && ip.src == 10.0.0.0/8

# DNS TXT record queries (potential C2 or tunnelling)
dns.qry.type == 16

# TLS connections with specific JA3 hash
tls.handshake.ja3 == "e7d705a3286e19ea42f587b344ee6865"

# SMB lateral movement
smb2.cmd == 1 && smb2.filename contains "\\ADMIN$"
```

### Real-World Example

A large university deployed **Zeek** on their 40 Gbps uplink and fed metadata into **Splunk**. When a server was compromised for cryptocurrency mining, Zeek conn.log showed sustained outbound connections to a mining pool on port 3333. A simple Splunk alert caught it within an hour. Full packet capture would have been impractical at 40 Gbps, but Zeek's metadata approach made detection trivial.

### Interview Tip

> Know the strengths and weaknesses of each tool. If asked "Splunk or QRadar?", explain trade-offs: Splunk has superior search language and ecosystem but is expensive at scale. QRadar includes flow analysis out of the box. Elastic is open-source but requires more operational overhead. The right choice depends on organisation size, budget, and team expertise.

### References

- [Splunk Documentation](https://docs.splunk.com/)
- [Zeek Documentation](https://docs.zeek.org/)

---

## Key Takeaways

1. **Detection is layered.** Combine signature-based (known threats), anomaly-based (unknown threats), and deception-based (guaranteed high-fidelity) detection.

2. **Signal quality matters more than quantity.** A SOC with 50 well-tuned, high-fidelity detection rules outperforms one with 5,000 noisy rules.

3. **Think like an attacker.** Every detection rule should be evaluated through an adversarial lens: how would an attacker evade this?

4. **Detection engineering is software engineering.** Rules should be version-controlled, tested against historical data, peer-reviewed, and maintained.

5. **The Pyramid of Pain is your guide.** TTP-based detections force attackers to fundamentally change their tradecraft.

6. **Visibility is prerequisite to detection.** Invest in logging infrastructure (Sysmon, Zeek, cloud audit trails) before detection rules.

7. **Honeypots and canary tokens are underutilised.** Near-zero false positive alerting and simple to deploy.

8. **Know your logs.** DNS, authentication, process execution, and network flow data are the four pillars of detection telemetry.

---

## Interview Practice Questions

1. **Explain the difference between signature-based and anomaly-based detection. When would you use each?**
   - Signatures for known threats (low FP, blind to novel attacks). Anomaly for unknown/insider threats (can catch zero-day, higher FP). Use both in layers.

2. **You receive 5,000 alerts per day and your team can investigate 50. How do you prioritise?**
   - Risk-based alerting (aggregate by entity), auto-triage known FPs with SOAR, enrich with threat intel and asset criticality, tune noisy rules, implement feedback loops.

3. **Write a Snort rule to detect DNS tunnelling.**
   - Match on long DNS queries: `alert udp $HOME_NET any -> any 53 (msg:"DNS tunnel"; content:"|01 00|"; offset:2; byte_test:1,>,50,12; sid:100001;)`

4. **An attacker is using encrypted C2 over HTTPS to a legitimate cloud provider. How do you detect this?**
   - JA3/JA3S TLS fingerprinting, beaconing analysis (periodic connection timing), unusual data volume patterns, DNS query patterns for the cloud endpoint, process-level network connections via Sysmon.

5. **What is the Pyramid of Pain and why does it matter for detection engineering?**
   - Ranks IOCs by attacker cost to change. Hash < IP < Domain < Network artefacts < Tools < TTPs. Focus detections on TTPs for maximum attacker disruption.

6. **Describe how you would deploy and use honeypots in a corporate environment.**
   - Internal honeypots on production VLANs to detect lateral movement, canary tokens in documents and credentials, honey DNS records, forward all honeypot telemetry to SIEM, alert on any interaction as high confidence.

7. **How does an attacker evade rate-based brute force detection? How would you counter it?**
   - Slow the attack below the threshold (1 attempt per minute). Counter with cumulative counting over longer windows (24h), credential stuffing detection (many users, few attempts each), impossible-travel correlation.

8. **What are the first three log sources you would configure in a new SIEM deployment and why?**
   - DNS (all attacks touch DNS, tunnelling detection), authentication logs (credential abuse is top initial access), endpoint process execution (Sysmon/EDR for visibility into what runs on hosts).

---

[Previous: Threat Modelling](threat-modelling.md) | [Next: Digital Forensics](digital-forensics.md)
