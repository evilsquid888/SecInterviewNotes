# Changelog

## 2026-04-12 - Deep Dive Enhancement

### Added

- **19 comprehensive deep-dive pages** in `sections/` directory, one for each topic area:
  - `learning-tips.md` - Spaced repetition, study frameworks, mental health strategies
  - `interviewing-tips.md` - Example dialogues, preparation checklists, thinking-aloud techniques
  - `networking.md` - Protocol deep dives, packet diagrams, hands-on commands (nmap, tcpdump, dig)
  - `web-application.md` - Vulnerable/fixed code examples, real-world breaches, hands-on labs
  - `infrastructure-cloud.md` - Hypervisor internals, container escapes, BeyondCorp, Log4Shell
  - `os-systems.md` - Buffer overflows, AD attacks, Linux privilege escalation, forensic artifacts
  - `mitigations.md` - DEP, ASLR, code signing, MACs with bypass techniques
  - `cryptography.md` - RSA/AES/ECC with Python code, key exchange diagrams, common mistakes
  - `authentication.md` - OAuth/SAML/Kerberos flows, DigiNotar, Golden Tickets, FIDO2/Passkeys
  - `identity.md` - ACLs, service account abuse, cloud IAM, JWT exploitation, federation attacks
  - `malware-reversing.md` - Stuxnet/WannaCry/Sunburst case studies, IDA Pro vs Ghidra
  - `exploits.md` - Social/physical/network vectors, reverse shells, Metasploit/Shodan guides
  - `attack-structure.md` - All 14 MITRE ATT&CK phases with SolarWinds campaign walkthrough
  - `threat-modelling.md` - STRIDE/DREAD/PASTA with worked banking app threat model
  - `detection.md` - Snort/YARA/Sigma rules, Splunk queries, honeypot deployment
  - `digital-forensics.md` - Volatility commands, disk imaging, memory analysis, chain of custody
  - `incident-management.md` - PICERL scenario walkthrough, escalation matrices, postmortem templates
  - `coding-algorithms.md` - Python implementations, Big O analysis, security-relevant patterns
  - `security-coding-challenges.md` - Complete Python solutions for all 9 challenges

- **Deep Dive links** added to every section in the main study notes file
- **README table of contents** restructured as a table with direct links to both overview and deep-dive pages
- **"How to Use This Guide"** section added to README
- This CHANGELOG

### Each deep-dive page includes

- Thorough explanations of every concept
- Step-by-step breakdowns of how things work
- Real-world examples and famous breach case studies
- Code examples, tool commands, and configuration samples
- Interview tips and practice questions
- External references to authoritative sources (OWASP, MITRE, NIST, RFCs)
- Navigation links (previous/next section)
