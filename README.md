# Security Engineering at Google: My Interview Study Notes
## By [nolang](https://twitter.com/__nolang)

I am a security engineer at Google and these are the notes from when I was studying for the interviews. This is my first job in security and a lot of people have asked me how I studied. My notes consist mostly of a list of terms and technologies to learn, plus little tidbits that helped me remember certain details. I've included interview tips and study strategies which are just as important as knowing what topics to study.

I occasionally update the notes to include more topics. There are many, many topics and terms in the list. Think carefully about the role you are applying for and target your study towards that. No one expects you to be an expert in everything.

**If you are less confident at coding:** 
Spend more time writing small scripts and studying features of your preferred language. Coding is essential (even if you don't like it or you don't use it much in your current role). I have a section on coding in this list.

**If you are less confident at security topics:** 
I recommend doing a lot of reading and whenever you come across a term you are unfamiliar with or couldn't easily explain, then add it to the list. 

### 5 Years Later [Update]
I've been at Google for few years now and I have been delighted to learn of how many people have used these notes! Not just to get offers from Google but to get their first jobs in this industry, or to change focus area. I love hearing these stories! 

Since joining I have also learned what keeps most people from getting through the Google Security Engineering interview process. **The number one reason why a candidate misses out on an offer is because they struggle with the coding questions.**

I have two things to say on this:
1. **Improving coding skills takes a lot of practice.** Be sure to allow yourself enough time for it, including allowing time to be frustrated, to procrastinate, to iterate on your ideas, and to get help from others. Look for ways to make it fun or motivating - there are tedius repetitive tasks everywhere just waiting to be automated. 
2. **It is completely normal and acceptable to interview again** (many times, in fact!). Hiring managers love to see how someone has grown their skills over time.

If you are someone who didn't get an offer because you weren't confident in some areas, but you still believe that it would be a good role/company for you, take some time to build confidence in those areas and try again. 

Finally, pull requests are welcome! Thank you to those who have made contributions and are helping to keep the list up to date.

### How to Use This Guide

The [main notes file](interview-study-notes-for-security-engineering.md) gives you a high-level overview of every topic. Each section links to a **Deep Dive** page in the `sections/` folder with:

- Thorough explanations of every concept
- Real-world examples and case studies (SolarWinds, Log4Shell, Capital One, etc.)
- Code examples and hands-on commands
- Interview tips and practice questions
- External references to authoritative sources (OWASP, MITRE ATT&CK, NIST, RFCs)

**Study strategy:** Read the main notes first to identify gaps, then dive into specific sections for depth.

### Contents

| Section | Overview | Deep Dive |
|---------|----------|-----------|
| Learning Tips | Study strategies and mental health | [Deep Dive](sections/learning-tips.md) |
| Interviewing Tips | How to approach interview questions | [Deep Dive](sections/interviewing-tips.md) |
| Networking | OSI model, protocols, DNS, TLS, firewalls | [Deep Dive](sections/networking.md) |
| Web Application | XSS, SQLi, CSRF, SSRF, CORS | [Deep Dive](sections/web-application.md) |
| Infrastructure & Cloud | Containers, VMs, cloud security, BeyondCorp | [Deep Dive](sections/infrastructure-cloud.md) |
| OS Implementation & Systems | Privilege escalation, AD, Linux/Windows internals | [Deep Dive](sections/os-systems.md) |
| Mitigations | DEP, ASLR, code signing, least privilege | [Deep Dive](sections/mitigations.md) |
| Cryptography | Encryption, hashing, PKI, forward secrecy | [Deep Dive](sections/cryptography.md) |
| Authentication | OAuth, SAML, Kerberos, FIDO2, MFA | [Deep Dive](sections/authentication.md) |
| Identity | ACLs, service accounts, IAM, federation | [Deep Dive](sections/identity.md) |
| Malware & Reversing | Notable malware, analysis techniques, RE tools | [Deep Dive](sections/malware-reversing.md) |
| Exploits | Social/physical/network attacks, tools | [Deep Dive](sections/exploits.md) |
| Attack Structure | Full kill chain, MITRE ATT&CK phases | [Deep Dive](sections/attack-structure.md) |
| Threat Modelling | STRIDE, DREAD, PASTA frameworks | [Deep Dive](sections/threat-modelling.md) |
| Detection | IDS, SIEM, YARA, Splunk, honeypots | [Deep Dive](sections/detection.md) |
| Digital Forensics | Disk/memory/network/mobile forensics | [Deep Dive](sections/digital-forensics.md) |
| Incident Management | PICERL, IMAG, playbooks, postmortems | [Deep Dive](sections/incident-management.md) |
| Coding & Algorithms | Data structures, sorting, Big O, Python | [Deep Dive](sections/coding-algorithms.md) |
| Security Coding Challenges | 9 hands-on projects with complete solutions | [Deep Dive](sections/security-coding-challenges.md) |

### Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed list of changes.
