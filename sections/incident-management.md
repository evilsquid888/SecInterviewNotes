# Incident Management - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#incident-management)

> **Prerequisites:** [Detection](detection.md), [Attack Structure](attack-structure.md)  
> **Difficulty:** Intermediate

---

## Table of Contents

1. [Privacy Incidents vs Information Security Incidents](#privacy-incidents-vs-information-security-incidents)
2. [Knowing When and Who to Communicate With](#knowing-when-and-who-to-communicate-with)
3. [Good Practices in Incident Response](#good-practices-in-incident-response)
4. [Important Knowledge Areas](#important-knowledge-areas)
5. [Response Models: SANS PICERL](#response-models-sans-picerl)
6. [Response Models: Google IMAG](#response-models-google-imag)
7. [Complete Scenario Walkthrough (PICERL)](#complete-scenario-walkthrough-picerl)
8. [Templates and Checklists](#templates-and-checklists)
9. [Key Takeaways](#key-takeaways)
10. [Interview Practice Questions](#interview-practice-questions)

---

## Privacy Incidents vs Information Security Incidents

### Explanation

These two categories overlap but carry different obligations, stakeholders, and regulatory consequences.

**Information Security Incident:** Any event that compromises the confidentiality, integrity, or availability of an information system or the data it processes. Examples include ransomware, DDoS, unauthorized access to servers, or defacement.

**Privacy Incident:** A subset (or adjacent category) where personally identifiable information (PII) or protected data is exposed, accessed without authorization, or mishandled in violation of privacy regulations. Examples include accidental data leaks, unauthorized employee access to customer records, or a breach exposing email addresses and passwords.

Key differences:

| Dimension | Security Incident | Privacy Incident |
|---|---|---|
| **Primary concern** | CIA triad for systems and data | Rights of data subjects |
| **Regulatory drivers** | SOC 2, ISO 27001, internal policy | GDPR, CCPA, HIPAA, PIPEDA |
| **Notification obligations** | Internal SLAs, possibly contractual | Legal deadlines (e.g., GDPR 72 hours) |
| **Who must be told** | Security team, management | Data Protection Officer, regulators, affected users |
| **Legal exposure** | Contract breach, negligence | Statutory fines, class-action lawsuits |
| **Can one be both?** | Yes -- a breach that exfiltrates PII is both | Yes |

A security incident does not always involve personal data (e.g., cryptominer on an internal build server). A privacy incident does not always involve an external attacker (e.g., an employee emails a spreadsheet of customer SSNs to the wrong recipient).

### Step-by-Step: Classifying the Incident Type

1. Determine what data or systems are affected.
2. Check whether any PII, PHI, or regulated data is involved.
3. If yes, immediately loop in the Data Protection Officer or privacy counsel.
4. Identify which jurisdictions are affected (where do the data subjects reside?).
5. Start the notification clock -- GDPR gives 72 hours from awareness, HIPAA gives 60 days, state breach notification laws vary.
6. Document the classification decision and reasoning.

### Interview Tip

Interviewers want to see that you understand the distinction and can articulate why it matters operationally. Say something like: "The first thing I determine is whether personal data is in scope, because that changes who I notify, the timeline I'm working under, and whether legal and the DPO need to be in the room from minute one."

---

## Knowing When and Who to Communicate With

### Explanation

Poor communication during an incident causes more organizational damage than many technical failures. The responder must know the escalation path before an incident occurs.

**Stakeholder map:**

| Stakeholder | When to involve | What they need |
|---|---|---|
| **Legal / Privacy Counsel** | Any suspected data breach; any incident that may trigger regulatory notification; any incident involving a third party or customer | Factual summary, data types affected, timeline, preservation guidance |
| **Affected Users** | When their data is confirmed compromised and legal/comms have approved the message | Clear language on what happened, what data was affected, what they should do |
| **Direct Manager** | Immediately upon confirming a real incident (not a false positive) | Severity, estimated impact, resources needed |
| **Directors / VPs** | High or critical severity; any incident that could become public; any incident affecting revenue or SLAs | Executive summary, business impact, ETA for resolution |
| **CISO / CSO** | All confirmed incidents above low severity | Strategic risk assessment, resource requests, external communication decisions |
| **PR / Communications** | When there is any chance of public exposure or media attention | Approved messaging, timeline, Q&A preparation |
| **Law Enforcement** | When criminal activity is confirmed and legal counsel advises it | Preserved evidence, chain of custody documentation |
| **Third-Party Vendors** | When the incident involves their systems or originates from their environment | Contractual obligations, joint investigation scope |

### Step-by-Step: Escalation Procedure

1. **Validate** the alert is a true positive. Do not escalate noise.
2. **Classify severity** using your organization's matrix (P1-P4 or Critical/High/Medium/Low).
3. **Notify the on-call incident commander** or security lead.
4. **Open a dedicated communication channel** (Slack war room, bridge call).
5. **Assess data impact** -- if PII is involved, notify legal and the DPO within 30 minutes.
6. **Escalate to management** per severity thresholds.
7. **Document every notification** with timestamp, recipient, and content summary.

### Interview Tip

Walk through an escalation scenario: "I confirmed the alert was real, opened a Slack channel, pulled in the on-call lead, and within 15 minutes we had classified it as P2. Because PII was potentially involved, I notified legal immediately rather than waiting for full confirmation."

---

## Good Practices in Incident Response

### Delegation and Roles

Every incident needs clear role assignment. Without it, responders duplicate effort or leave gaps. Standard roles from the Incident Command System (ICS) adapted for security:

- **Incident Commander (IC):** Owns the overall response. Makes final decisions. Does NOT do hands-on technical work.
- **Technical Lead:** Directs the investigation. Coordinates analysis across systems.
- **Communications Lead:** Manages all internal and external messaging. Single point of contact for stakeholders.
- **Scribe / Documenter:** Maintains the real-time incident timeline. Records actions, findings, and decisions with timestamps.
- **Subject Matter Experts (SMEs):** Called in as needed (network, endpoint, cloud, application).

### Communication Methods

- **War Room Channel:** Dedicated Slack/Teams channel, created per incident, named with incident ID.
- **Bridge Call:** For critical incidents, maintain an open video/phone bridge.
- **Status Updates:** Push regular updates at fixed intervals (every 30 or 60 minutes), even if there is nothing new. Silence breeds anxiety.
- **Out-of-Band Communication:** If the attacker may have access to corporate messaging, use pre-arranged out-of-band channels (personal phones, Signal group, physical meeting).

### When to Stop an Attack vs. Risk of Alerting the Attacker

This is one of the most critical judgment calls in incident response.

**Stop immediately when:**
- Active data exfiltration of highly sensitive data is in progress.
- Ransomware is actively encrypting and lateral movement is ongoing.
- Safety of people is at risk (OT/ICS environments).
- Regulatory obligations demand immediate containment.

**Delay containment (observe) when:**
- You need to understand the full scope before acting -- premature containment on one host may cause the attacker to detonate on others.
- The attacker has persistence mechanisms you have not yet identified; killing one C2 channel may trigger a backup.
- Law enforcement has requested continued monitoring.
- You want to identify the attacker's full toolkit and objectives.

**Risk of alerting the attacker:** Attackers who realize they have been detected may accelerate their objectives (deploy ransomware early, wipe logs, destroy evidence). Containment actions like resetting passwords, blocking IPs, or isolating hosts are visible to a sophisticated adversary. Plan your containment to be simultaneous and comprehensive.

### Attacker Cleanup and Evidence Preservation

Attackers often clean up after themselves: clearing event logs, deleting tools, timestomping files. Your response must:

1. Preserve volatile evidence first (memory dumps, network connections, running processes).
2. Capture disk images before remediation.
3. Centralize logs in a tamper-proof location (SIEM, write-once storage).
4. Assume any system the attacker touched may have had its logs altered.

### Priority Metrics

Use these to drive decision-making:

- **MTTD (Mean Time to Detect):** How long from compromise to detection?
- **MTTC (Mean Time to Contain):** How long from detection to stopping the bleeding?
- **MTTR (Mean Time to Recover):** How long until normal operations resume?
- **Blast Radius:** How many systems, users, or data records are affected?
- **Business Impact:** Revenue loss, SLA violations, regulatory exposure.

### Playbooks

Playbooks are pre-written, step-by-step response procedures for common incident types. They reduce decision fatigue and ensure consistency.

Common playbooks to maintain:
- Phishing (credential harvesting, malware delivery)
- Ransomware
- Unauthorized access / compromised credentials
- Data exfiltration
- DDoS
- Insider threat
- Cloud misconfiguration / exposure
- Supply chain compromise

Each playbook should include: detection criteria, initial triage steps, containment actions, eradication steps, recovery procedures, and communication templates.

### Interview Tip

Interviewers love candidates who mention playbooks unprompted. Say: "In my experience, having pre-built playbooks for common scenarios like phishing or ransomware dramatically reduces response time and ensures we don't miss steps under pressure."

---

## Important Knowledge Areas

### Alert Types and Triggers

Understanding what generates alerts is fundamental to effective triage.

| Source | Example Alerts |
|---|---|
| **SIEM** | Correlation rules firing (e.g., brute force followed by successful login), threshold alerts |
| **EDR** | Process injection, suspicious PowerShell, credential dumping (LSASS access) |
| **Network (IDS/IPS)** | Known exploit signatures, C2 beacon patterns, DNS tunneling |
| **Cloud** | Impossible travel, new OAuth app consent, IAM policy changes, S3 bucket made public |
| **DLP** | Large file transfers, sensitive data patterns leaving the network |
| **User Reports** | Phishing emails, suspicious behavior from colleagues, unexpected MFA prompts |

### Root Cause Analysis

Root cause analysis (RCA) answers "why did this happen?" not just "what happened?" Use the **5 Whys** technique:

1. Why was the server compromised? -- The attacker exploited a known vulnerability.
2. Why was the vulnerability present? -- The patch had not been applied.
3. Why was the patch not applied? -- The server was not in the patch management inventory.
4. Why was it not in the inventory? -- It was provisioned outside the standard process.
5. Why was it provisioned outside the process? -- There was no enforcement mechanism for the provisioning policy.

Root cause: Lack of automated enforcement for server provisioning standards.

### Cyber Kill Chain Stages in Incident Context

During an incident, mapping attacker activity to the kill chain helps you understand where you are and what comes next:

1. **Reconnaissance:** Attacker gathered info (may only be visible in hindsight through OSINT or scanning logs).
2. **Weaponization:** Attacker prepared the payload (typically invisible to defenders).
3. **Delivery:** Phishing email, watering hole, exploit kit -- this is often the first observable event.
4. **Exploitation:** Vulnerability triggered -- look for exploit artifacts, crash dumps, anomalous process behavior.
5. **Installation:** Persistence established -- new services, scheduled tasks, registry keys, startup items.
6. **Command and Control:** Outbound beaconing -- DNS anomalies, HTTP/S to unusual domains, periodic callback patterns.
7. **Actions on Objectives:** Data exfiltration, lateral movement, privilege escalation, destruction.

### Symptom vs. Cause

A critical thinking skill: the alert you received is almost never the root cause.

- **Symptom:** "Antivirus quarantined a file on a workstation."
- **Cause:** The user clicked a phishing link, downloaded a dropper, which fetched the payload that AV caught. The attacker may already have other footholds.

Always ask: "Is this the beginning of the story, or the middle?"

### First Principles vs. Systems Knowledge

- **First Principles:** Understanding how things work at a fundamental level (how does DNS resolution work? how does Kerberos authentication flow?). Allows you to reason about novel attacks.
- **Systems Knowledge:** Understanding your specific environment (what tools you have, how they are configured, what is normal). Allows you to investigate efficiently.

You need both. First principles let you understand what the attacker is doing. Systems knowledge lets you find the evidence.

### Building Timelines

The incident timeline is the single most important artifact you produce.

1. Collect timestamps from all sources (logs, alerts, user reports, file metadata).
2. Normalize to a single timezone (UTC).
3. Order chronologically.
4. Identify gaps -- missing time ranges often indicate log deletion or blind spots.
5. Correlate across data sources (SIEM event at 14:32 + EDR alert at 14:33 + firewall log at 14:31 = same activity).
6. Present the timeline visually when briefing stakeholders.

### Assuming Good Intent

In insider threat scenarios, always start by assuming good intent. The "suspicious" activity may have a legitimate explanation. Before escalating an insider threat investigation:

1. Verify the activity is actually anomalous (not a new job responsibility, not a one-time project).
2. Check with the employee's manager discreetly (if appropriate and if the manager is not the subject).
3. Involve HR before confronting anyone.
4. Document your reasoning for why you escalated or did not escalate.

Wrongly accusing an employee destroys trust and can create legal liability.

### Preventing Future Incidents

Every incident should produce actionable improvements:

- Patch the specific vulnerability or misconfiguration.
- Update detection rules to catch this attack earlier.
- Improve playbooks based on what worked and what did not.
- Conduct training if human error was a factor.
- Implement architectural changes if the root cause is systemic.

---

## Response Models: SANS PICERL

### Explanation

The SANS Institute defines six phases of incident response, commonly abbreviated as PICERL:

### 1. Preparation

Everything you do before an incident occurs.

- Develop and maintain an incident response plan (IRP).
- Build and train the incident response team.
- Deploy and tune detection tools (SIEM, EDR, NDR).
- Establish communication plans and escalation paths.
- Conduct tabletop exercises and red team engagements.
- Ensure legal agreements and retainer contracts are in place (forensics firms, outside counsel).
- Maintain jump bags (forensic tools, documentation, contact lists).

### 2. Identification

Detecting that an incident is occurring and determining its scope.

- Monitor alerts from all detection sources.
- Validate that the alert is a true positive.
- Determine the initial scope: what systems, what data, what users.
- Classify severity.
- Begin documentation and timeline.
- Assign incident roles.

### 3. Containment

Stopping the incident from spreading while preserving evidence.

**Short-term containment:**
- Isolate affected systems from the network (EDR network isolation, VLAN changes, firewall rules).
- Block known malicious IPs, domains, and hashes.
- Disable compromised accounts.
- Redirect DNS for C2 domains to a sinkhole.

**Long-term containment:**
- Apply temporary fixes to keep business running while you prepare for eradication.
- Stand up clean replacement systems if needed.
- Implement enhanced monitoring on adjacent systems.

### 4. Eradication

Removing the attacker's presence entirely.

- Remove malware, backdoors, web shells, and persistence mechanisms.
- Patch the vulnerability that allowed initial access.
- Reset all potentially compromised credentials (not just the ones you confirmed).
- Verify removal through scanning and manual review.
- Rebuild systems from known-good images if integrity cannot be assured.

### 5. Recovery

Restoring systems to normal operations.

- Bring cleaned or rebuilt systems back online in a controlled manner.
- Monitor recovered systems intensively for signs of re-compromise.
- Validate that business functions are operating correctly.
- Gradually reduce enhanced monitoring as confidence grows.
- Confirm with stakeholders that operations are restored.

### 6. Lessons Learned

The most important and most frequently skipped phase.

- Conduct a post-incident review (blameless postmortem) within 5 business days.
- Document the complete timeline.
- Identify what worked well and what did not.
- Produce specific, actionable recommendations with owners and deadlines.
- Update playbooks, detection rules, and the incident response plan.
- Share sanitized findings with the broader organization if appropriate.

### References

- NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide
- SANS Incident Handler's Handbook
- SANS FOR508: Advanced Incident Response, Threat Hunting, and Digital Forensics

---

## Response Models: Google IMAG

### Explanation

Google's Incident Management at Google (IMAG) framework, documented in the Google SRE book, applies site reliability engineering principles to incident management. Key concepts:

**Structured Incident Management:**
- Every incident gets a clear **Incident Commander** who manages the response, not the technical work.
- Separation of roles is strict: the IC does not debug. The person debugging does not communicate with stakeholders.
- Handoffs are explicit and acknowledged.

**Key Principles:**

1. **Recursive Separation of Responsibilities:** As incidents grow, roles are subdivided. One IC becomes an IC with a Communications Lead and an Operations Lead, each of whom may further delegate.
2. **Well-Defined Roles:**
   - **Incident Commander:** Coordinates response, assigns roles, makes decisions.
   - **Operations Lead (Ops Lead):** Directs hands-on technical work.
   - **Communications Lead:** Manages stakeholder updates.
   - **Planning Lead:** Tracks longer-running tasks and resources (for extended incidents).
3. **Live Incident State Document:** A shared document updated in real time that serves as the single source of truth.
4. **Regular Handoffs:** For incidents lasting more than a few hours, structured handoffs prevent fatigue-induced errors.
5. **Declared Incident Levels:** Clear thresholds for declaring and escalating incidents.

**Comparison with PICERL:**

| Aspect | PICERL | IMAG |
|---|---|---|
| **Focus** | Security incidents | Reliability and security incidents |
| **Phases** | Linear six-phase model | Role-based concurrent model |
| **Strength** | Comprehensive handling methodology | Operational coordination at scale |
| **Best for** | Security teams following a structured process | Large organizations with complex systems |

In practice, mature teams combine both: use PICERL as the process framework and IMAG as the operational coordination model.

### References

- Google SRE Book, Chapter 14: Managing Incidents
- Google SRE Workbook, Chapter 9: Incident Response

---

## Complete Scenario Walkthrough (PICERL)

### Scenario: Credential Phishing Leading to Data Exfiltration

**Company context:** A mid-size SaaS company with 500 employees, hosting customer data in AWS. They have a SIEM (Splunk), EDR (CrowdStrike), and an identity provider (Okta).

---

#### Phase 1: Preparation (Before the Incident)

The security team has:
- An incident response plan reviewed quarterly.
- Playbooks for phishing, ransomware, and unauthorized access.
- A Slack channel naming convention: `#incident-YYYY-MM-DD-short-description`.
- An on-call rotation with a pager (PagerDuty).
- A retainer contract with an external forensics firm.
- Tabletop exercises conducted twice a year.
- Phishing simulation training for all employees.

---

#### Phase 2: Identification

**Day 0, 09:15 UTC:** The SIEM generates an alert: "Impossible travel detected -- user `jdoe@company.com` authenticated from New York at 09:00 and from Lagos, Nigeria at 09:14."

**09:17 UTC:** The on-call analyst reviews the alert.
- Checks Okta logs: confirms two successful authentications 14 minutes apart from geolocated IPs in different continents.
- Checks whether `jdoe` has a VPN or travel scheduled: no travel on calendar, no VPN IP match.
- Checks the Lagos IP against threat intelligence: the IP is associated with a known phishing infrastructure provider.

**09:22 UTC:** Analyst escalates to the security lead. Classification: **P2 -- High Severity** (compromised credential with active unauthorized access).

**09:25 UTC:** Incident Commander is assigned. Slack channel `#incident-2026-04-12-jdoe-compromise` is created. Scribe begins the timeline document.

**09:28 UTC:** IC assigns roles:
- **Technical Lead:** Senior security engineer
- **Communications Lead:** Security manager
- **Scribe:** Junior analyst

**09:30 UTC:** Technical Lead begins deeper investigation:
- Pulls all Okta activity for `jdoe` in the last 48 hours.
- Discovers that `jdoe` received an email at 08:45 UTC containing a link to `company-login.evil-domain.com`. Jdoe clicked the link at 08:52 and entered credentials.
- The phishing page proxied the real Okta login, capturing the session token and MFA code (adversary-in-the-middle / AiTM phishing).
- From 09:14 onward, the attacker's session shows access to: internal wiki, Salesforce (via SSO), and AWS console (via SSO).

**09:35 UTC:** Technical Lead reports: "This is an AiTM phishing compromise. The attacker has an active session and is browsing internal resources. PII exposure is probable given Salesforce access."

**09:36 UTC:** IC notifies legal and the DPO because Salesforce contains customer PII. The notification clock starts.

---

#### Phase 3: Containment

**09:38 UTC -- Short-term containment actions (executed simultaneously):**

1. **Revoke all active sessions for `jdoe` in Okta.** This immediately terminates the attacker's SSO access to all integrated applications.
2. **Reset `jdoe`'s Okta password and MFA factors.** Prevent the attacker from re-authenticating.
3. **Block the phishing domain** (`company-login.evil-domain.com`) at the web proxy, DNS resolver, and email gateway.
4. **Block the Lagos IP range** at the WAF and cloud security groups.
5. **Place a litigation hold** on all relevant logs (legal requirement once breach is suspected).

**09:42 UTC:** Technical Lead confirms the attacker's sessions are terminated. No new authentication attempts from the adversary IP.

**09:45 UTC:** Broader containment assessment:
- Search email gateway logs: three other employees received the same phishing email. Two did not click. One (`asmith@company.com`) clicked but did not enter credentials (confirmed via Okta -- no authentication from anomalous IP).
- Search SIEM for any other authentication from the Lagos IP block: none found.
- Review `jdoe`'s email sent folder: no evidence the attacker used jdoe's email to send further phishing internally.

**09:50 UTC -- Long-term containment:**
- Enable Okta session binding to device fingerprint for all users (prevents stolen session token reuse).
- Deploy a conditional access policy requiring re-authentication for Salesforce and AWS access from new devices.
- Enhanced monitoring: custom SIEM rule for any authentication from the threat actor's IP ranges, any access to Salesforce export functionality.

---

#### Phase 4: Eradication

**10:00 UTC:** Eradication actions:

1. **Confirm no persistence in Okta:** Review `jdoe`'s account for new API tokens, registered devices, or OAuth app grants the attacker may have created. Finding: the attacker registered a new TOTP device at 09:16. This MFA factor is removed.
2. **Review AWS CloudTrail:** The attacker accessed the AWS console via SSO at 09:20. Actions taken: listed S3 buckets, accessed the `customer-data-prod` bucket, and downloaded a CSV file containing 12,000 customer records (names, emails, company names). No IAM changes were made.
3. **Review Salesforce audit logs:** The attacker viewed 47 customer account pages but did not export data.
4. **Scan `jdoe`'s workstation with CrowdStrike:** No malware found. The attack was purely credential-based.
5. **Verify the phishing domain is blocked** across all layers.
6. **Issue a company-wide phishing alert** with the specific lure details so employees can report if they interacted with it.

**10:30 UTC:** IC confirms: the attacker's access has been fully removed. No persistence mechanisms remain. The scope is defined: 12,000 customer records confirmed exfiltrated.

---

#### Phase 5: Recovery

**10:35 UTC:** Recovery actions:

1. **Restore `jdoe`'s access** with new credentials, new MFA enrollment conducted in person with IT.
2. **Brief `jdoe`** on what happened (assume good intent -- jdoe is a victim, not a suspect).
3. **Monitor `jdoe`'s account** with enhanced alerting for 30 days.
4. **Monitor the exfiltrated data:** Set up dark web monitoring for the 12,000 customer records.
5. **Confirm all business operations are normal.** Salesforce and AWS access verified functional for all users.

**11:00 UTC:** IC downgrades incident to monitoring phase.

---

#### Phase 6: Lessons Learned

**April 17, 2026 (5 days later):** Blameless post-incident review.

**Attendees:** IC, Technical Lead, Communications Lead, CISO, DPO, IT Director, `jdoe`'s manager.

**Timeline reviewed:** Complete timeline from phishing email delivery to full recovery.

**What went well:**
- Detection was fast (30 minutes from compromise to detection via impossible travel rule).
- Containment was decisive (sessions revoked within 23 minutes of detection).
- Roles were clearly assigned and followed the IMAG model.
- Legal was notified early, enabling timely regulatory notification.

**What did not go well:**
- The AiTM phishing bypassed MFA. The organization relied on TOTP-based MFA, which is vulnerable to session hijack.
- The S3 bucket `customer-data-prod` did not have data access logging enabled by default, slowing the investigation by 15 minutes.
- No DLP alert fired on the S3 download because DLP was only configured for network egress, not cloud-native access.

**Action items:**

| Action | Owner | Deadline |
|---|---|---|
| Migrate to phishing-resistant MFA (FIDO2/WebAuthn) for all users | IT Director | June 30 |
| Enable S3 server access logging and CloudTrail data events for all sensitive buckets | Cloud Security Lead | April 30 |
| Deploy CASB or native DLP for cloud data access patterns | Security Engineering Lead | May 31 |
| Conduct AiTM phishing awareness training | Security Awareness Lead | May 15 |
| Update phishing playbook with AiTM-specific steps | Incident Response Lead | April 24 |

**Regulatory notification:** GDPR notification submitted to the supervisory authority within 48 hours. Affected customers notified within 72 hours with a clear explanation and free credit monitoring offer.

---

## Templates and Checklists

### Incident Declaration Checklist

```
[ ] Alert validated as true positive
[ ] Severity classified (P1/P2/P3/P4)
[ ] Incident Commander assigned
[ ] Communication channel created
[ ] Scribe assigned, timeline started
[ ] Roles assigned: Technical Lead, Comms Lead, SMEs
[ ] Stakeholder notification per severity matrix:
    [ ] P1: CISO, VP Eng, Legal, DPO within 15 minutes
    [ ] P2: Security Manager, Legal (if PII), DPO (if PII) within 30 minutes
    [ ] P3: Security Lead within 1 hour
    [ ] P4: Documented in ticketing system, reviewed next business day
[ ] Initial scope documented
[ ] Evidence preservation initiated
```

### Stakeholder Update Template

```
INCIDENT UPDATE -- [Incident ID] -- [Severity]
Time: [UTC timestamp]
Status: [Investigating / Contained / Eradicated / Recovered / Closed]

Summary:
[2-3 sentences on current state]

Impact:
- Systems affected: [list]
- Data affected: [type and estimated volume]
- Users affected: [count and description]

Actions taken since last update:
- [Action 1]
- [Action 2]

Next steps:
- [Planned action 1 with ETA]
- [Planned action 2 with ETA]

Next update: [time]
Incident Commander: [name]
```

### Post-Incident Review Template

```
INCIDENT POST-MORTEM -- [Incident ID]
Date of incident: [date]
Date of review: [date]
Severity: [level]
Duration: [detection to resolution]

1. Executive Summary
   [3-5 sentences covering what happened, impact, and resolution]

2. Timeline
   [Chronological list of events with UTC timestamps]

3. Root Cause
   [5 Whys analysis or equivalent]

4. Impact Assessment
   - Systems: [list]
   - Data: [type, volume]
   - Users: [count]
   - Business: [revenue, SLA, reputation]
   - Regulatory: [notifications required/sent]

5. What Went Well
   - [item]

6. What Needs Improvement
   - [item]

7. Action Items
   | Action | Owner | Deadline | Status |
   |--------|-------|----------|--------|

8. Metrics
   - Time to detect: [duration]
   - Time to contain: [duration]
   - Time to recover: [duration]
```

### Severity Classification Matrix

```
P1 - CRITICAL
  - Active data exfiltration of sensitive data
  - Ransomware spreading across systems
  - Complete loss of a critical service
  - Safety risk to personnel
  Response: All hands, immediate executive notification

P2 - HIGH
  - Confirmed compromise with potential data access
  - Single critical system unavailable
  - Attacker has active foothold but limited access
  Response: Dedicated team, management notified within 30 min

P3 - MEDIUM
  - Suspicious activity requiring investigation
  - Compromised non-sensitive system
  - Policy violation with security implications
  Response: Assigned analyst, tracked in ticketing system

P4 - LOW
  - Isolated malware caught by AV
  - Failed attack attempts
  - Minor policy violations
  Response: Documented, reviewed in daily triage
```

---

## Key Takeaways

1. **Classify early:** Distinguish between security and privacy incidents immediately -- it changes your obligations and stakeholders.
2. **Roles matter more than tools:** Clear role assignment (IC, Tech Lead, Comms Lead, Scribe) prevents chaos. One person should never do everything.
3. **Communicate proactively:** Regular updates, even when there is no news, maintain stakeholder confidence. Silence is worse than "no change."
4. **Preserve before you remediate:** Volatile evidence disappears. Memory dumps and disk images come before cleanup.
5. **Think before you contain:** Premature containment can alert the attacker and cause them to accelerate or destroy evidence. Plan containment to be comprehensive and simultaneous.
6. **The timeline is your most valuable artifact:** A well-constructed, UTC-normalized timeline across all data sources tells the story.
7. **Lessons learned is not optional:** Every incident that does not produce actionable improvements is a wasted opportunity. Assign owners and deadlines.
8. **Playbooks reduce decision fatigue:** Pre-built procedures for common incidents let you act quickly and consistently under pressure.
9. **PICERL gives you structure; IMAG gives you coordination:** Use both. PICERL for the process, IMAG for managing people and communication.
10. **Root cause, not symptoms:** Always ask "why did this happen?" not just "what happened?" The 5 Whys technique prevents superficial fixes.

## Interview Practice Questions

1. **Walk me through how you would respond to a phishing incident where an employee entered their credentials on a fake login page.** (Demonstrate PICERL structure, mention AiTM risk, session revocation, scope assessment, and regulatory notification.)

2. **You discover an attacker has been in your network for 3 months. What do you do?** (Emphasize scoping before containment, coordinated eradication, the risk of alerting the attacker, and the importance of understanding their full footprint.)

3. **How do you decide whether to immediately contain an incident or continue monitoring the attacker?** (Discuss data sensitivity, business risk, legal obligations, law enforcement considerations, and the attacker's position in the kill chain.)

4. **What is the difference between a privacy incident and a security incident? Give an example of each that is not the other.** (Security-only: cryptominer on internal server. Privacy-only: employee accidentally emails customer PII to wrong recipient.)

5. **You are the Incident Commander and the CEO calls demanding to know what is happening. How do you handle this?** (Redirect to the Communications Lead, provide a brief factual summary, commit to a timeline for the next update. Do not speculate or provide unverified information.)

6. **Describe a time when an incident's root cause was different from the initial symptoms.** (Use the AV-quarantine example: the quarantined file was the symptom, the phishing email was the delivery, and the lack of MFA was the root cause enabling the compromise.)

7. **How would you build an incident response program from scratch at a company that has never had one?** (Start with the plan and team, then playbooks for the top 5 scenarios, then tools and detection, then exercises. Reference NIST SP 800-61 as the framework.)

8. **What metrics would you use to measure your incident response program's effectiveness?** (MTTD, MTTC, MTTR, number of incidents by severity, percentage of incidents with completed postmortems, percentage of action items completed on time.)

---

### References

- NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide
- SANS Incident Handler's Handbook (GCIH)
- SANS FOR508: Advanced Incident Response, Threat Hunting, and Digital Forensics
- Google SRE Book, Chapter 14: Managing Incidents
- Google SRE Workbook, Chapter 9: Incident Response
- Lockheed Martin Cyber Kill Chain
- MITRE ATT&CK Framework
- GDPR Articles 33 and 34 (Breach Notification)

---
[Previous: Digital Forensics](digital-forensics.md) | [Next: Coding & Algorithms](coding-algorithms.md)
