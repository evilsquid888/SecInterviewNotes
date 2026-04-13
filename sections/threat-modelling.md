# Threat Modelling - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#threat-modelling)

> **Prerequisites:** [Attack Structure](attack-structure.md), [Web Application](web-application.md)  
> **Difficulty:** Intermediate

---

## Table of Contents

1. [What Is Threat Modelling?](#what-is-threat-modelling)
2. [When to Do Threat Modelling](#when-to-do-threat-modelling)
3. [The Threat Modelling Process](#the-threat-modelling-process)
4. [Frameworks Overview](#frameworks-overview)
   - [STRIDE](#stride)
   - [DREAD](#dread)
   - [MITRE ATT&CK](#mitre-attck)
   - [Threat Matrix](#threat-matrix)
   - [PASTA](#pasta)
   - [TRIKE](#trike)
   - [OCTAVE](#octave)
   - [MAESTRO](#maestro)
5. [Complete Worked Example: STRIDE on a Web Banking Application](#complete-worked-example-stride-on-a-web-banking-application)
6. [Framework Comparison](#framework-comparison)
7. [Talk Reference: "Defense Against the Dark Arts" by Lilly Ryan](#talk-reference-defense-against-the-dark-arts-by-lilly-ryan)
8. [Key Takeaways](#key-takeaways)
9. [Interview Practice Questions](#interview-practice-questions)

---

## What Is Threat Modelling?

Threat modelling is a structured process for identifying, quantifying, and addressing security threats to a system. It asks four fundamental questions:

1. **What are we building?** - Understand the system architecture.
2. **What can go wrong?** - Identify threats systematically.
3. **What are we going to do about it?** - Propose mitigations.
4. **Did we do a good enough job?** - Validate and iterate.

Threat modelling is **proactive** security: you find problems before attackers do, at design time rather than after deployment.

---

## When to Do Threat Modelling

Threat modelling is not a one-time activity. It should be performed at multiple stages throughout the software development lifecycle.

### Feature Prioritization

- When new features are proposed, threat modelling helps the team understand the security implications **before** committing to a design.
- Product managers and security engineers collaborate to determine whether a feature introduces unacceptable risk.
- Threat models can influence whether a feature ships, gets redesigned, or is deprioritised.

### Design Phase (Most Critical)

- The **design phase** is the single most impactful time to perform threat modelling.
- Changes at this stage are cheap. Fixing a design flaw after deployment can be 100x more expensive.
- Security architects should be embedded in design reviews, not bolted on after the fact.
- Produces artifacts (DFDs, threat lists) that feed into secure development and testing.

### Threat Hunting

- Existing systems benefit from threat modelling when the security team is actively hunting for gaps.
- Reverse-engineer the architecture, build a DFD, and systematically walk through threat categories.
- Particularly useful after a breach or near-miss to ensure similar vectors are covered.

### Risk Assessments

- Threat models feed directly into formal risk assessments (ISO 27001, SOC 2, etc.).
- The output (identified threats + mitigations) maps to risk registers with likelihood and impact scores.
- Regulatory and compliance requirements may mandate periodic threat modelling for critical systems.

### Continuous / Agile Threat Modelling

- In modern CI/CD environments, threat modelling should be **incremental**: re-evaluate when architecture changes, not from scratch every sprint.
- Use "threat model as code" approaches where the model lives alongside the codebase and is updated with PRs.

> **Interview Tip:** If asked "when should you threat model?", the strongest answer is "as early as possible in the design phase, and then continuously as the system evolves." Mention that it is most cost-effective during design but also valuable retroactively.

---

## The Threat Modelling Process

Regardless of which framework you choose, the core process follows these steps:

### Step 1: Architecture Review

- Gather all available documentation: architecture diagrams, API specs, network topology, data flow descriptions.
- Interview developers and architects to fill gaps.
- Understand the technology stack, deployment model (on-prem, cloud, hybrid), and third-party dependencies.

### Step 2: Build a Data Flow Diagram (DFD)

A DFD visualises how data moves through the system. It uses four element types:

| Symbol | Element | Description |
|--------|---------|-------------|
| Rectangle | **External Entity** | Users, third-party systems, anything outside your control |
| Rounded Rectangle | **Process** | Code that transforms or acts on data |
| Parallel Lines | **Data Store** | Databases, files, caches, message queues |
| Arrow | **Data Flow** | Movement of data between elements |

**Levels of detail:**
- **DFD Level 0 (Context Diagram):** The entire system as a single process with external entities.
- **DFD Level 1:** Major subsystems and their interactions.
- **DFD Level 2+:** Detailed breakdown of individual subsystems.

### Step 3: Identify Trust Boundaries

Trust boundaries are lines on the DFD where the level of trust changes. Examples:

- Between the internet and your load balancer (network boundary).
- Between the web server and the database (privilege boundary).
- Between your service and a third-party API (organisational boundary).
- Between user-space and kernel-space.
- Between different microservices if they run with different privileges.

**Every data flow that crosses a trust boundary is a candidate for threats.** This is the most important insight in threat modelling.

### Step 4: List Threats

Apply your chosen framework (STRIDE, PASTA, etc.) to each element and data flow. Focus especially on trust boundary crossings.

For each threat, document:
- **Threat ID** (e.g., T-001)
- **Category** (e.g., Spoofing, Tampering)
- **Description** (what could go wrong)
- **Affected Component** (which DFD element)
- **Severity** (High / Medium / Low, or use DREAD scoring)

### Step 5: Propose Mitigations

For each threat, propose one or more mitigations:

| Mitigation Strategy | Description |
|---------------------|-------------|
| **Mitigate** | Implement a control (e.g., add authentication) |
| **Eliminate** | Remove the feature or component |
| **Transfer** | Shift risk to another party (e.g., insurance, SaaS provider) |
| **Accept** | Document the risk and accept it with stakeholder sign-off |

### Step 6: Validate

- Review the threat model with the development team.
- Ensure mitigations are tracked in the backlog.
- Re-assess after implementation to confirm mitigations are effective.
- Penetration testing can validate that identified threats are actually mitigated.

> **Interview Tip:** Walk through this six-step process confidently. Interviewers want to see that you have a repeatable, structured method -- not that you just "think of attacks."

---

## Frameworks Overview

### STRIDE

**Origin:** Developed by Microsoft (Loren Kohnfelder and Praerit Garg, 1999). The most widely used threat classification framework.

**Explanation:**

STRIDE is a mnemonic for six categories of threats. Each category maps to a violated security property:

| Threat | Security Property Violated | Description |
|--------|---------------------------|-------------|
| **S**poofing | Authentication | Pretending to be someone or something else |
| **T**ampering | Integrity | Modifying data or code without authorisation |
| **R**epudiation | Non-repudiation | Denying having performed an action |
| **I**nformation Disclosure | Confidentiality | Exposing data to unauthorised parties |
| **D**enial of Service | Availability | Making a system unavailable |
| **E**levation of Privilege | Authorisation | Gaining capabilities beyond what is granted |

**Step-by-Step: How to Apply STRIDE**

1. **Draw the DFD** with trust boundaries marked.
2. **For each DFD element**, walk through all six STRIDE categories and ask: "Could this happen here?"
   - External entities are primarily susceptible to **Spoofing** and **Repudiation**.
   - Processes are susceptible to **all six** categories.
   - Data stores are primarily susceptible to **Tampering**, **Information Disclosure**, and **Denial of Service**.
   - Data flows are primarily susceptible to **Tampering**, **Information Disclosure**, and **Denial of Service**.
3. **Document each identified threat** with a description and affected component.
4. **Rate severity** (optionally using DREAD).
5. **Propose mitigations** for each threat.

**STRIDE-per-Element mapping:**

| Element Type | S | T | R | I | D | E |
|-------------|---|---|---|---|---|---|
| External Entity | X | | X | | | |
| Process | X | X | X | X | X | X |
| Data Store | | X | | X | X | |
| Data Flow | | X | | X | X | |

This table reduces noise: you only consider threats relevant to each element type.

### DREAD

**Origin:** Also Microsoft. Used for **scoring** threats identified by STRIDE or other methods.

**Explanation:**

DREAD assigns a 1-10 score across five dimensions:

| Dimension | Question | Score Guide |
|-----------|----------|-------------|
| **D**amage | How severe is the impact? | 1 = minimal, 10 = complete system compromise |
| **R**eproducibility | How easy is it to reproduce? | 1 = very difficult, 10 = every time |
| **E**xploitability | How easy is it to exploit? | 1 = requires deep expertise, 10 = trivial |
| **A**ffected Users | How many users are impacted? | 1 = single user, 10 = all users |
| **D**iscoverability | How easy is it to find? | 1 = very obscure, 10 = publicly known |

**Overall DREAD Score** = (D + R + E + A + D) / 5

| Score Range | Risk Level | Action |
|-------------|------------|--------|
| 1 - 3.9 | Low | Monitor, accept, or fix in future release |
| 4 - 6.9 | Medium | Plan remediation in near-term |
| 7 - 10 | High / Critical | Fix immediately before release |

**Step-by-Step:**

1. Take each threat from your STRIDE analysis.
2. Score each of the five DREAD dimensions (1-10).
3. Calculate the average.
4. Rank threats by score to prioritise mitigation effort.

> **Note:** DREAD has been criticised for subjectivity. Microsoft itself moved away from it. Many teams now use simpler High/Medium/Low or CVSS-style scoring. However, DREAD remains a popular interview topic.

### MITRE ATT&CK

**Origin:** MITRE Corporation. A comprehensive knowledge base of adversary tactics and techniques based on real-world observations.

**Explanation:**

ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is not a threat modelling methodology per se -- it is a **taxonomy of attacker behaviour**. It catalogues:

- **Tactics:** The adversary's goal (e.g., Initial Access, Persistence, Lateral Movement).
- **Techniques:** How the adversary achieves the tactic (e.g., Phishing, DLL Side-Loading).
- **Sub-techniques:** More specific variations of techniques.
- **Procedures:** Specific implementations observed in the wild (tied to threat groups).

**The ATT&CK Matrix** is organised as a table: tactics as columns, techniques as rows under each tactic.

**14 Enterprise Tactics (in kill-chain order):**

1. Reconnaissance
2. Resource Development
3. Initial Access
4. Execution
5. Persistence
6. Privilege Escalation
7. Defense Evasion
8. Credential Access
9. Discovery
10. Lateral Movement
11. Collection
12. Command and Control
13. Exfiltration
14. Impact

**Step-by-Step: Using ATT&CK for Threat Modelling**

1. **Identify your threat actors** (nation-state, organised crime, insider, script kiddy).
2. **Map relevant ATT&CK techniques** to your system. Use the ATT&CK Navigator tool to visualise coverage.
3. **For each relevant technique**, assess whether your system has detection or prevention controls.
4. **Identify gaps** where you have no coverage.
5. **Prioritise** based on the threat actors most relevant to your organisation and the techniques they are known to use.

**Worked Example (brief):**
For a web banking app, an APT group targeting financial institutions might use:
- T1566 (Phishing) for Initial Access
- T1078 (Valid Accounts) for Persistence
- T1552 (Unsecured Credentials) for Credential Access

You would check: Do we have email filtering? MFA? Secrets management? Log monitoring for these techniques?

### Threat Matrix

The term "Threat Matrix" can refer to several things:

- **MITRE ATT&CK Matrix** (the most common usage) - the tactics x techniques grid described above.
- **Microsoft Threat Matrix for Kubernetes** - an ATT&CK-style matrix specifically for container/K8s threats.
- **Cloud Threat Matrices** - ATT&CK adaptations for AWS, Azure, GCP.
- **Custom Threat Matrices** - organisation-specific grids mapping threats to assets.

**Step-by-Step: Building a Custom Threat Matrix**

1. List your critical assets as columns.
2. List threat categories (from STRIDE, ATT&CK, or custom) as rows.
3. In each cell, note whether the threat applies, existing controls, and gaps.
4. Colour-code: Green (mitigated), Yellow (partial), Red (unmitigated).
5. Use this as a living dashboard for security posture.

### PASTA

**Process for Attack Simulation and Threat Analysis**

**Explanation:**

PASTA is a seven-stage, risk-centric threat modelling methodology. Unlike STRIDE (which is threat-centric), PASTA is **attacker-centric** -- it simulates how an attacker would approach the system.

**Seven Stages:**

| Stage | Name | Activity |
|-------|------|----------|
| 1 | Define Objectives | Identify business objectives, compliance requirements, and security goals |
| 2 | Define Technical Scope | Document the architecture, technologies, and dependencies |
| 3 | Application Decomposition | Build DFDs, identify entry points, trust boundaries, assets |
| 4 | Threat Analysis | Research applicable threats using threat intelligence feeds, CVE databases |
| 5 | Vulnerability Analysis | Map vulnerabilities to threats using scanning, code review, pen test results |
| 6 | Attack Modelling | Build attack trees showing how an attacker chains vulnerabilities |
| 7 | Risk & Impact Analysis | Calculate risk (likelihood x impact), prioritise, propose mitigations |

**Step-by-Step:**

1. Meet with stakeholders to understand business context and risk appetite (Stage 1).
2. Document all technical components and their interactions (Stages 2-3).
3. Research threat intelligence relevant to your industry and tech stack (Stage 4).
4. Run vulnerability scans and correlate findings with identified threats (Stage 5).
5. Build attack trees showing realistic attack paths (Stage 6).
6. Score risks and present prioritised mitigations to stakeholders (Stage 7).

**When to use PASTA:** Large organisations that need business-aligned, risk-driven threat models. More heavyweight than STRIDE but produces richer output.

### TRIKE

**Explanation:**

Trike is a risk-based threat modelling framework that focuses on **acceptable risk** as defined by stakeholders. It uses a requirements model rather than an attacker model.

**Core Concepts:**

- **Actors:** Users and external systems that interact with the application.
- **Assets:** Data and resources that need protection.
- **Actions:** CRUD operations (Create, Read, Update, Delete) that actors perform on assets.
- **Rules:** Which actors are allowed which actions on which assets.

**Step-by-Step:**

1. Build an **actor-asset-action matrix** listing all actors, assets, and permitted CRUD operations.
2. For each cell, define the **intended behaviour** (what should happen) and **threat behaviour** (what an attacker would try).
3. Assign risk values based on stakeholder-defined acceptable risk levels.
4. Any cell where actual risk exceeds acceptable risk is flagged for mitigation.

**When to use Trike:** When you need strong alignment between security requirements and business risk tolerance. Good for compliance-heavy environments.

### OCTAVE

**Operationally Critical Threat, Asset, and Vulnerability Evaluation**

**Origin:** Carnegie Mellon SEI (Software Engineering Institute).

**Explanation:**

OCTAVE is an organisational-level risk assessment framework. It is broader than application-level threat modelling -- it considers people, processes, and technology.

**Three Phases:**

| Phase | Name | Activity |
|-------|------|----------|
| 1 | Build Asset-Based Threat Profiles | Identify critical assets, their owners, security requirements, and threats |
| 2 | Identify Infrastructure Vulnerabilities | Evaluate the technical infrastructure supporting those assets |
| 3 | Develop Security Strategy | Create a protection strategy and mitigation plans |

**Variants:**
- **OCTAVE (original):** Large organisations with dedicated security teams (requires 3-5 month engagement).
- **OCTAVE-S:** Simplified version for small organisations (< 100 people).
- **OCTAVE Allegro:** Streamlined, focuses on information assets. Most commonly used today.

**Step-by-Step (OCTAVE Allegro):**

1. Establish risk measurement criteria (what does "high impact" mean for your org?).
2. Develop information asset profiles (what data matters most?).
3. Identify information asset containers (where does the data live?).
4. Identify areas of concern (brainstorm threat scenarios).
5. Identify threat scenarios (formalise the concerns).
6. Identify risks (likelihood + impact for each scenario).
7. Analyse risks (score and rank).
8. Select mitigation approach (mitigate, defer, accept, transfer).

**When to use OCTAVE:** Enterprise-wide risk assessments, not individual application threat models. Feeds into governance and compliance programs.

### MAESTRO

**Mitigation, Assessment, Evaluation of Security Threats and Risk to Operations**

**Explanation:**

MAESTRO is a newer framework designed for AI and ML systems. It addresses threats unique to machine learning pipelines that traditional frameworks like STRIDE do not cover well.

**Key Areas MAESTRO Addresses:**

- **Data poisoning:** Corrupting training data to influence model behaviour.
- **Model theft/extraction:** Querying a model to reconstruct it.
- **Adversarial inputs:** Crafted inputs that cause misclassification.
- **Supply chain risks:** Compromised pre-trained models or datasets.
- **Privacy leakage:** Models memorising and leaking training data.

**Step-by-Step:**

1. Map the entire ML pipeline: data collection, preprocessing, training, evaluation, deployment, inference.
2. Identify trust boundaries specific to ML (e.g., between training environment and production, between data sources and the pipeline).
3. For each pipeline stage, enumerate MAESTRO-specific threats (data poisoning at ingestion, adversarial inputs at inference, etc.).
4. Assess existing controls and gaps.
5. Propose mitigations (input validation, differential privacy, model monitoring, etc.).

**When to use MAESTRO:** Any system incorporating machine learning or AI components. Use alongside STRIDE for a complete picture -- STRIDE for the traditional application layer, MAESTRO for the ML-specific layer.

---

## Complete Worked Example: STRIDE on a Web Banking Application

### System Description

**SecureBank Online** is a web banking application with the following architecture:

- **Customer (Browser)** - External entity, accesses the system over HTTPS.
- **Web Application Server** - Serves the frontend and handles API requests (Node.js).
- **Authentication Service** - Manages login, MFA, session tokens (microservice).
- **Transaction Service** - Processes transfers, payments, balance queries (microservice).
- **Database** - PostgreSQL storing user accounts, balances, transaction history.
- **Third-Party Payment Gateway** - External service for interbank transfers.
- **Audit Log Service** - Writes immutable logs of all actions.

### Data Flow Diagram (Level 1)

```
                        TRUST BOUNDARY: Internet / DMZ
                        ================================
                        |                              |
  +-----------+         |    +-------------------+     |
  | Customer  |---HTTPS----->| Web App Server    |     |
  | (Browser) |<--HTTPS------| (Node.js)         |     |
  +-----------+         |    +-------------------+     |
                        |        |           |         |
                        =========|===========|==========
                  TRUST BOUNDARY: DMZ / Internal Network
                                 |           |
                        +--------+--+   +----+----------+
                        | Auth      |   | Transaction   |
                        | Service   |   | Service       |
                        +-----+-----+   +----+-----+----+
                              |              |     |
                              +------+-------+     |
                                     |             |
                              +------+------+      |
                              | PostgreSQL  |      |
                              | Database    |      |
                              +-------------+      |
                                                   |
                              TRUST BOUNDARY: Internal / External
                              ==============================
                                                   |
                              +--------------------+----+
                              | Third-Party Payment     |
                              | Gateway                 |
                              +-------------------------+

  (All services write to Audit Log Service, omitted for clarity)
```

### STRIDE Analysis

#### Data Flow: Customer <-> Web App Server (crosses Internet/DMZ boundary)

| ID | Category | Threat | Severity | Mitigation |
|----|----------|--------|----------|------------|
| T-001 | **Spoofing** | Attacker impersonates a legitimate customer by stealing session tokens or credentials. | High | Enforce MFA. Use short-lived JWTs. Bind sessions to IP/device fingerprint. Implement account lockout after failed attempts. |
| T-002 | **Spoofing** | Attacker performs a man-in-the-middle attack, impersonating the web server to the customer. | High | Enforce TLS 1.2+ with HSTS. Pin certificates. Use Certificate Transparency monitoring. |
| T-003 | **Tampering** | Attacker modifies HTTP requests in transit (e.g., changes transfer amount). | High | TLS encryption in transit. Server-side validation of all inputs. CSRF tokens on state-changing operations. |
| T-004 | **Repudiation** | Customer denies initiating a transfer. | Medium | Log all transactions with timestamps, IP, device info, MFA confirmation. Audit logs are append-only and cryptographically signed. |
| T-005 | **Information Disclosure** | Sensitive data (account numbers, balances) exposed in transit. | High | TLS encryption. Remove sensitive data from URL parameters. Use `Cache-Control: no-store` headers. |
| T-006 | **Information Disclosure** | Error messages leak internal implementation details (stack traces, SQL errors). | Medium | Custom error pages. Generic error messages to client. Detailed errors only in server-side logs. |
| T-007 | **Denial of Service** | Attacker floods the web server with requests, making it unavailable to legitimate customers. | High | Rate limiting. WAF. CDN-based DDoS protection. Auto-scaling. CAPTCHA on login. |
| T-008 | **Elevation of Privilege** | Attacker exploits a vulnerability (e.g., SQL injection, SSRF) to gain admin access. | Critical | Input validation. Parameterised queries. Principle of least privilege. Regular security scanning. Secure code review. |

#### Process: Authentication Service

| ID | Category | Threat | Severity | Mitigation |
|----|----------|--------|----------|------------|
| T-009 | **Spoofing** | Attacker brute-forces credentials. | High | Account lockout. Rate limiting. CAPTCHA. MFA enforcement. Monitor for credential stuffing patterns. |
| T-010 | **Spoofing** | Attacker uses stolen credentials from another breach (credential stuffing). | High | Check passwords against known breach databases (e.g., HaveIBeenPwned API). Enforce MFA. Detect anomalous login locations. |
| T-011 | **Tampering** | Attacker modifies authentication tokens to escalate privileges. | Critical | Sign JWTs with strong keys (RS256). Validate signatures server-side on every request. Short token expiry. |
| T-012 | **Repudiation** | Admin denies changing a user's permissions. | Medium | Immutable audit log of all privilege changes with actor identity and timestamp. |
| T-013 | **Information Disclosure** | Authentication tokens leaked via logs, referrer headers, or browser history. | High | Never log tokens. Use `HttpOnly`, `Secure`, `SameSite` cookie flags. Avoid tokens in URLs. |
| T-014 | **Denial of Service** | Attacker triggers mass account lockouts by deliberately failing logins for many accounts. | Medium | Use progressive delays instead of hard lockout. CAPTCHA. Distinguish between targeted and distributed attacks. |
| T-015 | **Elevation of Privilege** | Attacker exploits IDOR to access another user's account by manipulating user IDs in requests. | Critical | Authorisation checks on every request using the authenticated session, not client-supplied user IDs. |

#### Data Store: PostgreSQL Database

| ID | Category | Threat | Severity | Mitigation |
|----|----------|--------|----------|------------|
| T-016 | **Tampering** | Attacker with database access modifies account balances directly. | Critical | Restrict DB access to service accounts only. Use database audit logging. Integrity checks on critical tables. Separate read/write credentials. |
| T-017 | **Information Disclosure** | Database backup or snapshot is exfiltrated. | Critical | Encrypt backups at rest (AES-256). Restrict access to backup storage. Monitor for unusual data access patterns. |
| T-018 | **Information Disclosure** | SQL injection allows attacker to dump database contents. | Critical | Parameterised queries exclusively. ORM with query builder. WAF rules for SQL injection patterns. Regular DAST scanning. |
| T-019 | **Denial of Service** | Attacker triggers expensive queries causing database slowdown. | Medium | Query timeouts. Connection pooling limits. Read replicas. Query plan analysis. Rate limiting at application layer. |

#### Data Flow: Transaction Service <-> Payment Gateway (crosses Internal/External boundary)

| ID | Category | Threat | Severity | Mitigation |
|----|----------|--------|----------|------------|
| T-020 | **Spoofing** | Attacker impersonates the payment gateway, sending fake transaction confirmations. | Critical | Mutual TLS (mTLS) between services. Verify digital signatures on gateway responses. Certificate pinning. |
| T-021 | **Tampering** | Attacker intercepts and modifies transaction amounts or destination accounts in transit to the gateway. | Critical | TLS encryption. Sign transaction payloads. Verify response signatures. Reconciliation processes. |
| T-022 | **Information Disclosure** | Transaction details (account numbers, amounts) exposed to a network-level attacker. | High | TLS 1.2+ for all gateway communications. Tokenise sensitive data where possible. |
| T-023 | **Denial of Service** | Payment gateway becomes unavailable. | Medium | Circuit breaker pattern. Queue transactions for retry. Fallback gateway. Notify customers of delays. |

### DREAD Scoring for Top Threats

| Threat ID | D | R | E | A | D | Score | Priority |
|-----------|---|---|---|---|---|-------|----------|
| T-008 (SQLi -> admin) | 10 | 8 | 6 | 10 | 8 | **8.4** | Critical |
| T-018 (SQLi -> data dump) | 10 | 8 | 6 | 10 | 8 | **8.4** | Critical |
| T-020 (Gateway spoofing) | 10 | 5 | 4 | 10 | 3 | **6.4** | Medium |
| T-011 (Token tampering) | 9 | 7 | 5 | 10 | 6 | **7.4** | High |
| T-001 (Session theft) | 8 | 7 | 6 | 8 | 7 | **7.2** | High |
| T-007 (DDoS) | 7 | 10 | 9 | 10 | 10 | **9.2** | Critical |

### Summary of Mitigations (Prioritised)

1. **Parameterised queries and input validation everywhere** (addresses T-008, T-018).
2. **MFA enforcement for all customers** (addresses T-001, T-009, T-010).
3. **DDoS protection (WAF + CDN + rate limiting)** (addresses T-007, T-014).
4. **JWT signing with RS256 and strict server-side validation** (addresses T-011, T-013).
5. **Mutual TLS with payment gateway** (addresses T-020, T-021, T-022).
6. **Immutable, signed audit logs** (addresses T-004, T-012).
7. **Database encryption at rest and in transit** (addresses T-016, T-017).
8. **Authorisation checks on every endpoint** (addresses T-015).

---

## Framework Comparison

| Criterion | STRIDE | DREAD | MITRE ATT&CK | PASTA | TRIKE | OCTAVE | MAESTRO |
|-----------|--------|-------|---------------|-------|-------|--------|---------|
| **Type** | Threat classification | Risk scoring | Threat knowledge base | Full methodology | Risk-based model | Org-level assessment | AI/ML-specific |
| **Scope** | Application | Per-threat | Enterprise / SOC | Application | Application | Organisation | ML pipelines |
| **Complexity** | Low-Medium | Low | Medium-High | High | Medium | High | Medium |
| **Best For** | Design-phase reviews | Prioritising threats | Detection engineering, threat hunting | Business-risk-aligned modelling | Compliance-driven orgs | Enterprise risk management | AI/ML systems |
| **Output** | List of categorised threats | Numeric risk scores | Coverage heatmap | Attack trees + risk scores | Risk matrix | Security strategy | ML threat catalogue |
| **Used With** | DFDs | STRIDE (as scoring) | Threat intelligence | Standalone | Standalone | Standalone | STRIDE (complementary) |
| **Industry Adoption** | Very High | Declining | Very High | Medium | Low | Medium | Growing |

### Decision Guide: When to Use Which

- **Quick design review for a new feature?** -> STRIDE
- **Need to prioritise a long list of threats?** -> DREAD (or simple High/Medium/Low)
- **Building detection rules for your SOC?** -> MITRE ATT&CK
- **Enterprise-wide risk assessment for the board?** -> OCTAVE
- **Business-driven threat model for a critical app?** -> PASTA
- **Compliance-focused with strict access control requirements?** -> TRIKE
- **Threat modelling an ML pipeline?** -> MAESTRO + STRIDE

---

## Talk Reference: "Defense Against the Dark Arts" by Lilly Ryan

Lilly Ryan's talk draws parallels between historical "threat modelling" (how societies have anticipated and defended against threats throughout history) and modern security practices.

### Key Themes

1. **Threat modelling is fundamentally about empathy** -- understanding the attacker's perspective, motivations, and constraints. You cannot defend against what you cannot imagine.

2. **Historical precedent matters.** Studying past attacks (both digital and pre-digital) reveals patterns that repeat. Attackers exploit trust, social structures, and assumptions -- not just technical vulnerabilities.

3. **The "dark arts" are not magic** -- they are systematic. Just as threat modelling applies structure to security analysis, attackers apply structure to their campaigns. Understanding their frameworks (like ATT&CK) demystifies the threat.

4. **Defenders must think like attackers** but also recognise their own biases. Threat models are only as good as the imagination and diversity of the modelling team. Include people with different backgrounds and perspectives.

5. **Privacy is a security concern.** Ryan emphasises that data collection itself is a threat. The best mitigation for data leakage is not collecting the data in the first place.

### Relevance to Interviews

If asked about this talk, focus on:
- The human element of threat modelling (not purely technical).
- The importance of diverse perspectives in the modelling team.
- How historical patterns inform modern threat analysis.
- Data minimisation as a defensive strategy.

---

## Key Takeaways

1. **Threat modelling is most effective in the design phase** but should be performed continuously as the system evolves.
2. **STRIDE is the go-to framework** for application-level threat modelling in interviews and practice. Learn it thoroughly.
3. **DFDs with trust boundaries** are the foundation of all threat modelling. Every data flow crossing a trust boundary demands scrutiny.
4. **No single framework covers everything.** Combine STRIDE (classification) + DREAD (scoring) + ATT&CK (detection) for comprehensive coverage.
5. **Threat models are living documents.** They should be updated when architecture changes, new features are added, or new threat intelligence emerges.
6. **The four questions** -- What are we building? What can go wrong? What are we doing about it? Did we do a good enough job? -- are the universal starting point regardless of framework.
7. **MAESTRO fills the AI/ML gap** that traditional frameworks miss. As AI systems proliferate, expect this to appear more in interviews.

## Interview Practice Questions

1. **"Walk me through how you would threat model this system."**
   - Start with the four questions. Draw a DFD. Identify trust boundaries. Apply STRIDE. Propose mitigations. Mention validation.

2. **"What is STRIDE? Give an example of each category."**
   - Define each letter, map to the security property it violates, and give a concrete example from a web application (as in the worked example above).

3. **"How do you prioritise threats?"**
   - Mention DREAD scoring or a simpler likelihood x impact matrix. Emphasise that prioritisation should align with business risk, not just technical severity.

4. **"What is a trust boundary? Why does it matter?"**
   - A point where the level of trust changes. It matters because every data flow crossing a trust boundary is a potential attack surface. Give examples: internet/DMZ, user/kernel, service/third-party.

5. **"Compare STRIDE and MITRE ATT&CK."**
   - STRIDE is a design-time threat classification for applications. ATT&CK is a runtime threat knowledge base for detection and response. They complement each other: STRIDE for building secure systems, ATT&CK for defending running systems.

6. **"You are threat modelling a microservices architecture. What are the unique challenges?"**
   - Many more trust boundaries (inter-service communication). Service mesh concerns. API gateway as a critical choke point. Secrets management across services. East-west traffic monitoring.

7. **"A product manager says threat modelling slows down development. How do you respond?"**
   - Quantify the cost of fixing vulnerabilities post-deployment vs. design time (IBM/NIST data: 30-100x more expensive). Position threat modelling as a time-saver, not a blocker. Propose lightweight, incremental approaches for agile teams.

8. **"Threat model a login page."**
   - Spoofing: credential stuffing, phishing. Tampering: modifying login requests. Repudiation: denying login activity. Information Disclosure: timing attacks revealing valid usernames, credentials in logs. DoS: account lockout abuse. EoP: authentication bypass.

---

## References

- [Microsoft Threat Modelling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool) - Official Microsoft Threat Modelling Tool and documentation.
- [OWASP Threat Modelling](https://owasp.org/www-community/Threat_Modeling) - OWASP community guide to threat modelling.
- [OWASP Threat Modelling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) - Quick reference for practitioners.
- [MITRE ATT&CK](https://attack.mitre.org/) - The ATT&CK knowledge base and Navigator tool.
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) - Interactive tool for visualising ATT&CK coverage.
- [Adam Shostack, "Threat Modeling: Designing for Security"](https://shostack.org/resources/threat-modeling) - The definitive book on threat modelling.
- [PASTA Threat Modelling](https://owasp.org/www-pdf-archive/AppSecEU2012_PASTA.pdf) - Original PASTA methodology paper.
- [Carnegie Mellon SEI - OCTAVE](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=13473) - OCTAVE framework documentation.
- [Lilly Ryan - "Defense Against the Dark Arts"](https://www.youtube.com/results?search_query=lilly+ryan+defense+against+the+dark+arts) - Conference talk.

---
[Previous: Attack Structure](attack-structure.md) | [Next: Detection](detection.md)
