# Mitigations - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#mitigations)

> **Prerequisites:** [OS Systems](os-systems.md), [Exploits](exploits.md)  
> **Difficulty:** Intermediate

---

## Table of Contents

1. [Patching](#1-patching)
2. [Data Execution Prevention (DEP)](#2-data-execution-prevention-dep)
3. [Address Space Layout Randomisation (ASLR)](#3-address-space-layout-randomisation-aslr)
4. [Principle of Least Privilege](#4-principle-of-least-privilege)
5. [Code Signing](#5-code-signing)
6. [Compiler Security Features](#6-compiler-security-features)
7. [Encryption of Software and Firmware](#7-encryption-of-software-and-firmware)
8. [Mandatory Access Controls](#8-mandatory-access-controls)
9. [Insecure by Exception Philosophy](#9-insecure-by-exception-philosophy)
10. [Do Not Blame the User Philosophy](#10-do-not-blame-the-user-philosophy)

---

## 1. Patching

### Explanation

Patching is the process of applying updates to software, firmware, or operating systems to fix known vulnerabilities, correct bugs, or improve functionality. It is the single most impactful mitigation an organisation can implement. Patches are released by vendors after a vulnerability is discovered (ideally before it is exploited in the wild) and distributed through package managers, update services (e.g., Windows Update, `apt`, `yum`), or manual deployment.

Patch management at scale involves inventorying assets, prioritising patches by severity (typically using CVSS scores), testing patches in staging environments, deploying them within a defined SLA, and verifying successful application.

### How It Works

1. A vulnerability is discovered and reported (via bug bounty, internal audit, or public disclosure).
2. The vendor develops a fix and releases a patch, often alongside a CVE identifier and advisory.
3. The organisation's vulnerability management tool (e.g., Qualys, Tenable, WSUS) identifies affected systems.
4. Patches are tested in a staging environment to check for regressions.
5. Approved patches are deployed to production systems, typically in priority order (internet-facing first).
6. Post-deployment scans verify that the vulnerability is no longer present.

### Example

```bash
# Debian/Ubuntu -- apply all available security patches
sudo apt update && sudo apt upgrade -y

# Red Hat / CentOS -- apply only security errata
sudo yum update --security -y

# Windows -- force check via PowerShell
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate -Install -AcceptAll
```

Enterprise environments often use tools like SCCM, Ansible, or Chef to orchestrate patch deployment across thousands of hosts with defined maintenance windows.

### What It Prevents

- Exploitation of **known vulnerabilities** (the vast majority of real-world breaches exploit unpatched, known CVEs).
- Wormable attacks such as **EternalBlue / WannaCry** (MS17-010 patch was available months before the outbreak).
- Privilege escalation via known kernel or service bugs.

### Limitations

- **Zero-day vulnerabilities** have no patch available by definition.
- Patches can introduce regressions or break application compatibility, causing organisations to delay deployment.
- Legacy or end-of-life systems may never receive patches.
- Supply-chain attacks can compromise the patch delivery mechanism itself (e.g., the SolarWinds Orion incident).

### Interview Tip

> When asked about the most effective security control, patching is almost always the correct first answer. Emphasise that most breaches exploit *known, patched* vulnerabilities -- the problem is not lack of patches but lack of timely application. Mention a concrete example like WannaCry to illustrate the cost of delayed patching.

### References

- NIST SP 800-40 Rev. 4 -- Guide to Enterprise Patch Management Planning
- CISA Known Exploited Vulnerabilities (KEV) Catalogue
- Microsoft Security Update Guide

---

## 2. Data Execution Prevention (DEP)

### Explanation

Data Execution Prevention (DEP) is a hardware- and software-enforced security feature that marks regions of memory as non-executable. Its purpose is to prevent an attacker from injecting shellcode into a data region (such as the stack or heap) and then redirecting execution to it. On x86-64 processors this is implemented via the **NX bit** (No eXecute) in page table entries; ARM processors use the **XN bit**.

DEP works in conjunction with the OS memory manager. Windows provides both hardware-enforced DEP (using NX/XD) and software-enforced DEP (SafeSEH). Linux implements this through the `noexec` flag on memory mappings.

### How It Works

1. When the OS allocates a page of memory, it sets the NX bit in the page table entry for data pages (stack, heap, data segments).
2. Code pages (.text sections) are marked executable but typically not writable (W^X policy).
3. If the CPU's instruction pointer lands on a page with the NX bit set, the processor raises a hardware exception.
4. The OS catches this exception and terminates the offending process (on Windows, a `STATUS_ACCESS_VIOLATION`; on Linux, a `SIGSEGV`).

### Example

```c
// On Linux, mmap with explicit permissions -- no PROT_EXEC on data buffers
void *buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
// Attempting to execute code placed in 'buf' will trigger SIGSEGV

// On Windows, DEP is enabled system-wide via:
// bcdedit /set {current} nx AlwaysOn
```

```powershell
# Check DEP status on Windows
Get-CimInstance Win32_OperatingSystem | Select-Object DataExecutionPrevention_SupportPolicy
# 3 = AlwaysOn (recommended)
```

### What It Prevents

- **Classic stack-based buffer overflow** exploitation where shellcode is placed on the stack and executed.
- **Heap spraying** attacks that rely on executing code from heap allocations.
- Any attack that depends on executing injected code in a writable data region.

### Limitations

- **Return-Oriented Programming (ROP):** Attackers chain existing executable code snippets ("gadgets") rather than injecting new code, bypassing DEP entirely.
- **JIT spraying:** Just-In-Time compilers (e.g., in browsers) create writable-then-executable pages, which can be abused.
- Does not protect against **logic bugs**, information disclosure, or attacks that corrupt data without executing injected code.
- Some legacy applications require executable data regions and must opt out of DEP.

### Interview Tip

> Always pair DEP with ASLR in your answer. DEP stops injected code from executing, but ROP bypasses it by reusing existing code. ASLR makes ROP harder by randomising where that existing code lives. Together they provide defence in depth. Know the term "W^X" (Write XOR Execute) as the policy underlying DEP.

### References

- Intel Software Developer Manual, Volume 3A -- NX Bit
- Microsoft DEP Documentation
- PaX / grsecurity project (Linux NX enforcement history)

---

## 3. Address Space Layout Randomisation (ASLR)

### Explanation

ASLR randomises the base addresses of key memory regions -- the executable image, shared libraries, the stack, the heap, and memory-mapped files -- each time a process starts. This means an attacker cannot rely on hardcoded addresses when crafting exploits. Without ASLR, the address of `system()` in libc or a particular ROP gadget is predictable across runs and even across machines with the same OS version.

Modern implementations include **full ASLR** (PIE binaries where the main executable is also relocated), **KASLR** (kernel address space randomisation), and **fine-grained ASLR** (randomising at the function or basic-block level, still experimental).

### How It Works

1. At process creation, the OS kernel selects random offsets for the stack, heap, shared library load addresses, and (if PIE) the main executable base.
2. The dynamic linker resolves symbols relative to these randomised bases.
3. An attacker attempting a ROP chain or ret2libc attack must first **leak** a valid pointer to defeat ASLR before constructing the exploit.
4. On each new execution the layout changes, so a leaked address is only useful for that specific process instance.

### Example

```bash
# Check ASLR status on Linux
cat /proc/sys/kernel/randomize_va_space
# 0 = disabled, 1 = partial (stack/mmap), 2 = full (stack/mmap/heap)

# Enable full ASLR
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

# Compile a Position Independent Executable (required for full ASLR on main binary)
gcc -fPIE -pie -o myapp myapp.c
```

```
# Observing ASLR -- run 'ldd' twice on the same binary:
$ ldd /bin/ls
  libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x7f2a3c200000)
$ ldd /bin/ls
  libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x7f8b1a400000)
# Note: different base address each time
```

### What It Prevents

- **Return-to-libc / ret2libc** attacks that jump to known library functions.
- **ROP chains** that depend on predictable gadget addresses.
- **GOT/PLT overwrite** attacks where the attacker needs the address of the Global Offset Table.
- Reduces the reliability of any exploit that requires knowledge of absolute memory addresses.

### Limitations

- **Information leaks** (format string bugs, out-of-bounds reads, side-channels) can reveal randomised addresses, defeating ASLR.
- **Low entropy on 32-bit systems:** Only ~8-16 bits of randomness for some regions, making brute-force feasible (especially for forking servers that do not re-randomise).
- **Non-PIE binaries** are loaded at a fixed address, giving attackers a known code region to pivot from.
- **KASLR** can be defeated by microarchitectural side-channels (e.g., prefetch timing, TLB-based attacks).

### Interview Tip

> Emphasise that ASLR is probabilistic, not deterministic. It raises the *cost* of exploitation but does not make it impossible. A strong answer pairs ASLR with DEP and discusses how an information leak is the typical prerequisite for bypassing ASLR. Mention that 64-bit systems have significantly more entropy than 32-bit, making brute-force impractical.

### References

- PaX ASLR (original implementation, 2001)
- Microsoft ASLR implementation details (Windows Internals, 7th Ed.)
- Linux kernel `randomize_va_space` documentation

---

## 4. Principle of Least Privilege

### Explanation

The Principle of Least Privilege (PoLP) states that every subject (user, process, service) should operate with the minimum set of permissions necessary to perform its function, and no more. If a component is compromised, the blast radius is limited to what that component was authorised to do. This principle applies at every layer: user accounts, service accounts, file permissions, network access, database roles, API scopes, and container capabilities.

A landmark real-world example is **Internet Explorer's Protected Mode** (Vista+), where the browser process ran with the Administrator SID explicitly set to `SE_GROUP_USE_FOR_DENY_ONLY`, meaning even if the user was an admin, IE could not exercise admin privileges. This was later extended with **AppContainer** isolation in IE 10+ and Edge.

### How It Works

1. Identify the minimum permissions a subject needs (read-only access to specific files, network access to specific ports, etc.).
2. Assign only those permissions, explicitly denying everything else.
3. Use separation of duties: split a high-privilege operation into multiple lower-privilege components that communicate via well-defined interfaces.
4. Regularly audit and revoke accumulated permissions (privilege creep).

### Example

```powershell
# Windows: IE Protected Mode ran the broker at Medium Integrity Level
# and the content process at Low Integrity Level with Admin SID denied.
# The Admin SID was set with SE_GROUP_USE_FOR_DENY_ONLY flag:
whoami /groups
# ...
# BUILTIN\Administrators  Alias  S-1-5-32-544  Group used for deny only
```

```bash
# Linux: Run a web server as a dedicated non-root user with limited caps
useradd -r -s /usr/sbin/nologin webworker
# Grant only the capability to bind to port 80, not full root
setcap 'cap_net_bind_service=+ep' /usr/local/bin/mywebserver
sudo -u webworker /usr/local/bin/mywebserver
```

```yaml
# Kubernetes: Drop all capabilities, add back only what is needed
securityContext:
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]
  readOnlyRootFilesystem: true
```

### What It Prevents

- **Privilege escalation** from a compromised low-privilege process to full system control.
- **Lateral movement** -- a compromised service account with minimal network access cannot pivot to other hosts.
- **Accidental damage** -- an admin who normally operates as a standard user is less likely to accidentally delete critical files.
- **Data exfiltration** -- a service that can only read its own database cannot access other datasets.

### Limitations

- Complex to implement correctly at scale; over-restriction causes operational friction and "permission fatigue" where admins grant overly broad access to avoid tickets.
- Does not prevent exploitation of the application within its own privilege boundary.
- Requires ongoing governance; permissions tend to accumulate over time ("privilege creep").
- Kernel vulnerabilities can allow a low-privilege process to escalate regardless of PoLP.

### Interview Tip

> The IE Protected Mode example is excellent for demonstrating PoLP in practice. Explain that even though the user was an administrator, the browser process had the Admin SID set to deny-only, so a browser exploit could not leverage admin privileges. This shows defence in depth: the user has privileges, but the attack surface (the browser) does not.

### References

- Saltzer & Schroeder, "The Protection of Information in Computer Systems" (1975)
- Microsoft Protected Mode / AppContainer documentation
- CIS Benchmarks (least privilege recommendations per platform)

---

## 5. Code Signing

### Explanation

Code signing is the process of applying a cryptographic digital signature to executables, drivers, scripts, or firmware so that their authenticity and integrity can be verified before execution. The signature proves that the code comes from a known publisher and has not been tampered with since signing. In **kernel mode**, code signing is mandatory on modern Windows (64-bit) and macOS -- unsigned drivers simply cannot be loaded.

The signing process uses asymmetric cryptography: the developer signs with a private key, and the OS verifies with the corresponding public key (typically via a certificate chain rooted in a trusted CA). Timestamping ensures signatures remain valid even after the signing certificate expires.

### How It Works

1. The developer compiles the code and computes a cryptographic hash of the binary.
2. The hash is signed with the developer's private key, producing a digital signature.
3. The signature and the developer's certificate are embedded in the binary (e.g., Authenticode for PE files, codesign for Mach-O).
4. At load time, the OS or bootloader verifies the signature against a trusted certificate store.
5. If verification fails (invalid signature, revoked certificate, tampered binary), the OS refuses to load the code or warns the user.

### Example

```powershell
# Windows: Sign a kernel driver with signtool
signtool sign /v /fd sha256 /tr http://timestamp.digicert.com /td sha256 ^
  /f MyCert.pfx /p MyPassword mydriver.sys

# Verify a signed binary
signtool verify /pa /v mydriver.sys

# Check Windows Driver Signature Enforcement status
bcdedit /enum {current} | findstr "testsigning"
# testsigning = No (enforced, production default)
```

```bash
# macOS: Sign a binary
codesign --sign "Developer ID Application: MyCompany" --timestamp myapp

# Verify
codesign --verify --deep --strict myapp
```

### What It Prevents

- **Unsigned malware** from loading as a kernel driver (kernel-mode code signing).
- **Tampering** with legitimate binaries (supply chain integrity).
- **Impersonation** -- an attacker cannot sign code as Microsoft or Apple without stealing or forging a certificate.
- **Rootkits** that modify system files; the modified files will fail signature verification.

### Limitations

- **Stolen or leaked signing keys** allow attackers to sign malicious code (e.g., Stuxnet used stolen Realtek and JMicron certificates).
- **Certificate Authority compromise** can undermine the entire trust chain.
- Does not verify that the signed code is *safe*, only that it is *authentic and unmodified*. Legitimately signed software can contain vulnerabilities.
- Revocation (CRL/OCSP) is often slow or not checked in real time.
- On platforms where users can disable enforcement (e.g., `bcdedit /set testsigning on`), the protection is opt-out.

### Interview Tip

> Stress the distinction between authenticity/integrity and safety. Code signing answers "who wrote this and has it been changed?" but not "is this code secure?" Reference the Stuxnet example to show that stolen certificates are a real threat. Mention that Windows 64-bit requires all kernel drivers to be signed, making unsigned rootkits significantly harder.

### References

- Microsoft Authenticode documentation
- Apple Code Signing Guide
- NIST SP 800-102 -- Recommendation for Digital Signature Timeliness

---

## 6. Compiler Security Features

### Explanation

Modern compilers include built-in security features that instrument compiled code to detect and prevent common memory corruption vulnerabilities at runtime. These features add minimal performance overhead but significantly raise the bar for exploitation. Key features include **stack canaries** (buffer overrun detection), **FORTIFY_SOURCE** (bounds-checked standard library functions), **Control Flow Integrity (CFI)**, and **SafeStack**.

Stack canaries (also called stack cookies or stack guards) are the most widely known compiler mitigation. A random value is placed on the stack between local variables and the saved return address. Before a function returns, the canary is checked; if a buffer overflow has overwritten it, the program aborts.

### How It Works

1. **Stack Canaries (`-fstack-protector`):** At function prologue, a random canary value is written to the stack. At epilogue, the canary is compared to the expected value. If it differs, `__stack_chk_fail()` is called, terminating the process.
2. **FORTIFY_SOURCE:** The compiler replaces unsafe functions (e.g., `memcpy`, `strcpy`) with bounds-checked versions when buffer sizes are known at compile time. Overflows are detected and the process aborts.
3. **Control Flow Integrity (CFI):** Indirect calls and jumps are restricted to a set of valid targets determined at compile time, making ROP and JOP attacks harder.
4. **SafeStack:** Separates the stack into a "safe stack" (return addresses, register spills) and an "unsafe stack" (local buffers), so buffer overflows on the unsafe stack cannot overwrite return addresses.

### Example

```bash
# GCC/Clang: Enable all major protections
gcc -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -fPIE -pie \
    -Wl,-z,relro,-z,now \
    -Wl,-z,noexecstack \
    -fcf-protection=full \
    -o myapp myapp.c

# Check which protections a binary has (using checksec)
checksec --file=myapp
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
# FORTIFY:  Enabled
```

```c
// Stack canary in action -- simplified view of generated code
void vulnerable_function(char *input) {
    long canary = __stack_chk_guard;  // prologue: load canary
    char buffer[64];
    strcpy(buffer, input);            // potential overflow
    if (canary != __stack_chk_guard)  // epilogue: verify canary
        __stack_chk_fail();           // abort if corrupted
}
```

### What It Prevents

- **Stack buffer overflows** (stack canaries detect overwriting past local buffers).
- **Known-size buffer overflows** in standard library calls (FORTIFY_SOURCE).
- **ROP/JOP attacks** (CFI restricts indirect call targets).
- **Format string attacks** that attempt to overwrite the return address (canary must be bypassed first).

### Limitations

- **Stack canaries** can be bypassed if the attacker can leak the canary value (e.g., via a format string or byte-by-byte brute force on forking servers).
- Canaries do not protect against overflows that overwrite **other local variables** without reaching the canary (e.g., overwriting a function pointer stored before the canary).
- **FORTIFY_SOURCE** only works when buffer sizes are known at compile time; dynamically sized buffers are not protected.
- **CFI** can be coarse-grained, allowing some invalid targets if they share the same function signature.
- All compiler mitigations add some runtime overhead (typically 1-5%).

### Interview Tip

> Know the `checksec` tool and what each flag means. An interviewer may show you a binary and ask what protections it has. Be able to explain what `-fstack-protector-strong` does versus `-fstack-protector-all` (strong protects functions with arrays or address-taken variables; all protects every function). Mention that compiler mitigations are defence in depth -- they complement, not replace, proper input validation.

### References

- GCC Stack Protector documentation
- Clang SafeStack and CFI documentation
- `checksec` tool (github.com/slimm609/checksec.sh)

---

## 7. Encryption of Software and Firmware

### Explanation

Encrypting software and firmware protects the confidentiality and integrity of code both at rest and during distribution. Firmware encryption prevents attackers from reverse-engineering proprietary firmware images to discover vulnerabilities, extract cryptographic keys, or create modified ("trojanised") firmware. Combined with secure boot, it ensures that only authentic, unmodified firmware is executed.

This mitigation spans several areas: encrypted firmware update packages, encrypted storage of firmware on flash chips, code obfuscation (a weaker form), and encrypted containers for application distribution. Modern secure boot chains (UEFI Secure Boot, ARM TrustZone Secure Boot) verify firmware integrity before execution using signatures, while encryption protects the firmware content itself.

### How It Works

1. The vendor encrypts the firmware image using a symmetric key (e.g., AES-256) before distribution.
2. The encryption key is stored in a hardware security module or one-time-programmable (OTP) fuses on the target device.
3. During boot, the bootloader decrypts the firmware in a trusted execution environment (TEE) before loading it.
4. A signature check (code signing) is performed after decryption to verify integrity.
5. If decryption fails or the signature is invalid, the device refuses to boot the firmware.

### Example

```bash
# Encrypting a firmware image for distribution
openssl enc -aes-256-cbc -salt -pbkdf2 \
  -in firmware_v2.1.bin -out firmware_v2.1.bin.enc -pass file:./key.bin

# UEFI Secure Boot key enrollment (simplified)
# 1. Generate keys
openssl req -new -x509 -newkey rsa:2048 -keyout PK.key -out PK.crt -days 3650
# 2. Enroll Platform Key in UEFI firmware setup
# 3. Sign bootloader
sbsign --key PK.key --cert PK.crt --output grubx64.efi.signed grubx64.efi
```

```
# Android Verified Boot (AVB) flow:
# 1. Bootloader verifies 'vbmeta' partition signature
# 2. vbmeta contains hashes of boot, system, vendor partitions
# 3. Each partition is verified against its hash before mounting
# 4. If any check fails, boot is aborted or a warning is displayed
```

### What It Prevents

- **Reverse engineering** of firmware to find vulnerabilities or extract secrets.
- **Firmware modification attacks** (evil maid attacks, supply chain implants).
- **Bootkit/rootkit** installation at the firmware level.
- **Intellectual property theft** from embedded device firmware.
- **Downgrade attacks** when combined with anti-rollback counters.

### Limitations

- **Key management** is the hardest part; if the decryption key is extractable from the device (e.g., via JTAG, glitching, or side-channel attacks), encryption is defeated.
- Encrypted firmware does not prevent exploitation of vulnerabilities in the running (decrypted) firmware.
- Performance overhead of decryption can be significant on resource-constrained embedded devices.
- If the encryption scheme is proprietary or poorly implemented, it may give a false sense of security.
- **Cold boot attacks** or DMA attacks may extract decrypted firmware from RAM.

### Interview Tip

> Distinguish between encryption (confidentiality) and signing (integrity/authenticity). A firmware image should be *both* signed and encrypted. Encryption without signing allows an attacker to replace the image with garbage; signing without encryption allows reverse engineering. Mention UEFI Secure Boot as a practical example the interviewer will recognise.

### References

- UEFI Secure Boot specification
- ARM TrustZone documentation
- Android Verified Boot (AVB) documentation
- NIST SP 800-147 -- BIOS Protection Guidelines

---

## 8. Mandatory Access Controls

### Explanation

Mandatory Access Controls (MAC) enforce access policies defined by a central authority (the system policy) that cannot be overridden by individual users or processes. This contrasts with Discretionary Access Controls (DAC), where the owner of a resource sets permissions. In MAC systems, even root may be restricted from certain actions if the policy does not permit them.

Key implementations include **SELinux** (Security-Enhanced Linux, developed by the NSA), **AppArmor**, **Windows Mandatory Integrity Control (MIC)**, and **macOS Sandbox (Seatbelt)**. ACLs (Access Control Lists) are technically a DAC mechanism but are often discussed alongside MACs because they provide fine-grained per-object permissions.

### How It Works

1. A security policy is defined that labels every subject (process, user) and object (file, socket, device) with a security context or type.
2. When a subject attempts to access an object, the MAC subsystem checks whether the policy allows that specific subject-type to perform that specific action on that object-type.
3. The decision is made by the kernel's security module (e.g., the SELinux LSM hook), independent of traditional Unix DAC permissions.
4. If the policy denies the access, the operation fails even if the process runs as root.
5. Policy violations are logged (audit log), providing visibility into attempted policy breaches.

### Example

```bash
# SELinux: Check status
sestatus
# SELinux status:      enabled
# Current mode:        enforcing
# Policy:              targeted

# View the security context of a file
ls -Z /var/www/html/index.html
# system_u:object_r:httpd_sys_content_t:s0  /var/www/html/index.html

# View the security context of a process
ps -eZ | grep httpd
# system_u:system_r:httpd_t:s0  1234 ?  00:00:01 httpd

# The policy allows httpd_t to read httpd_sys_content_t
# but denies httpd_t from reading user_home_t, even if DAC permits it
```

```bash
# AppArmor: Example profile for nginx
# /etc/apparmor.d/usr.sbin.nginx
/usr/sbin/nginx {
  /var/www/html/** r,
  /var/log/nginx/** w,
  /run/nginx.pid rw,
  network inet stream,
  deny /etc/shadow r,
  deny /home/** rwx,
}
```

### What It Prevents

- **Privilege escalation via root:** Even a compromised root process cannot access resources outside its MAC policy.
- **Container breakouts:** SELinux/AppArmor policies confine container processes.
- **Lateral movement within the OS:** A compromised web server cannot read `/etc/shadow` if the policy forbids it.
- **Unauthorised data access:** Processes are confined to their designated data and cannot access other services' files.

### Limitations

- **Policy complexity:** Writing and maintaining correct MAC policies is notoriously difficult. Misconfigured policies are the #1 reason organisations disable SELinux (`setenforce 0`).
- **Permissive mode drift:** Admins often set SELinux to permissive to troubleshoot, then forget to re-enable enforcing mode.
- **Does not protect against vulnerabilities within the allowed policy boundary** -- if the web server is allowed to read a database, SQL injection still works.
- **Kernel vulnerabilities** can bypass MAC entirely since the enforcement happens in the kernel itself.
- Performance overhead, though minimal on modern systems (~1-3%).

### Interview Tip

> Many candidates say "just disable SELinux" when troubleshooting. This is a red flag in a security interview. Instead, demonstrate that you understand `audit2allow` to generate policy exceptions, and that you can work with MAC rather than against it. Know the difference between MAC (policy-driven, centralised) and DAC (owner-driven, discretionary). Mention that SELinux implements the Flask architecture with type enforcement.

### References

- NSA SELinux documentation
- AppArmor Wiki
- Windows Mandatory Integrity Control (MIC) documentation
- "SELinux by Example" by Mayer, MacMillan, and Caplan

---

## 9. "Insecure by Exception" Philosophy

### Explanation

The "insecure by exception" philosophy (also called "secure by default" or "default deny") dictates that a system should ship in its most restrictive, secure configuration out of the box. Any relaxation of security -- opening a port, enabling a service, granting a permission -- must be an explicit, deliberate, documented exception. This is the inverse of the legacy approach where everything was enabled by default and administrators had to harden after deployment.

This philosophy applies to firewall rules (default deny all, then whitelist), service configurations (disable all optional services by default), user permissions (no access until explicitly granted), and feature flags (security features enabled, not opt-in).

### How It Works

1. The default state of any system, service, or feature is **locked down**: all ports closed, all services disabled, all permissions denied.
2. An administrator or operator must explicitly enable each required capability through a change management process.
3. Each exception is documented with a justification, an owner, and a review date.
4. Periodic audits verify that exceptions are still needed and revoke those that are not.
5. New features ship with security controls enabled by default (e.g., HTTPS, authentication required).

### Example

```bash
# Firewall: Default deny with explicit exceptions
# iptables -- default DROP on INPUT
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
# Allow only SSH and HTTPS
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

```yaml
# Kubernetes NetworkPolicy: default deny all ingress, allow specific
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web-traffic
spec:
  podSelector:
    matchLabels:
      app: frontend
  ingress:
  - from: []
    ports:
    - port: 443
```

### What It Prevents

- **Unnecessary attack surface:** Services that are not running cannot be exploited.
- **Misconfiguration-driven breaches:** When the default is secure, forgetting to configure something does not create a vulnerability.
- **Shadow IT exposure:** Unmanaged services and ports are blocked by default.
- **Accidental data exposure:** Default-deny permissions prevent unintended access.

### Limitations

- Overly restrictive defaults can cause operational friction and delay deployments.
- Developers may work around restrictions in insecure ways (e.g., disabling the firewall entirely rather than creating proper exceptions).
- Requires robust change management processes to handle exceptions efficiently.
- Does not protect against vulnerabilities in the explicitly allowed services.

### Interview Tip

> Frame this as a design philosophy, not just a technical control. Contrast it with "secure by hardening" (start open, then lock down) and explain why the former is superior: forgotten steps in hardening leave gaps, whereas forgotten exceptions in a default-deny model leave you more secure, not less. Reference cloud security groups that start with no inbound rules as a modern example.

### References

- CIS Benchmarks (default-deny principles)
- NIST SP 800-123 -- Guide to General Server Security
- OWASP Secure by Default principles

---

## 10. "Do Not Blame the User" Philosophy

### Explanation

The "do not blame the user" philosophy holds that security failures resulting from user behaviour are fundamentally design failures, not user failures. If a user clicks a phishing link, the question should not be "why did the user click?" but "why did the system allow a phishing link to reach the user and cause damage?" This philosophy drives security engineers to build systems that are resilient to human error rather than dependent on human perfection.

This principle influences the design of authentication systems (password managers over password policies), email security (automatic link scanning over user training alone), permission models (least privilege so mistakes have limited impact), and error handling (fail secure, not fail open).

### How It Works

1. **Assume users will make mistakes.** Design systems so that the most natural, easy action is also the secure action ("paving the path of least resistance").
2. **Automate security decisions** wherever possible -- auto-update, auto-lock, auto-encrypt.
3. **Provide clear, actionable warnings** instead of vague security prompts that users learn to dismiss.
4. **Implement guardrails** that prevent catastrophic outcomes from single user errors (e.g., MFA preventing account takeover even if a password is phished).
5. **Measure and iterate** by studying where users fail and redesigning those interactions rather than re-training users.

### Example

```
BAD DESIGN (blaming the user):
- "Users must choose passwords with 12+ chars, uppercase, lowercase, 
   numbers, symbols, and change them every 90 days."
- Result: Users write passwords on sticky notes or use Password1!

GOOD DESIGN (not blaming the user):
- Deploy a password manager org-wide with SSO.
- Enforce MFA (hardware keys preferred).
- Allow long passphrases without complexity rules.
- Monitor for credential stuffing rather than forcing rotation.
- Result: Users have unique, strong credentials without memorisation burden.
```

```
BAD DESIGN: A confirmation dialog that says "Are you sure?" for every action.
- Users develop "click fatigue" and automatically click "Yes."

GOOD DESIGN: Undo functionality instead of confirmation dialogs.
- Gmail's "Undo Send" is more effective than "Are you sure you want to send?"
- AWS S3 versioning protects against accidental deletion without prompts.
```

### What It Prevents

- **Phishing success** (when combined with technical controls like FIDO2/WebAuthn, which are phishing-resistant by design).
- **Credential reuse** (by providing password managers rather than demanding memorisation).
- **Alert fatigue** and prompt blindness (by reducing unnecessary security prompts).
- **Insider threat from negligence** (guardrails prevent accidental data exposure).

### Limitations

- Cannot fully prevent deliberate, malicious insider actions (this philosophy targets mistakes, not malice).
- Requires significant UX investment, which security teams may lack the resources or skills for.
- Some regulatory requirements still mandate user-centric controls (e.g., security awareness training).
- Can create a false sense of security if technical controls are assumed to compensate for all user behaviour.

### Interview Tip

> This is a philosophy question, so demonstrate systems thinking. Give a concrete example: "Instead of training users not to click phishing links, deploy DMARC/DKIM/SPF to block spoofed emails, use a web proxy that scans URLs in real time, and enforce hardware MFA so that even successful phishing cannot compromise credentials." Show that you view the user as someone to protect, not someone to blame. Reference NIST 800-63B's removal of periodic password rotation as an example of the industry moving away from blaming users.

### References

- NIST SP 800-63B -- Digital Identity Guidelines (password guidance)
- Don Norman, "The Design of Everyday Things" (usability principles)
- Google's BeyondCorp Zero Trust model (user-friendly security)
- FIDO Alliance / WebAuthn specification

---

## Key Takeaways

- **Defence in depth is non-negotiable.** No single mitigation is sufficient. DEP + ASLR + stack canaries + least privilege + MAC together create a layered defence that forces attackers to chain multiple bypasses.
- **Patching remains the #1 most impactful control.** The vast majority of successful attacks exploit known, patched vulnerabilities. The gap between patch availability and patch deployment is where breaches happen.
- **Every mitigation has known bypasses.** DEP falls to ROP. ASLR falls to info leaks. Stack canaries fall to canary leaks. The goal is to make exploitation expensive, not impossible.
- **Secure by default beats hardening guides.** Systems that ship locked down and require explicit exceptions to relax security are fundamentally more resilient than systems that require active hardening.
- **Design for human error.** The "do not blame the user" philosophy produces more secure systems than any amount of security awareness training. Build systems where the easy path is the secure path.
- **Understand the difference between integrity, authenticity, and confidentiality** when discussing code signing and firmware encryption -- they solve different problems and are complementary.

## Interview Practice Questions

1. **Explain how DEP and ASLR complement each other.** What attack does each one prevent, and how does an attacker bypass the combination?
2. **A legacy application crashes when DEP is enabled.** How would you investigate and resolve this while maintaining security?
3. **Describe the SELinux enforcement model.** What is type enforcement, and how does it differ from traditional Unix DAC?
4. **Your organisation has a mean time to patch of 90 days.** What steps would you recommend to reduce this, and how would you prioritise which patches to apply first?
5. **An attacker has obtained a valid code signing certificate.** What additional controls could detect or prevent the use of malicious signed code?
6. **Compare stack canaries, ASLR, and CFI.** Which layer of the exploitation chain does each one target?
7. **Give an example of "blaming the user" in a security policy** and explain how you would redesign it following the "do not blame the user" philosophy.
8. **A developer asks you to disable SELinux on a production server** because their application does not work. How do you respond?
9. **Explain the difference between mandatory and discretionary access controls.** When would you choose one over the other?
10. **Describe a scenario where firmware encryption would have prevented a real-world attack.** What additional controls would you pair with it?

---

[Previous: OS Implementation & Systems](os-systems.md) | [Next: Cryptography](cryptography.md)
