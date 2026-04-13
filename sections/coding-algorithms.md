# Coding & Algorithms - Deep Dive

[Back to Main Notes](../interview-study-notes-for-security-engineering.md#coding--algorithms)

> **Prerequisites:** Basic programming experience  
> **Difficulty:** Beginner to Intermediate

---

## Table of Contents

1. [Programming Basics](#1-programming-basics)
2. [Data Structures](#2-data-structures)
3. [Sorting Algorithms](#3-sorting-algorithms)
4. [Searching Algorithms](#4-searching-algorithms)
5. [Big O Notation](#5-big-o-notation)
6. [Regular Expressions](#6-regular-expressions)
7. [Recursion](#7-recursion)
8. [Python Specifics](#8-python-specifics)
9. [Key Takeaways](#key-takeaways)
10. [Interview Practice Questions](#interview-practice-questions)

---

## 1. Programming Basics

### 1.1 Conditions

Conditions are the backbone of access control, input validation, and policy enforcement. A single misplaced condition can turn a secure system into a vulnerable one.

**Code Example:**
```python
# Access control decision using conditions
def check_access(user_role, resource_sensitivity):
    """Evaluate access based on role and resource sensitivity."""
    if not user_role or not resource_sensitivity:
        return False  # Deny by default (fail-closed)

    if user_role == "admin":
        return True
    elif user_role == "analyst" and resource_sensitivity in ("low", "medium"):
        return True
    elif user_role == "viewer" and resource_sensitivity == "low":
        return True
    else:
        return False  # Explicit deny

# Ternary / conditional expression
status = "BLOCKED" if is_malicious(packet) else "ALLOWED"

# Guard clauses - preferred pattern for input validation
def sanitize_input(user_input):
    if user_input is None:
        raise ValueError("Input cannot be None")
    if len(user_input) > 1024:
        raise ValueError("Input exceeds maximum length")
    if not user_input.isprintable():
        raise ValueError("Input contains non-printable characters")
    return user_input.strip()
```

**Complexity:** O(1) per check. Chained if/elif is O(n) branches.

**Security Relevance:** Short-circuit evaluation can leak timing info. Fail-open vs. fail-closed -- always default to deny. Type confusion attacks exploit weak checks (e.g., `if user_input == 0` passes when input is `False`).

**Interview Tip:** Always include a default deny case and handle `None`/empty inputs. Interviewers look for defensive programming habits.

---

### 1.2 Loops

Loops appear in brute-force detection, log parsing, packet processing, and cryptographic operations. Unbounded loops enable DoS; algorithmic complexity attacks craft input triggering worst-case behavior.

**Code Example:**
```python
# First-match firewall evaluation
firewall_rules = [
    {"src": "10.0.0.0/8", "dst": "any", "port": 443, "action": "allow"},
    {"src": "any", "dst": "any", "port": 22, "action": "deny"},
    {"src": "192.168.1.0/24", "dst": "10.0.0.5", "port": 3306, "action": "allow"},
]

def evaluate_packet(packet, rules):
    for rule in rules:
        if matches(packet, rule):
            return rule["action"]
    return "deny"  # Default deny if no rule matches
```

**Complexity:** O(n) single loop. Nested loops multiply: O(n^2).

**Interview Tip:** Always mention loop termination conditions and guard against infinite loops.

---

### 1.3 Dictionaries (Hash Maps)

Python's `dict` is a hash table with open addressing. Average-case get/set/delete is O(1). The workhorse of security tools -- DNS caches, session tokens, IP reputation lists, threat intel indexes.

**Code Example:**
```python
# IP reputation tracker using a dictionary
ip_reputation = {}

def record_event(ip, event_type):
    """Track suspicious activity per IP."""
    if ip not in ip_reputation:
        ip_reputation[ip] = {"failed_logins": 0, "port_scans": 0, "score": 0}

    record = ip_reputation[ip]
    if event_type == "failed_login":
        record["failed_logins"] += 1
        record["score"] += 10
    elif event_type == "port_scan":
        record["port_scans"] += 1
        record["score"] += 50

    return record["score"]

def get_blocked_ips(threshold=100):
    """Return all IPs exceeding the threat score threshold."""
    return {ip: data for ip, data in ip_reputation.items()
            if data["score"] >= threshold}

# defaultdict for cleaner counting
from collections import defaultdict, Counter

failed_attempts = defaultdict(int)
for log_entry in parse_auth_log("/var/log/auth.log"):
    failed_attempts[log_entry["source_ip"]] += 1

# Find top 10 offenders
top_offenders = Counter(failed_attempts).most_common(10)
```

**Complexity Analysis:**
| Operation | Average | Worst Case |
|-----------|---------|------------|
| Get       | O(1)    | O(n)       |
| Set       | O(1)    | O(n)       |
| Delete    | O(1)    | O(n)       |
| Iterate   | O(n)    | O(n)       |

Worst case occurs with hash collisions.

**Security Relevance:** HashDoS attacks craft keys that all collide, degrading O(1) to O(n). Python 3.6+ uses SipHash with randomized seed to mitigate. Constant-time lookups are essential for real-time threat detection at scale.

**Interview Tip:** Know `dict`, `defaultdict`, `OrderedDict`, and `Counter`. Be able to implement a simple hash map from scratch.

---

### 1.4 Slices, Lists, and Arrays

Python lists are dynamic arrays (contiguous memory of pointers). Slicing creates shallow copies. Arrays (`array` module, NumPy) store typed data more efficiently.

**Code Example:**
```python
# Array operations common in security
def detect_port_scan(connection_log, threshold=100, window=60):
    """Detect port scanning by counting unique ports per IP in a time window."""
    from collections import defaultdict
    ip_ports = defaultdict(set)

    for conn in connection_log:
        ip_ports[conn["src_ip"]].add(conn["dst_port"])

    scanners = []
    for ip, ports in ip_ports.items():
        if len(ports) >= threshold:
            scanners.append({"ip": ip, "ports_scanned": sorted(list(ports))})
    return scanners

```

**Complexity Analysis:**
| Operation       | Complexity |
|----------------|------------|
| Index access    | O(1)       |
| Append          | O(1) amortized |
| Insert at i     | O(n)       |
| Delete at i     | O(n)       |
| Slice [a:b]     | O(b - a)   |
| Search (in)     | O(n)       |
| Sort            | O(n log n) |

**Interview Tip:** Know slicing fluently. "Reverse a string" or "rotate an array" are solved elegantly with slices. Buffer overflows in C/C++ exploit array bounds -- Python lists are bounds-checked.

---

### 1.5 String and Array Operations

**Code Example:**
```python
# Common string operations in security contexts

# 1. URL parsing and validation
from urllib.parse import urlparse, parse_qs

def analyze_url(url):
    """Break down a URL for security analysis."""
    parsed = urlparse(url)
    return {
        "scheme": parsed.scheme,
        "domain": parsed.netloc,
        "path": parsed.path,
        "params": parse_qs(parsed.query),
        "is_https": parsed.scheme == "https",
        "has_suspicious_params": any(
            k in parse_qs(parsed.query)
            for k in ["cmd", "exec", "system", "eval"]
        ),
    }

# 2. IP address manipulation
def ip_to_int(ip):
    """Convert dotted IP to integer for range comparisons."""
    parts = ip.split(".")
    return sum(int(part) << (8 * (3 - i)) for i, part in enumerate(parts))

def is_private_ip(ip):
    """Check if IP is in RFC 1918 private range."""
    ip_int = ip_to_int(ip)
    private_ranges = [
        (ip_to_int("10.0.0.0"), ip_to_int("10.255.255.255")),
        (ip_to_int("172.16.0.0"), ip_to_int("172.31.255.255")),
        (ip_to_int("192.168.0.0"), ip_to_int("192.168.255.255")),
    ]
    return any(start <= ip_int <= end for start, end in private_ranges)
```

**Security Relevance:** String operations underpin input validation, log analysis, and threat detection. Improper handling leads to injection attacks (SQL, XSS, command injection).

---

## 2. Data Structures

### 2.1 Hash Tables

Hash tables store key-value pairs using a hash function to compute bucket indexes. Collisions resolved via **chaining** (linked list per bucket) or **open addressing** (probing for next empty slot). See Section 1.3 for Python `dict` usage and examples.

**Code Example:**
```python
class HashTableChaining:
    """Hash table with separate chaining."""
    def __init__(self, size=16):
        self.size = size
        self.buckets = [[] for _ in range(size)]

    def _hash(self, key):
        return hash(key) % self.size

    def put(self, key, value):
        bucket = self.buckets[self._hash(key)]
        for i, (k, v) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, value)
                return
        bucket.append((key, value))

    def get(self, key):
        for k, v in self.buckets[self._hash(key)]:
            if k == key:
                return v
        raise KeyError(key)
```

**Complexity:** Average O(1), worst O(n) for insert/lookup/delete. With BST chaining, worst case improves to O(log n).

**Interview Tip:** Be ready to implement a hash table from scratch. Know load factor (~75% triggers resize), collision resolution strategies, and HashDoS (Python mitigates with SipHash + randomized seeds since 3.3).

---

### 2.2 Arrays

(Covered in Section 1.4 above. Key additions for interviews:)

```python
# Two-pointer technique - common interview pattern
def find_pair_with_sum(sorted_arr, target):
    """Find two numbers that sum to target in a sorted array."""
    left, right = 0, len(sorted_arr) - 1
    while left < right:
        current_sum = sorted_arr[left] + sorted_arr[right]
        if current_sum == target:
            return (sorted_arr[left], sorted_arr[right])
        elif current_sum < target:
            left += 1
        else:
            right -= 1
    return None

# Sliding window - useful for network traffic analysis
def max_connections_in_window(timestamps, window_size):
    """Find maximum concurrent connections in a time window."""
    if not timestamps:
        return 0
    timestamps.sort()
    max_count = 0
    left = 0
    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > window_size:
            left += 1
        max_count = max(max_count, right - left + 1)
    return max_count
```

---

### 2.3 Stacks

A stack is a Last-In-First-Out (LIFO) data structure. Push/Pop/Peek are all O(1), Search is O(n). Fundamental to function call execution, expression parsing, and depth-first traversal. Stack-based buffer overflows are a classic vulnerability class; ROP chains manipulate the call stack, mitigated by stack canaries and ASLR.

**Code Example:**
```python
# Stack-based bracket validator (useful for config file parsing)
def validate_brackets(text):
    """Validate matching brackets - critical for parsing configs, JSON, code."""
    stack = []
    matching = {')': '(', ']': '[', '}': '{'}

    for i, char in enumerate(text):
        if char in '([{':
            stack.append((char, i))
        elif char in ')]}':
            if not stack:
                return False, f"Unmatched '{char}' at position {i}"
            top_char, top_pos = stack.pop()
            if matching[char] != top_char:
                return False, f"Mismatched '{top_char}' at {top_pos} with '{char}' at {i}"

    if stack:
        return False, f"Unclosed '{stack[-1][0]}' at position {stack[-1][1]}"
    return True, "Valid"
```

---

### 2.4 SQL / Tables

SQL operates on relational tables. Security engineers query databases for audit logs, user permissions, vulnerability data, and incident records. SQL injection remains a top-10 OWASP vulnerability -- always use parameterized queries, never concatenate user input into SQL strings.

**Code Example:**
```python
import sqlite3

conn = sqlite3.connect(":memory:")
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT CHECK(severity IN ('low','medium','high','critical'))
    )
""")

# Parameterized queries to PREVENT SQL injection -- use ? placeholders, NEVER f-strings
cursor.execute(
    "INSERT INTO security_events (timestamp, source_ip, event_type, severity) "
    "VALUES (?, ?, ?, ?)",
    ("2024-01-15 10:30:00", "10.0.0.5", "brute_force", "critical")
)

# Aggregate query: top offending IPs
cursor.execute("""
    SELECT source_ip, COUNT(*) as event_count
    FROM security_events
    WHERE severity IN ('high', 'critical')
    GROUP BY source_ip ORDER BY event_count DESC LIMIT 10
""")
```

---

### 2.5 Bigtables / NoSQL

Google Bigtable (and similar: HBase, Cassandra, DynamoDB) are distributed, wide-column NoSQL stores for petabyte-scale data. Data is organized by row key, column family, and timestamp. Row keys are sorted lexicographically, making prefix scans efficient. SIEM backends (Chronicle, Sentinel) use this model for log retention at scale. Access control is per-column-family. NoSQL injection is possible in MongoDB and similar systems -- input validation still matters.

**Code Example:**
```python
# Bigtable-style access: data keyed as {row_key: {col_family: {col: {timestamp: value}}}}
class SimpleBigtable:
    def __init__(self):
        self.data = {}

    def put(self, row_key, col_family, column, value, timestamp=None):
        import time
        ts = timestamp or int(time.time() * 1000)
        self.data.setdefault(row_key, {}).setdefault(col_family, {}).setdefault(column, {})[ts] = value

    def scan(self, prefix):
        """Scan all rows matching a key prefix."""
        return {k: v for k, v in sorted(self.data.items()) if k.startswith(prefix)}

# Usage: bt.put("ip#10.0.0.5#2024011510", "event", "type", "brute_force")
```

---

## 3. Sorting Algorithms

### 3.1 Quicksort

Quicksort is a divide-and-conquer algorithm: select a pivot, partition so elements less than pivot come before it and greater after, then recursively sort sub-arrays. In-place and cache-friendly. An attacker who controls input to a quicksort with deterministic pivot can force O(n^2) (DoS). Mitigation: randomized pivot or median-of-three. Python's `sorted()` uses Timsort (O(n log n) guaranteed).

**Code Example:**
```python
def quicksort(arr):
    if len(arr) <= 1:
        return arr
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    return quicksort(left) + middle + quicksort(right)
```

**Complexity Analysis:**
| Case    | Time       | Space    |
|---------|-----------|----------|
| Best    | O(n log n)| O(log n) |
| Average | O(n log n)| O(log n) |
| Worst   | O(n^2)    | O(n)     |

---

### 3.2 Merge Sort

Merge sort divides the array in half recursively until each sub-array has one element, then merges back in sorted order. Guarantees O(n log n) in all cases but requires O(n) extra space. It is stable (preserves relative order of equal elements), which matters when sorting security events by timestamp. Immune to the algorithmic complexity attacks that affect quicksort. Use `heapq.merge()` for efficient n-way merge of sorted log streams.

**Code Example:**
```python
def merge_sort(arr):
    if len(arr) <= 1:
        return arr
    mid = len(arr) // 2
    left = merge_sort(arr[:mid])
    right = merge_sort(arr[mid:])
    return merge(left, right)

def merge(left, right):
    result = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:  # <= makes it stable
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1
    result.extend(left[i:])
    result.extend(right[j:])
    return result
```

**Complexity:** O(n log n) time (all cases), O(n) space.

**Interview Tip:** Quicksort is faster in practice (cache-friendly, in-place) but merge sort has guaranteed performance. Python's Timsort combines the best of both.

---

## 4. Searching Algorithms

### 4.1 Binary Search vs. Linear Search

Linear search checks each element one by one -- O(n). Binary search works on sorted data by repeatedly halving the search space -- O(log n). For 1,000,000 elements: linear needs up to 1M comparisons, binary needs ~20. IP blocklists and reputation lookups at scale require O(log n) or O(1), not O(n). Use Python's `bisect` module for sorted list operations.

**Code Example:**
```python
def binary_search(arr, target):
    """O(log n) search - requires sorted data."""
    low, high = 0, len(arr) - 1
    while low <= high:
        mid = (low + high) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            low = mid + 1
        else:
            high = mid - 1
    return -1
```

**Complexity Analysis:**
| Algorithm | Time (avg) | Time (worst) | Space | Requires Sorted? |
|-----------|-----------|-------------|-------|-------------------|
| Linear    | O(n)      | O(n)        | O(1)  | No               |
| Binary    | O(log n)  | O(log n)    | O(1)  | Yes              |

**Interview Tip:** Always clarify whether the input is sorted. Sorting first O(n log n) + binary search O(log n) beats repeated linear searches if you search more than O(log n) times.

---

## 5. Big O Notation

Big O notation describes the upper bound of an algorithm's growth rate as input size increases, ignoring constants and lower-order terms. Security engineers need Big O to evaluate whether tools can handle production-scale data and to identify algorithmic DoS vulnerabilities.

**Common complexities (n=1000):**
```
  O(1)        = 1 operation
  O(log n)    ~ 10 operations
  O(n)        = 1,000 operations
  O(n log n)  ~ 10,000 operations
  O(n^2)      = 1,000,000 operations
  O(2^n)      = 10^301 (intractable)
```

**Code Example:**
```python
# O(1) - Constant: hash table lookup
def check_membership(d, key): return key in d

# O(log n) - Logarithmic: binary search (see Section 4.1)

# O(n) - Linear: single pass
def find_max(arr):
    return max(arr)

# O(n log n) - Linearithmic: sorting
# arr.sort()  # Timsort

# O(n^2) - Quadratic: nested loops
def find_all_pairs(arr):
    return [(arr[i], arr[j]) for i in range(len(arr)) for j in range(i+1, len(arr))]
```

**Security Relevance:** Algorithmic complexity attacks trigger worst-case behavior for DoS. Cryptographic strength relies on intractable complexity (O(2^n) for brute-forcing AES-256). A SIEM processing 10B events/day needs O(1) or O(log n) per-event operations. Rate limiting must be O(1).

**Interview Tip:** State **time** and **space** complexity separately. Drop constants (O(2n) = O(n)) and lower-order terms (O(n^2 + n) = O(n^2)). Consider best, average, and worst cases.

---

## 6. Regular Expressions

Regular expressions define search patterns for matching text. Simple patterns run in O(n) via DFA, but pathological patterns on backtracking engines (NFA, which Python uses) degrade to O(2^n) -- this is **ReDoS** (Regular Expression Denial of Service). Example: pattern `^(a+)+$` against input `"aaaaaaaaaaaaaaaaaX"` tries 2^n combinations before failing.

**Code Example:**
```python
import re

# Basic regex syntax reference
patterns = {
    "ip_address":    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    "email":         r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "url":           r'https?://[^\s<>"{}|\\^`\[\]]+',
    "mac_address":   r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}',
    "ipv6":          r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
    "cve_id":        r'CVE-\d{4}-\d{4,}',
    "base64":        r'[A-Za-z0-9+/]{20,}={0,2}',
    "private_key":   r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
    "aws_key":       r'AKIA[0-9A-Z]{16}',
    "jwt_token":     r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
}

def scan_for_secrets(text):
    """Scan text for common secrets and sensitive patterns."""
    findings = []
    secret_patterns = {
        "AWS Access Key":  r'AKIA[0-9A-Z]{16}',
        "Private Key":     r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
        "API Key":         r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9]{20,})',
        "Password in URL": r'://[^:]+:([^@]+)@',
    }
    for name, pattern in secret_patterns.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            findings.append({
                "type": name,
                "match": match.group()[:50] + "..." if len(match.group()) > 50 else match.group(),
                "position": match.start(),
            })
    return findings

# Compiled regex for performance (compile once, use many times)
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\d+)'
)

def parse_log_line(line):
    """Parse Apache/Nginx log line using compiled regex."""
    match = LOG_PATTERN.match(line)
    if match:
        return match.groupdict()
    return None

# ReDoS-safe pattern design
# BAD (vulnerable to ReDoS):  r'^([a-zA-Z0-9]+)*@example\.com$'
# GOOD (no nested quantifiers): r'^[a-zA-Z0-9]+@example\.com$'
```

**Complexity:** DFA engines: O(n) always. NFA (Python): O(n) typical, O(2^n) pathological.

**Interview Tip:** Dangerous patterns: nested quantifiers `(a+)+`, overlapping alternation `(a|a)+`, quantified repetition `(a{1,10}){1,10}`. Mitigation: switch to RE2 (Google's DFA engine) or use atomic groups. IDS/IPS rules (Snort, Suricata) and secret scanning pipelines are regex-heavy.

**References:**
- [ReDoS explained - OWASP](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [regex101.com](https://regex101.com) - interactive regex tester

---

## 7. Recursion

Recursion is a technique where a function calls itself with a **base case** (termination) and a **recursive case** (smaller subproblem). Rarely used in production security code: Python's default recursion limit is 1000, no tail-call optimization, each call adds a stack frame (~100-400 bytes), and iterative alternatives with explicit stacks are safer. Attackers exploit recursion via billion laughs (XML bombs), zip bombs, deeply nested JSON, and symlink loops in directory traversal.

**Code Example:**
```python
def fibonacci(n, memo={}):
    """Fibonacci with memoization (top-down dynamic programming)."""
    if n in memo:
        return memo[n]
    if n <= 1:
        return n
    memo[n] = fibonacci(n - 1, memo) + fibonacci(n - 2, memo)
    return memo[n]

# Security use case: recursive directory traversal for file scanning
import os

def scan_directory(path, max_depth=10, current_depth=0):
    """Recursively scan directory for suspicious files."""
    if current_depth > max_depth:  # CRITICAL: prevent infinite recursion
        return []
    findings = []
    try:
        for entry in os.scandir(path):
            if entry.is_file() and is_suspicious(entry.name):
                findings.append(entry.path)
            elif entry.is_dir() and not entry.is_symlink():  # Avoid symlink loops
                findings.extend(scan_directory(entry.path, max_depth, current_depth + 1))
    except PermissionError:
        pass
    return findings

def is_suspicious(filename):
    return any(filename.lower().endswith(ext) for ext in {'.exe', '.bat', '.ps1', '.vbs', '.scr', '.dll'})
```

**Interview Tip:** Write the recursive solution, then mention you would convert to iterative with an explicit stack in production. Know how to do the conversion.

---

## 8. Python Specifics

### 8.1 List Comprehensions

**Explanation:**
List comprehensions are a Pythonic way to create lists using a concise, declarative syntax. They are faster than equivalent `for` loops because the iteration is implemented in C internally.

**Code Example:**
```python
# Basic list comprehension
ips = [f"192.168.1.{i}" for i in range(1, 255)]

# With condition (filtering)
high_severity = [event for event in events if event["severity"] == "critical"]

# Nested comprehension
ports_by_host = {
    host: [scan["port"] for scan in scans if scan["host"] == host]
    for host in unique_hosts
}

# Dictionary comprehension
status_counts = {status: 0 for status in ["blocked", "allowed", "flagged"]}

# Set comprehension (deduplicate)
unique_source_ips = {event["src_ip"] for event in firewall_logs}

# Real-world: extract all unique domains from URLs
from urllib.parse import urlparse
urls = ["https://evil.com/phish", "http://evil.com/malware", "https://legit.com"]
unique_domains = {urlparse(url).netloc for url in urls}
# Result: {'evil.com', 'legit.com'}
```

**Interview Tip:** Prefer comprehensions over `map()`/`filter()` for readability. But avoid overly complex comprehensions -- if it needs more than one condition or nested loop, use a regular `for` loop.

---

### 8.2 Generators and Iterators

Generators produce values lazily using `yield`, computing one value at a time instead of building an entire list in memory. Essential for processing large datasets (multi-GB log files, network streams). Uses O(1) memory regardless of dataset size.

**Code Example:**
```python
# Generator for reading large log files line by line
def read_large_log(filepath):
    """Process a multi-GB log file without loading it all into memory."""
    with open(filepath, 'r') as f:
        for line in f:  # 'f' is already an iterator
            stripped = line.strip()
            if stripped:  # Skip empty lines
                yield stripped

# Chained generators for a processing pipeline
def parse_entries(lines):
    for line in lines:
        parts = line.split(" ", 3)
        if len(parts) >= 4:
            yield {"timestamp": parts[0], "level": parts[1],
                   "source": parts[2], "message": parts[3]}

def filter_critical(entries):
    for entry in entries:
        if entry["level"] in ("ERROR", "CRITICAL"):
            yield entry

def enrich_with_geo(entries):
    for entry in entries:
        entry["country"] = lookup_geo(entry.get("source", ""))
        yield entry

# Usage: memory-efficient pipeline
# Nothing executes until we iterate -- all lazy evaluation
pipeline = enrich_with_geo(
    filter_critical(
        parse_entries(
            read_large_log("/var/log/security.log")
        )
    )
)

for event in pipeline:
    send_to_siem(event)

# Generator expression (like list comprehension but lazy)
total_bytes = sum(event["size"] for event in parse_entries(lines))
```

---

### 8.3 Slicing

```python
data[2:5]    # [2,3,4]   data[:3]   # first 3   data[-3:]  # last 3
data[::2]    # every other   data[::-1]  # reversed   data[1:8:3]  # start:stop:step

# Slice objects for reusable patterns (e.g., packet parsing)
HEADER, PAYLOAD, CHECKSUM = slice(0, 20), slice(20, -4), slice(-4, None)

# TCP header parsing with byte slicing
def parse_tcp_header(data):
    return {
        "src_port": int.from_bytes(data[0:2], 'big'),
        "dst_port": int.from_bytes(data[2:4], 'big'),
        "seq": int.from_bytes(data[4:8], 'big'),
        "flags": {"SYN": bool(data[13] & 0x02), "ACK": bool(data[13] & 0x10),
                  "RST": bool(data[13] & 0x04), "FIN": bool(data[13] & 0x01)},
    }
```

---

### 8.4 Dynamic Typing

Python is dynamically typed -- type checking happens at runtime. This enables rapid prototyping but introduces type confusion risks. Type hints (PEP 484) add optional static analysis via `mypy` without changing runtime behavior. Always validate types on security-critical inputs.

**Code Example:**
```python
from typing import Optional

def process_input_safe(data: str) -> str:
    """Type-annotated version. Use mypy for static checking."""
    if not isinstance(data, str):
        raise TypeError(f"Expected str, got {type(data).__name__}")
    return data.upper()

# Security implication: type confusion
def authenticate(password: str) -> bool:
    """Vulnerable to type confusion if input is not validated."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    return verify_hash(password, get_stored_hash())
```

---

### 8.5 Python Pros/Cons vs. C/Java

```
+------------------+----------------------------------+----------------------------------+
| Aspect           | Python                           | C / Java                         |
+------------------+----------------------------------+----------------------------------+
| Typing           | Dynamic (duck typing)            | Static (compile-time checked)    |
| Speed            | ~10-100x slower than C           | C: native speed, Java: JIT      |
| Memory safety    | Automatic (GC, bounds checking)  | C: manual (buffer overflows)     |
|                  |                                  | Java: GC (memory safe)           |
| Prototyping      | Very fast (REPL, concise syntax) | Slower (boilerplate, compilation)|
| Security tooling | Dominant (scapy, pwntools, etc.) | C: system-level exploits         |
|                  |                                  | Java: enterprise security        |
| Concurrency      | GIL limits true parallelism      | C: pthreads, Java: native threads|
| Deployment       | Script or package                | C: compiled binary, Java: JAR    |
| Error handling   | Exceptions (runtime)             | C: error codes, Java: exceptions |
| Use in security  | Scripting, automation, CTFs,     | C: kernel exploits, drivers      |
|                  | SIEM integrations, forensics     | Java: enterprise apps, Android   |
+------------------+----------------------------------+----------------------------------+
```

**Use Python for:** rapid prototyping, log analysis, CTFs/exploit dev (pwntools), automation, incident response. **Not ideal for:** real-time processing (C/Rust), kernel-level tools (C), high-concurrency services (Go/Rust).

---

## Key Takeaways

1. **Always validate input** -- conditions, type checking, and bounds checking are your first line of defense.
2. **Know your complexity** -- O(1) and O(log n) are required for production-scale security systems. O(n^2) or worse is a DoS risk.
3. **Hash tables are everywhere** in security -- sessions, caches, blocklists, reputation databases. Understand collision attacks.
4. **Quicksort vs. merge sort** -- quicksort is faster in practice but vulnerable to worst-case attacks. Merge sort guarantees O(n log n). Python's Timsort gives you the best of both.
5. **Binary search** requires sorted data but gives O(log n). Use `bisect` for sorted list operations in Python.
6. **Regex is powerful but dangerous** -- ReDoS is a real attack vector. Avoid nested quantifiers and consider RE2 for untrusted patterns.
7. **Prefer iteration over recursion** in production code to avoid stack overflows and improve debuggability.
8. **Python is the lingua franca of security engineering** -- know its strengths (rapid development, rich ecosystem) and weaknesses (speed, GIL).
9. **Generators over lists** when processing large data -- O(1) memory vs O(n).
10. **Parameterized queries always** -- never concatenate user input into SQL.

## Interview Practice Questions

1. **Easy:** Implement a function that checks if a string has all unique characters. What is the time and space complexity? Can you do it without extra data structures?
2. **Easy:** Given a list of log entries, find the most frequently occurring source IP. Use a dictionary.
3. **Medium:** Implement binary search on a sorted list of IP addresses (as strings). Handle the conversion from dotted notation to integers.
4. **Medium:** Write a function to detect if a regex pattern is potentially vulnerable to ReDoS (look for nested quantifiers).
5. **Medium:** Implement a simple LRU cache using a dictionary and a doubly-linked list. This is relevant for DNS caches and session stores.
6. **Medium:** Given two sorted log files (by timestamp), merge them into one sorted file efficiently. What is the time and space complexity?
7. **Hard:** Implement a rate limiter using the sliding window algorithm. It should allow N requests per T seconds per IP address.
8. **Hard:** Write a function that parses a firewall ruleset and detects shadowed rules (rules that can never match because a broader rule appears earlier).
9. **Practice Platforms:**
   - [LeetCode](https://leetcode.com/) -- Arrays, hash tables, binary search problems
   - [Big-O Cheat Sheet](https://www.bigocheatsheet.com/)

---
[Previous: Incident Management](incident-management.md) | [Next: Security Coding Challenges](security-coding-challenges.md)
