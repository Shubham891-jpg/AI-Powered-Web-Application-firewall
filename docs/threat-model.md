# AI-WAF Threat Model & Security Posture

## 1. Threat Identification (STRIDE Model)

| Threat Category | Primary Attack Vectors | AI-WAF Mitigation Strategy |
| :--- | :--- | :--- |
| **Spoofing** | Client IP spoofing via manipulated `X-Forwarded-For` headers | Only trust reverse proxy CIDR ranges; validate client IP extraction logic |
| **Tampering** | Parameter pollution, double URL encoding, unicode obfuscation | Multi-pass normalizer, canonicalization, preserving both raw and normalized states |
| **Repudiation** | Attackers denying malicious requests | Comprehensive security logging in PostgreSQL with request hashes, timestamps, and client IP |
| **Information Disclosure** | Leakage of stack traces, internal network IPs, or WAF signatures | Strict error isolation: clients receive uniform generic 403 blocks with `request_id` only |
| **Denial of Service** | Volumetric HTTP floods, massive payload exhaustion, slowloris | Pre-routing request size limits (10MB body, 16KB headers), timeouts (10s), Redis sliding-window rate limiting |
| **Elevation of Privilege** | Remote code execution, SQL injection, authentication bypass | Rule-based syntactic parsing, ML classification, risk scoring |

---

## 2. Specific Attack Mitigations

### 2.1 SQL Injection (SQLi)
- Token-level and pattern analysis for SQL keywords (`UNION`, `SELECT`, `INSERT`, `OR '1'='1'`).
- Tautology detection and comment stripping (`--`, `/*...*/`, `#`).
- Detection of stacked statements and out-of-band SQL functions.

### 2.2 Cross-Site Scripting (XSS)
- Normalized script tag and HTML markup detection (`<script>`, `<img src=x onerror=...>`).
- JavaScript event handlers (`onload`, `onclick`, `onerror`).
- Encoded javascript URIs (`javascript:`, `data:text/html`).

### 2.3 Command Injection (RCE)
- Detection of shell command chaining operators (`;`, `&&`, `||`, `|`, `$(...)`, `` ` ``).
- Identification of common binary invocations (`sh`, `bash`, `curl`, `wget`, `nc`, `powershell`).

### 2.4 Path Traversal
- Canonicalization of path sequences (`../`, `..\`, `....//`).
- Unicode and URL-encoded separator detection (`%2e%2e%2f`, `%252e%252e`).
- Strict disallowance of filesystem execution based on incoming request parameters.

### 2.5 Server-Side Request Forgery (SSRF)
- The WAF operates exclusively against explicitly configured, validated upstream targets.
- Client requests cannot dictate or redirect proxy destinations.
