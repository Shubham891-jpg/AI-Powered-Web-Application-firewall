# AI-WAF System Architecture

## 1. Overview
The AI-Powered Web Application Firewall (AI-WAF) operates as a transparent reverse proxy between untrusted internet clients and backend web applications. Every incoming HTTP request is intercepted, parsed, normalized, inspected through multi-tiered detection engines, risk-scored, and either transparently proxied to the upstream target or immediately terminated with an HTTP 403 response.

```mermaid
flowchart TD
    Client[Internet Client] -->|HTTP Request| Gateway[AI-WAF Reverse Proxy Gateway]
    
    subgraph WAF_Pipeline ["Request Processing Pipeline"]
        Gateway --> P1[Request Parser & Size Guard]
        P1 --> P2[Redis Sliding-Window Rate Limiter]
        P2 --> P3[Request Normalization Engine]
        
        P3 --> P4A[Deterministic Rule Engine]
        P3 --> P4B[Supervised ML Classifier]
        
        P4A --> P5[Risk Engine Decision Matrix]
        P4B --> P5
        
        P5 -->|Score 0-29: ALLOW| ActionAllow[Transparent Upstream Proxy]
        P5 -->|Score 30-69: FLAG| ActionFlag[Log Security Event & Proxy]
        P5 -->|Score 70-100: BLOCK| ActionBlock[HTTP 403 Forbidden]
    end
    
    ActionAllow --> Upstream[Protected Web Application]
    ActionFlag --> Upstream
    ActionBlock --> DB[(PostgreSQL Security Events)]
    ActionFlag --> DB
    
    Upstream -->|HTTP Response| Gateway
    Gateway -->|HTTP Response| Client
```

---

## 2. Request Processing Pipeline

1. **Request Intake & Metadata Capture**:
   - Assign unique `X-Request-ID` (UUIDv4) for distributed tracing.
   - Capture client IP (handling `X-Forwarded-For` with trust verification), HTTP method, URI, headers, query parameters, cookies, and payload.
   - Enforce maximum body size (`MAX_REQUEST_BODY_SIZE`) and maximum header size (`MAX_HEADER_SIZE`).

2. **Rate Limiting**:
   - Query Redis for client IP sliding-window counters.
   - If rate limits are violated, short-circuit immediately with HTTP 429 and log rate-limit violation.

3. **Normalization (Multi-pass)**:
   - Preserve `raw_request` for forensic logging.
   - Generate `normalized_request` through URL decoding, HTML entity decoding, Unicode normalization (NFKC), whitespace compression, and path canonicalization.

4. **Multi-Tier Threat Analysis**:
   - **Deterministic Rule Engine**: Inspects for SQLi, XSS, RCE, and Path Traversal indicators.
   - **Supervised ML Classifier**: TF-IDF vectorizer + Character n-grams + Logistic Regression classifier executing locally in < 5ms without external LLM latency.

5. **Risk Engine & Policy Enforcement**:
   - Combines rule confidence scores and ML attack probabilities into a normalized 0–100 risk score.
   - Evaluates thresholds:
     - 0–29: `ALLOW`
     - 30–69: `FLAG`
     - 70–100: `BLOCK`

6. **Persistence & Upstream Proxy**:
   - Asynchronously records security events into PostgreSQL.
   - If allowed/flagged, streams request to configured upstream destination using connection-pooled HTTP client (`httpx`).
