# AI-WAF Detection Engine Design

## 1. Multi-Tier Hybrid Detection

The AI-WAF employs a hybrid strategy uniting deterministic rules with statistical machine learning:

1. **Deterministic Rule Engine**: High precision, zero-false-positive baseline for known signatures, regexes, and AST structural patterns.
2. **Supervised Machine Learning**: Generalizes to novel variations, obfuscated tokens, and anomalous payload structures.
3. **Risk Scoring Engine**: Synthesizes rule outputs and ML confidence scores into an actionable threat index (0-100).

```
+-------------------------------------------------------------+
|                Incoming Normalized Request                  |
+-------------------------------------------------------------+
               |                               |
               v                               v
+-----------------------------+ +-----------------------------+
|     Rule Engine Results     | |    ML Classifier Output     |
| - SQLi: 80                  | | - Class: SQL_INJECTION      |
| - XSS: 0                    | | - Confidence: 0.91          |
| - RCE: 0                    | |                             |
+-----------------------------+ +-----------------------------+
               \                               /
                \                             /
                 v                           v
+-------------------------------------------------------------+
|                      Risk Scoring Engine                    |
| Combined Risk Score = f(Rule Score, ML Prob, Weights) = 93  |
| Decision: BLOCK (Score >= 70)                               |
+-------------------------------------------------------------+
```

---

## 2. ML Pipeline Specifications

- **Baseline Classifier**: Logistic Regression with L2 regularization.
- **Feature Extraction**: TF-IDF vectorization with character n-grams (ranges 2 to 5).
- **Latency Budget**: < 5ms per inference.
- **Inference Context**: Runs entirely in-process using loaded `joblib` artifacts; never requires external network calls.

---

## 3. Dedicated Request Normalization Pipeline (Phase 2)

Before any rule analysis or machine learning evaluation executes, every incoming HTTP request passes through a multi-pass normalization pipeline:

1. **Null-Byte Elimination**: Strips `%00` and `\x00` while flagging critical injection markers.
2. **Multi-Pass URL Decoding**: Unwinds nested and repeated encodings (up to 4 recursion passes) to unveil obfuscated payloads (e.g. `%2527` -> `%27` -> `'`).
3. **HTML Entity Resolution**: Decodes named (`&lt;`), numeric decimal (`&#60;`), and hexadecimal (`&#x3c;`) entities.
4. **Unicode NFKC Normalization**: Maps full-width and compatibility characters (e.g., full-width `＜script＞` -> standard `<script>`).
5. **Path Canonicalization**: Normalizes directory traversals (`../`), multiple redundant slashes (`///`), and Windows path separators (`\`).
6. **Whitespace & Control Character Compaction**: Collapses irregular spacing while avoiding accidental corruption of legitimate data.

### Immutability & Forensic Integrity
The system constructs an `InspectedRequestContext` housing two distinct representations:
- **`RawRequest`**: Retains verbatim query strings, headers, and payload bytes for forensic persistence.
- **`NormalizedRequest`**: Provides canonicalized representations for high-precision detection.

---

## 4. Multi-Tier Rule Detection Engine (Phase 3)

The rule engine deploys four specialized analyzers managed dynamically by `RuleRegistry`:

### 4.1 Rule Confidence Framework
Per Section 9 of the specification, every evaluation classifies matches into four confidence levels:
- `NO_EVIDENCE` (Score: 0): No anomalous tokens or syntax detected.
- `SUSPICIOUS` (Score: 30 - 50): Weak indicators, isolated comments, or anomalous encoding without full syntax.
- `LIKELY` (Score: 51 - 79): Moderate indicators, partial syntax structures, or secondary heuristics.
- `HIGH_CONFIDENCE` (Score: 80 - 100): Clear syntactic confirmation of weaponized attacks.

### 4.2 SQL Injection Detector (`SQLI-001`)
- **Tier 1: Structural Clauses**: Proximity analysis for `UNION ... SELECT`, `SELECT ... FROM`, `INSERT INTO ... VALUES`, `ORDER BY \d+`.
- **Tier 2: Boolean Tautologies**: Evaluates numeric (`' OR 1=1`) and string (`' OR 'a'='a'`) tautological logic.
- **Tier 3: Stacked Destructive Commands**: Identifies command termination with `; DROP TABLE`, `; EXEC xp_cmdshell`, or time-based `WAITFOR DELAY`.
- **Tier 4: Fingerprint Functions**: Probes for `SLEEP()`, `BENCHMARK()`, `VERSION()`, `USER()`, and comment sequences.
- **False-Positive Mitigation**: Discards isolated English words ("select", "union") lacking surrounding SQL grammar.

### 4.3 Context-Aware Cross-Site Scripting Detector (`XSS-001`)
- **Tier 1: Dangerous Markup Elements**: Detects `<script>`, `<iframe>`, `<object>`, `<embed>`, `<svg onload=...>`, `<base href=...>`.
- **Tier 2: Inline DOM Event Handlers**: Detects handlers (`onload=`, `onerror=`, `onclick=`) coupled with active JavaScript calls.
- **Tier 3: Script Pseudo-Protocols**: Identifies `javascript:`, `vbscript:`, and `data:text/html;base64,...`.
- **Tier 4: DOM Extraction**: Flags `document.cookie`, `document.location`, and dynamic `eval(...)` invocations.
- **False-Positive Mitigation**: Distinguishes mathematical comparison operators (`price < 50 && rating > 4`) from malformed HTML tags.

### 4.4 OS Command Injection Detector (`RCE-001`)
- **Tier 1: Chaining Operators**: Detects `;`, `&&`, `||`, `|`, `&` directly followed by common shell binaries (`cat`, `whoami`, `id`, `ls`, `curl`, `wget`, `bash`, `powershell`).
- **Tier 2: Command Substitutions**: Identifies `$(...)`, `` `...` ``, and `${IFS}` separator evasion.
- **Tier 3: Redirection & Sockets**: Detects reverse shell sockets (`> /dev/tcp/`), `2>&1`, and pipe to interpreters (`| sh`, `| bash`).
- **Tier 4: Process Invocations**: Identifies `/bin/sh`, `powershell.exe`, and `cmd.exe`.
- **False-Positive Mitigation**: Requires shell binary context, ensuring regular punctuation (such as semicolons in sentences) is ignored.

### 4.5 Path Traversal & File Escape Detector (`TRAV-001`)
- **Tier 1: Relative Traversal Sequences**: Detects `../`, `..\`, `....//`, and `/../`.
- **Tier 2: Encoded Variations**: Unmasks `%2e%2e%2f`, `%252e%252e%252f`, and overlong UTF-8 directory sequences.
- **Tier 3: High-Value System Targets**: Probes targeting `/etc/passwd`, `/etc/shadow`, `windows/win.ini`, `system32`, and `/proc/self/environ`.
- **Safety Guarantee**: In-memory regex evaluation only; the detector never accesses the underlying host filesystem.


