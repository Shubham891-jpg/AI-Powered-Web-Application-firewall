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

---

## 5. Supervised Machine Learning Pipeline (Phase 4)

### 5.1 Architecture & Strategy
- **Baseline Classifier**: Supervised `LogisticRegression(class_weight='balanced', C=5.0, solver='lbfgs')` trained on character n-grams.
- **Feature Extraction**: `TfidfVectorizer(analyzer='char', ngram_range=(2, 5), max_features=10000)`.
- **Train/Serve Skew Elimination**: The training pipeline normalizes training payloads using the exact same multi-pass `RequestNormalizer` as the runtime gateway before vectorization.
- **Strict Data Isolation**: 80/20 train/test split stratified by `attack_type` executed strictly before vectorizer fitting to prevent any data leakage.

### 5.2 Research Dataset Curation
The training dataset (`ml/data/processed/dataset.csv`) incorporates standard CSIC 2010 HTTP patterns and controlled multi-class security vectors across 5 categories:
- `NORMAL`: Standard browsing, REST queries, API headers, e-commerce actions, JSON bodies.
- `SQL_INJECTION`: UNION selects, boolean tautologies, stacked statements, sleep injection.
- `CROSS_SITE_SCRIPTING`: Markup tags, event handlers, javascript URIs, DOM access.
- `COMMAND_INJECTION`: Chaining operators, subshell commands, reverse shell probes.
- `PATH_TRAVERSAL`: Relative dot traversals, encoded traversals, sensitive system file probes.

### 5.3 Model Evaluation & Performance Metrics
- **Overall Accuracy**: 98.33% on held-out test evaluation.
- **Macro F1-Score**: 0.99 across all attack categories.
- **Benign False Positive Rate (FPR)**: 5.00% on normal web application traffic.
- **Inference Latency Benchmark**:
  - Average inference latency: **0.593 ms** (Target: < 5.000 ms -> **PASS**)
  - 95th Percentile (p95): **0.841 ms**
- **Artifact Serialization**:
  - Model: `ml/models/waf_classifier_v1.joblib`
  - Vectorizer: `ml/models/tfidf_vectorizer_v1.joblib`
  - Metadata: `ml/models/metadata_v1.json` (stores version `1.0.0`, training timestamp, vocabulary size, and confusion matrix).

---

## 6. Detection Engine Fusion & Risk Scoring (Phase 5)

The AI-WAF combines deterministic rule-based matching, machine-learning classification, and contextual request heuristics into a unified risk score.

### 6.1 Mathematical Fusion Formula
$$R_{\text{composite}} = \min\left(100, \max\left(R_{\text{override}}, \text{round}\left(w_{\text{rule}} \cdot S_{\text{rule}} + w_{\text{ml}} \cdot S_{\text{ml}} + \text{SynergyBonus} + \sum P_{\text{context}}\right)\right)\right)$$

Where:
- $S_{\text{rule}}$: Maximum score among matched rules ($0 - 100$).
- $S_{\text{ml}}$: Machine learning threat score. If ML predicts a malicious class, $S_{\text{ml}} = \text{confidence} \times 100$. If `NORMAL`, $S_{\text{ml}} = \max(0, (1 - \text{confidence}) \times 20)$.
- $w_{\text{rule}}$: Rule weight (default: $0.60$).
- $w_{\text{ml}}$: ML weight (default: $0.40$).
- **High-Confidence Rule Override ($R_{\text{override}}$)**: If any active rule reports `HIGH_CONFIDENCE` ($\ge 80$), $R_{\text{override}} = \max(S_{\text{rule}}, 85)$. Confirmed weaponized exploits are guaranteed to trigger a `BLOCK` regardless of ML confidence.
- **Corroboration Synergy**: $+15$ bonus points applied when both rules ($S_{\text{rule}} \ge 50$) and ML ($\text{conf} \ge 0.40$) confirm an active attack vector, driving the composite risk score into the $90-100$ range.
- **Contextual Threat Penalties ($\sum P_{\text{context}}$)**:
  - `SENSITIVE_PATH_ACCESS`: $+15$ points for probing `/admin`, `/.env`, `/auth`, `/login`, etc.
  - `NESTED_ENCODING_EVASION`: $+15$ points per recursion pass above depth 1.
  - `NULL_BYTE_INJECTION`: $+25$ points for `%00` or `\x00` presence.
  - `UNICODE_HOMOGLYPH_ANOMALY`: $+10$ points for fullwidth or homoglyph character substitutions.

### 6.2 Decision Thresholds & Modes
- **Configurable Boundaries**:
  - `0 - 29`: **`ALLOW`** (Benign traffic passes cleanly)
  - `30 - 69`: **`FLAG`** (Suspicious traffic allowed but logged with telemetry headers)
  - `70 - 100`: **`BLOCK`** (Malicious traffic terminated with HTTP 403)
- **Operational Enforcement Modes**:
  - `BLOCK`: Standard enforcement mode. Scores $\ge 70$ return HTTP 403.
  - `FLAG_ONLY`: Staging / dry-run mode. Blocks are downgraded to `FLAG` for policy tuning.
  - `MONITOR`: Silent observation mode. All requests pass through with risk scoring recorded.

### 6.3 Explainability Payload (`InspectionExplanation`)
Every inspection produces a structured audit record per Section 20 of the specification:
```json
{
  "request_id": "req-98e3b1c4",
  "timestamp": "2026-08-28T05:15:00.000Z",
  "decision": "BLOCK",
  "risk_score": 95,
  "category": "SQL_INJECTION",
  "rule_matches": [
    {
      "rule_id": "SQLI-001",
      "rule_name": "SQL Injection Detector",
      "category": "SQL_INJECTION",
      "confidence": "HIGH_CONFIDENCE",
      "score": 85,
      "reason": "Detected structural UNION ... SELECT statement clause",
      "indicators": ["UNION SELECT"]
    }
  ],
  "ml_prediction": {
    "predicted_class": "SQL_INJECTION",
    "confidence": 0.924,
    "model_name": "waf_classifier",
    "model_version": "1.0.0",
    "vectorizer_version": "1.0.0",
    "latency_ms": 0.58
  },
  "contextual_penalties": [
    {
      "factor": "NESTED_ENCODING_EVASION",
      "penalty_points": 15,
      "reason": "Nested URL encoding detected with recursion depth of 2"
    }
  ],
  "primary_reason": "[SQLI-001 / HIGH_CONFIDENCE] Detected structural UNION ... SELECT statement clause",
  "latency_ms": 1.15
}
```




