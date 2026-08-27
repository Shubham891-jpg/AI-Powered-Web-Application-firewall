# ML Dataset Repository for AI-WAF

This directory stores datasets utilized for training and evaluating the AI-WAF supervised classifier.

## Directory Structure:
- `raw/`: Untouched research datasets (such as CSIC 2010 HTTP Dataset, ECML/PKDD, and synthetic benign HTTP traffic).
- `processed/`: Canonicalized CSV/Parquet datasets matching schema:
  - `request`: Normalized HTTP request string (method, path, query, headers, body)
  - `label`: Binary classification label (`NORMAL` vs `MALICIOUS`)
  - `attack_type`: Granular classification (`NONE`, `SQL_INJECTION`, `CROSS_SITE_SCRIPTING`, `COMMAND_INJECTION`, `PATH_TRAVERSAL`, `SUSPICIOUS`)

## Preprocessing Pipeline:
1. Parse raw HTTP log streams
2. Clean & deduplicate requests
3. Apply multi-pass decoding & Unicode NFKC normalization
4. Split into train/validation/test sets (80% / 10% / 10%) with stratification
5. Vectorize using character n-grams TF-IDF (fitted strictly on training split)
