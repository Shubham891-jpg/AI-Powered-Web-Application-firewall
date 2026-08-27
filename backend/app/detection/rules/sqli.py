"""
Advanced Multi-Tier SQL Injection (SQLi) Detection Rule.
Combines structural syntax parsing, token analysis, keyword proximity,
and tautology heuristics per Section 9 of the specification.
"""

import re
from typing import Any
from app.detection.rules.base import BaseRule, RuleResult, score_to_confidence

# 1. Structural SQL Syntax Patterns
STRUCTURAL_PATTERNS = [
    (re.compile(r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\b"), 90, "SQL UNION injection clause"),
    (re.compile(r"(?i)\bSELECT\s+.+\s+FROM\s+\w+"), 85, "SQL SELECT ... FROM query structure"),
    (re.compile(r"(?i)\bINSERT\s+INTO\s+\w+\s*\(?.*\)?\s*VALUES\b"), 85, "SQL INSERT INTO clause"),
    (re.compile(r"(?i)\bUPDATE\s+\w+\s+SET\s+\w+\s*="), 80, "SQL UPDATE SET clause"),
    (re.compile(r"(?i)\bDELETE\s+FROM\s+\w+"), 85, "SQL DELETE FROM clause"),
    (re.compile(r"(?i)\bORDER\s+BY\s+\d+\b"), 75, "SQL column enumeration (ORDER BY n)"),
]

# 2. Boolean Logic & Tautology Patterns
TAUTOLOGY_PATTERNS = [
    (re.compile(r"(?i)[\'\"]\s*(?:OR|AND)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+"), 85, "Boolean numeric tautology (' OR 1=1)"),
    (re.compile(r"(?i)[\'\"]\s*(?:OR|AND)\s+[\'\"][a-zA-Z0-9]+[\'\"]\s*=\s*[\'\"][a-zA-Z0-9]+"), 85, "Boolean string tautology (' OR 'a'='a')"),
    (re.compile(r"(?i)\b(?:OR|AND)\s+\d+\s*=\s*\d+\b"), 80, "Unquoted boolean tautology (OR 1=1)"),
    (re.compile(r"(?i)\b(?:WHERE|HAVING)\s+1\s*=\s*1\b"), 75, "SQL condition tautology (WHERE/HAVING 1=1)"),
]

# 3. Stacked Commands & Dangerous Procedures
STACKED_PATTERNS = [
    (re.compile(r"(?i);\s*(?:DROP|ALTER|TRUNCATE)\s+(?:TABLE|DATABASE)\b"), 95, "Stacked destructive SQL statement (DROP/ALTER)"),
    (re.compile(r"(?i)\bEXEC(?:UTE)?\s+(?:master\.\.)?(?:xp_|sp_)\w+"), 95, "Dangerous stored procedure execution (xp_cmdshell)"),
    (re.compile(r"(?i)\bWAITFOR\s+DELAY\s+[\'\"]\d+:\d+:\d+[\'\"]"), 90, "Time-based blind SQL injection (WAITFOR DELAY)"),
]

# 4. Fingerprint Functions & Inline Comments
FINGERPRINT_PATTERNS = [
    (re.compile(r"(?i)\b(?:SLEEP|BENCHMARK|PG_SLEEP)\s*\(\s*\d+"), 90, "Time-delay blind injection function"),
    (re.compile(r"(?i)\b(?:DATABASE|VERSION|CURRENT_USER|SCHEMA)\s*\(\s*\)"), 70, "Database metadata reconnaissance function"),
    (re.compile(r"(?i)\bCONCAT\s*\(.+\)"), 60, "SQL CONCAT function"),
    (re.compile(r"(?i)(?:--|\#|/\*.*?\*/)"), 50, "SQL comment delimiter sequence"),
]


class SQLInjectionRule(BaseRule):
    """
    Modular SQL Injection Analyzer.
    Classifies requests into: NO_EVIDENCE, SUSPICIOUS, LIKELY, HIGH_CONFIDENCE.
    """

    def __init__(self):
        super().__init__(
            rule_id="SQLI-001",
            name="Advanced SQL Injection Detector",
            category="SQL_INJECTION",
            score=85,
        )

    def analyze(self, target_text: str) -> RuleResult:
        if not target_text or len(target_text.strip()) == 0:
            return RuleResult(
                matched=False,
                category="NORMAL",
                score=0,
                rule_id=self.rule_id,
            )

        matched_reasons: list[str] = []
        indicators: list[str] = []
        highest_score = 0

        # Scan all tiers
        all_tiers = [
            ("STRUCTURAL", STRUCTURAL_PATTERNS),
            ("TAUTOLOGY", TAUTOLOGY_PATTERNS),
            ("STACKED", STACKED_PATTERNS),
            ("FINGERPRINT", FINGERPRINT_PATTERNS),
        ]

        match_count = 0
        for tier_name, pattern_list in all_tiers:
            for regex, score, reason in pattern_list:
                match = regex.search(target_text)
                if match:
                    match_count += 1
                    matched_reasons.append(reason)
                    indicators.append(f"{tier_name}: {match.group(0)}")
                    if score > highest_score:
                        highest_score = score

        # Contextual scoring adjustment
        # If comments alone are found without any other SQL indicators, reduce score to avoid false positives on code snippets or hashtags
        if match_count == 1 and highest_score == 50 and any("comment delimiter" in r for r in matched_reasons):
            # Solitary hash or double dash without SQL context is likely benign (e.g. hashtag or markdown)
            if not re.search(r"(?i)\b(select|insert|update|delete|from|where|union)\b", target_text):
                highest_score = 0
                matched_reasons.clear()
                indicators.clear()

        # Compounding score if multiple distinct tiers trigger
        if match_count >= 2:
            highest_score = min(100, highest_score + 10)

        confidence = score_to_confidence(highest_score)

        return RuleResult(
            matched=highest_score >= 30,
            category=self.category if highest_score >= 30 else "NORMAL",
            score=highest_score,
            rule_id=self.rule_id,
            confidence=confidence,
            reason="; ".join(matched_reasons) if matched_reasons else "",
            indicators=indicators,
            metadata={"match_count": match_count, "highest_tier_score": highest_score},
        )
