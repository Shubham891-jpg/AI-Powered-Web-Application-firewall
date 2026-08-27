"""
Advanced Path Traversal & File System Escape Detection Rule.
Inspects relative traversal sequences, encoded sequences, mixed separators,
and sensitive system files per Section 12 of the specification.
Never accesses the local host filesystem.
"""

import re
from typing import Any
from app.detection.rules.base import BaseRule, RuleResult, score_to_confidence

# 1. Relative Dot-Dot Sequences
RELATIVE_PATTERNS = [
    (re.compile(r"(?:\.\.[/\\])"), 85, "Relative directory traversal sequence (../ or ..\\)"),
    (re.compile(r"(?:\.\.\.\.[/\\]{1,2})"), 90, "Multi-dot path traversal evasion (....//)"),
    (re.compile(r"(?:[/\\]\.\.[/\\])"), 90, "Enclosed parent directory reference (/../)"),
]

# 2. URL-Encoded and Obfuscated Traversals
ENCODED_PATTERNS = [
    (
        re.compile(r"(?i)(?:%2e%2e(?:%2f|%5c|\/|\\)|\.\.(?:%2f|%5c))"),
        90,
        "URL-encoded dot-dot traversal (%2e%2e%2f)",
    ),
    (
        re.compile(r"(?i)%252e%252e(?:%252f|%255c)"),
        95,
        "Double URL-encoded traversal sequence (%252e%252e%252f)",
    ),
    (
        re.compile(r"(?i)(?:%c0%ae%c0%ae|%e0%80%ae%e0%80%ae)"),
        95,
        "Overlong UTF-8 directory traversal evasion",
    ),
]

# 3. High-Value Sensitive OS Files & Configuration Paths
TARGET_FILE_PATTERNS = [
    (
        re.compile(r"(?i)\b(?:etc/(?:passwd|shadow|hosts|sudoers|group))\b"),
        95,
        "Sensitive Unix configuration probe (/etc/passwd, /etc/shadow)",
    ),
    (
        re.compile(r"(?i)\b(?:windows/(?:win\.ini|system32|repair/sam|boot\.ini))\b"),
        95,
        "Sensitive Windows system probe (win.ini, system32)",
    ),
    (
        re.compile(r"(?i)\b(?:proc/(?:self/environ|version|cmdline|mounts))\b"),
        90,
        "Linux virtual procfs information disclosure probe (/proc/self/environ)",
    ),
    (
        re.compile(r"(?i)\b(?:boot\.ini|ntldr|autoexec\.bat)\b"),
        85,
        "Legacy Windows boot file probe (boot.ini)",
    ),
]


class PathTraversalRule(BaseRule):
    """
    Modular Path Traversal Detector.
    Identifies path traversal probes and sensitive file targets without filesystem access.
    """

    def __init__(self):
        super().__init__(
            rule_id="TRAV-001",
            name="Advanced Path Traversal Detector",
            category="PATH_TRAVERSAL",
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
        match_count = 0

        all_tiers = [
            ("RELATIVE", RELATIVE_PATTERNS),
            ("ENCODED", ENCODED_PATTERNS),
            ("TARGET_FILE", TARGET_FILE_PATTERNS),
        ]

        for tier_name, patterns in all_tiers:
            for regex, score, reason in patterns:
                match = regex.search(target_text)
                if match:
                    match_count += 1
                    matched_reasons.append(reason)
                    indicators.append(f"{tier_name}: {match.group(0)}")
                    if score > highest_score:
                        highest_score = score

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
