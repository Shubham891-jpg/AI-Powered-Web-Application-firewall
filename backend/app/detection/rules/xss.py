"""
Advanced Context-Aware Cross-Site Scripting (XSS) Detection Rule.
Combines markup analysis, event handler inspection, pseudo-protocol detection,
and DOM execution heuristics per Section 10 of the specification.
"""

import re
from typing import Any
from app.detection.rules.base import BaseRule, RuleResult, score_to_confidence

# 1. Dangerous Markup Tags
MARKUP_PATTERNS = [
    (re.compile(r"(?i)<\s*script\b[^>]*>"), 95, "Executable <script> tag injection"),
    (re.compile(r"(?i)<\s*(?:iframe|object|embed|applet)\b[^>]*>"), 90, "Embedded container tag (<iframe/object/embed>)"),
    (re.compile(r"(?i)<\s*svg\b[^>]*\bon\w+\s*="), 95, "SVG element with inline event handler"),
    (re.compile(r"(?i)<\s*base\b[^>]*\bhref\s*="), 80, "Base URL hijacking (<base href=...>)"),
    (re.compile(r"(?i)<\s*meta\b[^>]*\bhttp-equiv\s*=\s*[\'\"]?refresh[\'\"]?"), 85, "Meta refresh redirection tag"),
    (re.compile(r"(?i)<\s*img\b[^>]*\bon\w+\s*="), 90, "IMG tag with embedded event handler"),
]

# 2. Inline DOM Event Handlers
EVENT_HANDLER_PATTERNS = [
    (
        re.compile(r"(?i)\bon(?:load|error|click|mouseover|focus|blur|submit|animationstart|mouseenter|pageshow)\s*=\s*[\'\"]?[^>\'\"]+[\'\"]?"),
        85,
        "DOM inline event handler execution (onload/onerror/onclick)",
    ),
    (re.compile(r"(?i)\bon\w+\s*=\s*[\'\"]?\s*(?:alert|prompt|confirm|eval|fetch)\b"), 95, "Event handler with immediate payload invocation"),
]

# 3. Pseudo-Protocols & Data URIs
PROTOCOL_PATTERNS = [
    (re.compile(r"(?i)javascript\s*:\s*[^\"\s>]+"), 90, "JavaScript pseudo-protocol URI (javascript:...)"),
    (re.compile(r"(?i)data\s*:\s*text\/html\s*(?:;base64)?,"), 85, "Data URI HTML markup injection (data:text/html)"),
    (re.compile(r"(?i)vbscript\s*:\s*[^\"\s>]+"), 85, "VBScript pseudo-protocol URI"),
]

# 4. DOM Manipulation & Dynamic Script Execution
DOM_EXECUTION_PATTERNS = [
    (re.compile(r"(?i)\bdocument\.(?:cookie|location|domain|write|writeln)\b"), 85, "DOM manipulation / cookie access (document.cookie)"),
    (re.compile(r"(?i)\b(?:eval|setTimeout|setInterval|Function)\s*\(\s*.*(?:alert|cookie|location|window)"), 95, "Dynamic JavaScript code execution wrapper"),
    (re.compile(r"(?i)\b(?:alert|prompt|confirm)\s*\(\s*[\'\"]?[^)]*[\'\"]?\s*\)"), 75, "Interactive JavaScript dialog execution (alert/prompt)"),
]


class XSSRule(BaseRule):
    """
    Context-Aware XSS Detection Rule.
    Minimizes false positives on legitimate HTML content or mathematical comparisons.
    """

    def __init__(self):
        super().__init__(
            rule_id="XSS-001",
            name="Advanced Cross-Site Scripting Detector",
            category="CROSS_SITE_SCRIPTING",
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
            ("MARKUP", MARKUP_PATTERNS),
            ("EVENT_HANDLER", EVENT_HANDLER_PATTERNS),
            ("PROTOCOL", PROTOCOL_PATTERNS),
            ("DOM_EXEC", DOM_EXECUTION_PATTERNS),
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

        # False-positive guard: If an alert() is detected in isolation without any tag, handler, or script context
        # (for instance, the word 'alert' in a message like "send alert to users"), verify function call syntax
        if match_count == 1 and highest_score == 75 and any("Interactive JavaScript dialog" in r for r in matched_reasons):
            # Check if it has suspicious parentheses with script context
            if not re.search(r"alert\s*\(\s*[\'\"]?\w*[\'\"]?\s*\)", target_text):
                highest_score = 0
                matched_reasons.clear()
                indicators.clear()

        # Compounding score
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
