"""
Advanced Operating System Command Injection (RCE) Detection Rule.
Performs token analysis, shell chaining syntax detection, command substitutions,
and interpreter piping detection per Section 11 of the specification.
"""

import re
from typing import Any
from app.detection.rules.base import BaseRule, RuleResult, score_to_confidence

# Common binary utilities frequently abused in RCE
COMMAND_BINARIES = r"(?:cat|ls|id|whoami|uname|hostname|nc|netcat|ncat|wget|curl|bash|sh|zsh|dash|powershell|cmd|cmd\.exe|certutil|python|perl|ruby|rm|chmod|chown|kill|touch|mkdir|cp|mv)"

# 1. Shell Chaining Operators with Binary Context
CHAINING_PATTERNS = [
    (
        re.compile(rf"(?i)(?:;|\|\||&&|\||&)\s*{COMMAND_BINARIES}\b"),
        95,
        "Shell command chaining operator coupled with system binary (;&|)",
    ),
    (
        re.compile(r"(?i)\|\s*(?:bash|sh|powershell|cmd|python|perl)\b"),
        95,
        "Piped execution to shell interpreter (| sh/bash)",
    ),
]

# 2. Command Substitution Syntaxes
SUBSTITUTION_PATTERNS = [
    (
        re.compile(rf"(?i)\$\(\s*{COMMAND_BINARIES}\b"),
        95,
        "POSIX subshell execution syntax ($(...))",
    ),
    (
        re.compile(rf"(?i)`\s*{COMMAND_BINARIES}\b[^`]*`"),
        90,
        "Backtick command execution syntax (`...`)",
    ),
    (
        re.compile(r"\$\{IFS\}|\$IFS\b"),
        90,
        "Internal Field Separator (IFS) shell evasion technique",
    ),
]

# 3. Network Redirection & Socket Probes
REDIRECTION_PATTERNS = [
    (
        re.compile(r"(?i)>\s*/dev/(?:tcp|udp)/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
        95,
        "Bash pseudo-device reverse shell socket redirection (/dev/tcp)",
    ),
    (
        re.compile(r"2>&1"),
        75,
        "Standard error file descriptor redirection (2>&1)",
    ),
    (
        re.compile(r"(?i)\|\s*base64\s+(?:-d|--decode)\b"),
        90,
        "Piped base64 payload decoding execution",
    ),
]

# 4. Direct Shell Binary / Interpreter Paths
SYSTEM_PATH_PATTERNS = [
    (
        re.compile(r"(?i)\b/(?:bin|usr/bin|usr/local/bin)/(?:sh|bash|zsh|dash|python)\b"),
        85,
        "Absolute Unix shell binary path invocation",
    ),
    (
        re.compile(r"(?i)\b(?:cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe)\b"),
        85,
        "Windows shell host process execution",
    ),
]


class CommandInjectionRule(BaseRule):
    """
    Modular Command Injection Detector.
    Identifies attempts to influence OS command execution without executing input.
    """

    def __init__(self):
        super().__init__(
            rule_id="RCE-001",
            name="Advanced OS Command Injection Detector",
            category="COMMAND_INJECTION",
            score=90,
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
            ("CHAINING", CHAINING_PATTERNS),
            ("SUBSTITUTION", SUBSTITUTION_PATTERNS),
            ("REDIRECTION", REDIRECTION_PATTERNS),
            ("SYSTEM_PATH", SYSTEM_PATH_PATTERNS),
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
