"""CWE to OWASP Top 10 (2021) tags and per-CWE fix suggestions."""
OWASP = {
    "CWE-78": "A03:2021 Injection",
    "CWE-89": "A03:2021 Injection",
    "CWE-22": "A01:2021 Broken Access Control",
}

CWE_NAMES = {
    "CWE-78": "Command injection",
    "CWE-89": "SQL injection",
    "CWE-22": "Path traversal",
}

FIXES = {
    "CWE-78": "Pass the command as an argument list without shell=True, or quote the "
              "user value with shlex.quote() before building the command string.",
    "CWE-89": "Use a parameterized query: cursor.execute(\"... WHERE id = ?\", (value,)) "
              "instead of building SQL with +, % or f-strings.",
    "CWE-22": "Run the name through werkzeug.utils.secure_filename(), then resolve the path "
              "with os.path.realpath() and check it starts with the allowed base folder.",
}


def tag(cwe: str) -> str:
    return OWASP.get(cwe, "")


def fix_for(cwe: str) -> str:
    return FIXES.get(cwe, "")
