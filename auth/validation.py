"""
Input validation for the manual account-creation flow.

Mirrors security/validation.py's pattern (a pure string-format check,
no external calls) for the same reason: keep validation logic in one
small, obviously-correct place rather than inline in the form handler.
"""
import re

# A pragmatic email check (something@something.tld) - not a full RFC
# 5322 parser, which is far stricter than any real signup form needs.
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_email_format(email: str) -> bool:
    return bool(EMAIL_REGEX.match((email or "").strip()))
