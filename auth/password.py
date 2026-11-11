"""
Password hashing helpers.

Uses bcrypt: a salted, deliberately-slow adaptive hash designed for
passwords (unlike plain SHA-256, it resists brute-force/GPU cracking
by design). Plain-text and reversible-encryption passwords are never
stored anywhere in this system.
"""
import bcrypt


def hash_password(plain_password: str) -> str:
    """Hash a plain-text password for storage.

    Returns a UTF-8 string (bcrypt's own encoding, includes the salt)
    safe to store directly in the users.password_hash column.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, password_hash) -> bool:
    """Check a plain-text password against a stored bcrypt hash.

    password_hash is None for a Google-only account (see
    database/schema.sql) - that account simply has no local password
    to check against, so this correctly returns False rather than
    raising, letting a Google user who tries the manual form see
    "invalid email or password" instead of a crash.
    """
    if password_hash is None:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), password_hash.encode("utf-8")
        )
    except (ValueError, TypeError, AttributeError):
        # Hash in the database is missing/malformed - fail closed
        # rather than raise, so a bad row can't crash the login page.
        return False
