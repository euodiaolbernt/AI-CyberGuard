"""Malaysia wall-clock time - the single source of truth for every
naive DATETIME column this app writes.

This project's DATETIME columns are naive and were designed to hold
Malaysia local time directly (see utils/time_navigator.py's own
docstring: every "today"/"last 7 days"/etc. boundary is computed from
Asia/Kuala_Lumpur wall-clock time and compared straight against these
columns). That held automatically back when every write relied on
MySQL's own NOW()/DEFAULT CURRENT_TIMESTAMP against a local XAMPP
MySQL server whose OS clock was Malaysia time. It silently broke once
the backend became a shared TiDB Cloud cluster (whose own clock is
UTC) reachable from both localhost and Streamlit Cloud - every
timestamp column started recording UTC instead, regardless of where
the Streamlit process itself runs. now_myt() is what every INSERT/
UPDATE that used to lean on NOW()/CURRENT_TIMESTAMP now calls instead,
so the stored value is always Malaysia time no matter which host or
database server executes the write.
"""
from datetime import datetime
from zoneinfo import ZoneInfo

MALAYSIA_TZ = ZoneInfo("Asia/Kuala_Lumpur")


def now_myt() -> datetime:
    """Naive current Malaysia time, safe to write straight into any of
    this project's naive DATETIME columns."""
    return datetime.now(MALAYSIA_TZ).replace(tzinfo=None)
