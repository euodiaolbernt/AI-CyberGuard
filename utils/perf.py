"""
Lightweight execution-time instrumentation for diagnosing slow spots -
opt-in only, via the PERF_LOGGING environment variable, so it costs
nothing (not even a timer call) in normal/production use and never
shows up in the UI. Logs to Python's own `logging` (the server
console/terminal running `streamlit run`), never to the browser - a
timing number is diagnostic information for whoever runs the app, not
something an end user needs to see.

Usage:
    from utils.perf import timed

    @timed("load_models")
    def load_models(...): ...

    # or as a context manager around a block:
    with timed("dashboard KPI row"):
        ...

Enable with PERF_LOGGING=true in .env, then watch the terminal running
`streamlit run app.py` for lines like:
    [PERF] load_models: 96.7 ms
"""
import functools
import logging
import os
import time
from contextlib import ContextDecorator

_ENABLED = os.getenv("PERF_LOGGING", "").strip().lower() in ("1", "true", "yes")

_logger = logging.getLogger("ai_cyberguard.perf")
if _ENABLED and not _logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[PERF] %(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


class timed(ContextDecorator):
    """A no-op (zero timer calls) unless PERF_LOGGING is enabled -
    usable as either a decorator (`@timed("label")`) or a context
    manager (`with timed("label"):`), so the SAME helper covers both
    "time this whole function" and "time just this block" without two
    separate utilities."""

    __slots__ = ("label", "_start")

    def __init__(self, label: str):
        self.label = label

    def __call__(self, func):
        if not _ENABLED:
            return func
        return super().__call__(func)

    def __enter__(self):
        if _ENABLED:
            self._start = time.perf_counter()
        return self

    def __exit__(self, *exc):
        if _ENABLED:
            elapsed_ms = (time.perf_counter() - self._start) * 1000
            _logger.info("%s: %.1f ms", self.label, elapsed_ms)
        return False
