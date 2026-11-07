"""Minimal, dependency-free cron schedule (5 fields: minute hour day-of-month month day-of-week).

Supports *, lists (1,15), ranges (1-5), steps (*/15, 0-30/5) and the aliases
@hourly @daily @weekly @monthly. Day-of-week: 0-7 (0 and 7 = Sunday) or mon..sun.
Like cron, when both day-of-month and day-of-week are restricted, either may match.
Times are evaluated in the container's local time zone (set TZ, e.g. TZ=America/Toronto).
"""
from __future__ import annotations

from datetime import datetime, timedelta

ALIASES = {"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *",
           "@weekly": "0 0 * * 0", "@monthly": "0 0 1 * *"}
NAMES = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
         "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8,
         "sep": 9, "oct": 10, "nov": 11, "dec": 12}
BOUNDS = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]


def _num(tok: str) -> int:
    tok = tok.lower()
    return NAMES[tok] if tok in NAMES else int(tok)


def _field(spec: str, lo: int, hi: int) -> set[int]:
    out: set[int] = set()
    for part in spec.split(","):
        rng, _, step = part.partition("/")
        step_n = int(step) if step else 1
        if step_n < 1:
            raise ValueError(f"invalid step in {part!r}")
        if rng == "*":
            a, b = lo, hi
        elif "-" in rng:
            a, b = (_num(x) for x in rng.split("-", 1))
        else:
            a = _num(rng)
            b = hi if step else a
        if not (lo <= a <= hi and lo <= b <= hi) or a > b:
            raise ValueError(f"value out of range in {part!r} (allowed {lo}-{hi})")
        out.update(range(a, b + 1, step_n))
    return out


class Cron:
    def __init__(self, expr: str):
        self.expr = expr.strip()
        fields = ALIASES.get(self.expr.lower(), self.expr).split()
        if len(fields) != 5:
            raise ValueError(f"cron expression needs 5 fields, got {len(fields)}: {expr!r}")
        self.minute, self.hour, self.dom, self.month, dow = (
            _field(f, lo, hi) for f, (lo, hi) in zip(fields, BOUNDS, strict=True))
        self.dow = {d % 7 for d in dow}
        self.dom_any, self.dow_any = fields[2] == "*", fields[4] == "*"

    def _day_ok(self, t: datetime) -> bool:
        dom_ok = t.day in self.dom
        dow_ok = (t.isoweekday() % 7) in self.dow
        if self.dom_any or self.dow_any:
            return dom_ok and dow_ok
        return dom_ok or dow_ok

    def next_after(self, t: datetime) -> datetime:
        t = t.replace(second=0, microsecond=0) + timedelta(minutes=1)
        limit = t + timedelta(days=366 * 5)
        while t < limit:
            if t.month not in self.month:
                t = (t.replace(day=1, hour=0, minute=0) + timedelta(days=32)).replace(day=1)
                continue
            if not self._day_ok(t):
                t = (t + timedelta(days=1)).replace(hour=0, minute=0)
                continue
            if t.hour not in self.hour:
                t = (t + timedelta(hours=1)).replace(minute=0)
                continue
            if t.minute not in self.minute:
                t += timedelta(minutes=1)
                continue
            return t
        raise ValueError(f"cron expression {self.expr!r} never matches")
