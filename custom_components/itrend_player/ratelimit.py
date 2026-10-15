"""Gleitende Zeitfenster-Begrenzung je Schluessel (Quelladresse, Geraet)."""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Callable

_MAX_KEYS = 2048


class SlidingWindowLimiter:
    """Zaehlt Ereignisse je Schluessel in einem Zeitfenster."""

    def __init__(self, limit: int, window: float, clock: Callable[[], float]) -> None:
        self.limit = limit
        self.window = window
        self._clock = clock
        self._events: dict[str, deque[float]] = {}

    def _prune(self, key: str, now: float) -> deque[float]:
        dq = self._events.get(key)
        if dq is None:
            dq = self._events[key] = deque()
            if len(self._events) > _MAX_KEYS:
                self._gc(now)
        while dq and now - dq[0] >= self.window:
            dq.popleft()
        return dq

    def _gc(self, now: float) -> None:
        for k in [k for k, dq in self._events.items() if not dq or now - dq[-1] >= self.window]:
            del self._events[k]

    def blocked(self, key: str) -> bool:
        """True, wenn das Limit schon erreicht ist (zaehlt nichts)."""
        return len(self._prune(key, self._clock())) >= self.limit

    def record(self, key: str) -> None:
        now = self._clock()
        self._prune(key, now).append(now)

    def hit(self, key: str) -> bool:
        """Zaehlt ein Ereignis; False, wenn das Limit damit ueberschritten waere."""
        now = self._clock()
        dq = self._prune(key, now)
        if len(dq) >= self.limit:
            return False
        dq.append(now)
        return True

    def retry_after(self, key: str) -> int:
        now = self._clock()
        dq = self._prune(key, now)
        if not dq or len(dq) < self.limit:
            return 1
        return max(1, math.ceil(self.window - (now - dq[0])))
