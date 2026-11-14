from collections import OrderedDict, deque
from threading import Lock
from time import monotonic

from fastapi import HTTPException, status


class RequestRateLimiter:
    # shortcut: per-process; use shared storage before scaling API or expecting limits to survive restarts.
    def __init__(self, limit: int = 120, window_seconds: int = 60, max_subjects: int = 2048):
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_subjects = max_subjects
        self._requests: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = Lock()

    def check(self, subject: str) -> None:
        now = monotonic()
        with self._lock:
            requests = self._requests.get(subject)
            if requests is None:
                if len(self._requests) >= self.max_subjects:
                    self._requests.popitem(last=False)
                requests = deque()
                self._requests[subject] = requests
            else:
                self._requests.move_to_end(subject)
            cutoff = now - self.window_seconds
            while requests and requests[0] <= cutoff:
                requests.popleft()
            if len(requests) >= self.limit:
                retry_after = max(1, int(requests[0] + self.window_seconds - now))
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "Request rate limit exceeded",
                    headers={"Retry-After": str(retry_after)},
                )
            requests.append(now)
