"""
Denial of Service Mitigation — Token-Bucket Rate Limiter
=========================================================
Implements a robust token-bucket rate limiter for AI inference endpoints.

Features:
1. Per-user/API-key rate limiting
2. Token-based limits (tokens per minute, matching LLM billing model)
3. Burst allowance
4. Graceful degradation (priority queuing)
5. Circuit breaker for sustained attacks
"""

import time
import random
from collections import deque, defaultdict
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Token Bucket Rate Limiter
# ---------------------------------------------------------------------------

@dataclass
class RateLimitConfig:
    """Configuration for a rate limiter."""
    requests_per_minute: int = 60
    tokens_per_minute: int   = 100_000
    burst_requests: int      = 20
    burst_tokens: int        = 10_000
    # Circuit breaker: block key after N violations in a window
    violation_threshold: int = 5
    violation_window_sec: int = 60


class TokenBucket:
    """Token bucket for rate limiting with refill."""
    def __init__(self, capacity: float, refill_rate: float):
        self.capacity = capacity
        self.rate = refill_rate  # tokens per second
        self._tokens = capacity
        self._last_refill = time.monotonic()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def consume(self, amount: float = 1.0) -> bool:
        self._refill()
        if self._tokens >= amount:
            self._tokens -= amount
            return True
        return False

    @property
    def available(self) -> float:
        self._refill()
        return self._tokens


class PerKeyRateLimiter:
    """
    Rate limiter that tracks usage per API key.
    Combines request-count and token-count limiting.
    """

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self._request_buckets: dict = {}
        self._token_buckets: dict   = {}
        self._violations: dict      = defaultdict(list)
        self._blocked_keys: set     = set()

    def _get_buckets(self, key: str):
        if key not in self._request_buckets:
            self._request_buckets[key] = TokenBucket(
                capacity=self.config.burst_requests,
                refill_rate=self.config.requests_per_minute / 60.0
            )
            self._token_buckets[key] = TokenBucket(
                capacity=self.config.burst_tokens,
                refill_rate=self.config.tokens_per_minute / 60.0
            )
        return self._request_buckets[key], self._token_buckets[key]

    def _record_violation(self, key: str):
        """Record a rate limit violation for circuit-breaker logic."""
        now = time.monotonic()
        window = self.config.violation_window_sec
        # Remove old violations outside the window
        self._violations[key] = [t for t in self._violations[key] if now - t < window]
        self._violations[key].append(now)

        if len(self._violations[key]) >= self.config.violation_threshold:
            self._blocked_keys.add(key)
            return True
        return False

    def check(self, key: str, n_tokens: int = 1) -> dict:
        """
        Check if a request is allowed.

        Returns:
            {
                'allowed': bool,
                'reason': str,
                'retry_after': float (seconds, if rate limited),
                'circuit_broken': bool
            }
        """
        # Circuit breaker check
        if key in self._blocked_keys:
            return {
                "allowed": False,
                "reason": "circuit_breaker_open",
                "retry_after": self.config.violation_window_sec,
                "circuit_broken": True,
            }

        req_bucket, tok_bucket = self._get_buckets(key)

        # Check request rate
        if not req_bucket.consume(1):
            self._record_violation(key)
            retry = 1.0 / (self.config.requests_per_minute / 60.0)
            return {
                "allowed": False,
                "reason": "request_rate_limit",
                "retry_after": round(retry, 2),
                "circuit_broken": False,
            }

        # Check token rate
        if not tok_bucket.consume(n_tokens):
            self._record_violation(key)
            retry = n_tokens / (self.config.tokens_per_minute / 60.0)
            return {
                "allowed": False,
                "reason": "token_rate_limit",
                "retry_after": round(retry, 2),
                "circuit_broken": False,
            }

        return {
            "allowed": True,
            "reason": None,
            "retry_after": 0,
            "circuit_broken": False,
        }

    def get_status(self, key: str) -> dict:
        """Get current rate limit status for a key."""
        if key in self._blocked_keys:
            return {"key": key, "status": "blocked", "violations": len(self._violations[key])}

        req_bucket, tok_bucket = self._get_buckets(key)
        return {
            "key": key,
            "status": "active",
            "available_requests": round(req_bucket.available, 2),
            "available_tokens": round(tok_bucket.available, 2),
            "violations": len(self._violations.get(key, [])),
        }

    def unblock(self, key: str):
        """Manually unblock a key (for admin use)."""
        self._blocked_keys.discard(key)
        self._violations[key] = []


# ---------------------------------------------------------------------------
# Request queue with priority
# ---------------------------------------------------------------------------

class PriorityInferenceQueue:
    """
    Queue for inference requests with priority levels.
    High-priority requests (paid tier) are processed first.
    """

    PRIORITY_HIGH   = 0  # Paid enterprise tier
    PRIORITY_MEDIUM = 1  # Standard tier
    PRIORITY_LOW    = 2  # Free tier

    def __init__(self, max_size_per_priority: int = 10):
        self._queues = {
            self.PRIORITY_HIGH:   deque(maxlen=max_size_per_priority),
            self.PRIORITY_MEDIUM: deque(maxlen=max_size_per_priority),
            self.PRIORITY_LOW:    deque(maxlen=max_size_per_priority),
        }

    def enqueue(self, request: dict, priority: int = 1) -> bool:
        """Add request to queue. Returns False if queue is full."""
        queue = self._queues.get(priority, self._queues[self.PRIORITY_LOW])
        if len(queue) >= queue.maxlen:
            return False
        queue.append(request)
        return True

    def dequeue(self) -> Optional[dict]:
        """Get next request (highest priority first)."""
        for priority in sorted(self._queues.keys()):
            if self._queues[priority]:
                return self._queues[priority].popleft()
        return None

    def size(self) -> int:
        return sum(len(q) for q in self._queues.values())


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("AI Inference Rate Limiter Demo")
    print("=" * 60)

    config = RateLimitConfig(
        requests_per_minute=10,
        tokens_per_minute=1000,
        burst_requests=5,
        burst_tokens=200,
        violation_threshold=3,
        violation_window_sec=30,
    )
    limiter = PerKeyRateLimiter(config)

    # Legitimate user
    print("\n[Legitimate user — 8 requests, small tokens each]")
    allowed = blocked = 0
    for i in range(8):
        result = limiter.check("user_alice", n_tokens=50)
        if result["allowed"]:
            allowed += 1
        else:
            blocked += 1
            print(f"  Request {i+1} blocked: {result['reason']} (retry in {result['retry_after']}s)")
    print(f"  Allowed: {allowed} | Blocked: {blocked}")

    # Attacker — flooding with large requests
    print("\n[Attacker — rapid requests with large token counts]")
    for i in range(20):
        result = limiter.check("user_attacker", n_tokens=500)
        if not result["allowed"]:
            if result["circuit_broken"]:
                print(f"  Request {i+1}: ⛔ CIRCUIT BREAKER — key blocked for {result['retry_after']}s")
                break
            else:
                print(f"  Request {i+1}: blocked ({result['reason']})")

    # Check status
    print("\n[Status]")
    print(f"  Alice:    {limiter.get_status('user_alice')}")
    print(f"  Attacker: {limiter.get_status('user_attacker')}")

    # Priority queue demo
    print("\n[Priority Queue Demo]")
    queue = PriorityInferenceQueue(max_size_per_priority=5)
    queue.enqueue({"id": "free_1", "user": "free_user"},    priority=PriorityInferenceQueue.PRIORITY_LOW)
    queue.enqueue({"id": "paid_1", "user": "enterprise"},   priority=PriorityInferenceQueue.PRIORITY_HIGH)
    queue.enqueue({"id": "std_1",  "user": "standard"},     priority=PriorityInferenceQueue.PRIORITY_MEDIUM)
    queue.enqueue({"id": "paid_2", "user": "enterprise2"},  priority=PriorityInferenceQueue.PRIORITY_HIGH)
    queue.enqueue({"id": "free_2", "user": "free_user2"},   priority=PriorityInferenceQueue.PRIORITY_LOW)

    print(f"  Queue size: {queue.size()}")
    print("  Processing order:")
    while True:
        req = queue.dequeue()
        if req is None:
            break
        print(f"    Processing: {req}")
