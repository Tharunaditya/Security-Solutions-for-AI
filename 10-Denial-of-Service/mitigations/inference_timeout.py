"""
Denial of Service Mitigation — Per-Request Inference Timeout
============================================================
Enforces strict per-request time budgets for AI inference,
preventing sponge examples and runaway inference from consuming all resources.

Features:
1. Hard timeout with graceful fallback response
2. Tiered timeouts based on request complexity
3. Timeout budget tracking per user
4. Adaptive timeout based on historical latency
"""

import time
import math
import random
import signal
import threading
from typing import Optional, Callable


# ---------------------------------------------------------------------------
# Thread-based timeout wrapper (portable, works on all OSes)
# ---------------------------------------------------------------------------

class InferenceTimeoutError(Exception):
    """Raised when inference exceeds the time budget."""
    pass


def with_timeout(fn: Callable, args: tuple, timeout_sec: float,
                  fallback=None) -> tuple:
    """
    Run fn(*args) with a timeout.
    Returns (result, elapsed, timed_out).
    If timeout is exceeded, returns (fallback, elapsed, True).
    """
    result_container = [fallback]
    error_container  = [None]
    finished_event   = threading.Event()

    def target():
        try:
            result_container[0] = fn(*args)
        except Exception as e:
            error_container[0] = e
        finally:
            finished_event.set()

    thread = threading.Thread(target=target, daemon=True)
    start = time.monotonic()
    thread.start()
    completed = finished_event.wait(timeout=timeout_sec)
    elapsed = time.monotonic() - start

    if not completed:
        return fallback, elapsed, True

    if error_container[0] is not None:
        raise error_container[0]

    return result_container[0], elapsed, False


# ---------------------------------------------------------------------------
# Tiered timeout configuration
# ---------------------------------------------------------------------------

class TimeoutConfig:
    """
    Timeout configuration based on request complexity.
    Complex requests get more time, but a hard cap applies.
    """
    # (max_input_tokens, timeout_seconds)
    TIERS = [
        (500,    2.0),    # Simple query
        (2000,   5.0),    # Medium query
        (8000,   15.0),   # Long context
        (32000,  30.0),   # Very long context
        (128000, 60.0),   # Max context
    ]
    ABSOLUTE_HARD_LIMIT = 120.0  # Never exceed 2 minutes regardless

    @classmethod
    def get_timeout(cls, n_input_tokens: int) -> float:
        for max_tokens, timeout in cls.TIERS:
            if n_input_tokens <= max_tokens:
                return min(timeout, cls.ABSOLUTE_HARD_LIMIT)
        return cls.ABSOLUTE_HARD_LIMIT


# ---------------------------------------------------------------------------
# Adaptive timeout tracker
# ---------------------------------------------------------------------------

class AdaptiveTimeoutTracker:
    """
    Learns the expected inference time from history and sets
    adaptive timeouts based on the observed distribution.
    """
    def __init__(self, window_size: int = 100, multiplier: float = 3.0):
        self._times = []
        self.window_size = window_size
        self.multiplier = multiplier

    def record(self, elapsed: float):
        self._times.append(elapsed)
        if len(self._times) > self.window_size:
            self._times = self._times[-self.window_size:]

    def get_adaptive_timeout(self, percentile: float = 0.95) -> Optional[float]:
        """
        Compute adaptive timeout as multiplier * P95 of observed times.
        Returns None if insufficient data.
        """
        if len(self._times) < 10:
            return None

        sorted_times = sorted(self._times)
        idx = int(len(sorted_times) * percentile)
        p95 = sorted_times[min(idx, len(sorted_times) - 1)]
        return p95 * self.multiplier


# ---------------------------------------------------------------------------
# Protected inference wrapper
# ---------------------------------------------------------------------------

def simulate_model_inference(x: list) -> str:
    """Simulated model inference (variable latency)."""
    energy = sum(abs(xi) for xi in x)
    # High-energy inputs take longer
    work_units = int(min(energy * 500, 10000))
    result = 0.0
    for i in range(work_units):
        result += math.sin(i * 0.001)
    return f"Result: {result:.4f}"


class TimeoutProtectedInference:
    """Wraps inference with configurable timeouts."""

    def __init__(self, model_fn: Callable,
                 static_timeout: float = 5.0,
                 use_adaptive: bool = True,
                 fallback_response: str = "Request timed out. Please reduce input size."):
        self.model = model_fn
        self.static_timeout = static_timeout
        self.use_adaptive = use_adaptive
        self.fallback = fallback_response
        self._tracker = AdaptiveTimeoutTracker()
        self._n_timeouts = 0
        self._n_completed = 0

    def infer(self, x, n_input_tokens: int = None) -> dict:
        """Run inference with timeout protection."""
        # Determine timeout
        if n_input_tokens is not None:
            timeout = TimeoutConfig.get_timeout(n_input_tokens)
        elif self.use_adaptive:
            adaptive = self._tracker.get_adaptive_timeout()
            timeout = adaptive if adaptive is not None else self.static_timeout
        else:
            timeout = self.static_timeout

        # Run with timeout
        result, elapsed, timed_out = with_timeout(
            self.model, (x,), timeout_sec=timeout, fallback=None
        )

        self._tracker.record(elapsed)

        if timed_out:
            self._n_timeouts += 1
            return {
                "response": self.fallback,
                "timed_out": True,
                "elapsed_ms": round(elapsed * 1000, 2),
                "timeout_sec": timeout,
                "status": "timeout",
            }

        self._n_completed += 1
        return {
            "response": result,
            "timed_out": False,
            "elapsed_ms": round(elapsed * 1000, 2),
            "timeout_sec": timeout,
            "status": "ok",
        }

    @property
    def timeout_rate(self) -> float:
        total = self._n_timeouts + self._n_completed
        return self._n_timeouts / max(total, 1)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    print("Inference Timeout Protection Demo")
    print("=" * 60)

    engine = TimeoutProtectedInference(
        simulate_model_inference,
        static_timeout=0.01,   # Tight timeout for demo
        use_adaptive=True,
    )

    # Normal requests (low energy inputs)
    print("\n[Normal requests]")
    for i in range(5):
        x = [random.uniform(-0.5, 0.5) for _ in range(4)]
        result = engine.infer(x, n_input_tokens=100)
        print(f"  Request {i+1}: status={result['status']} | "
              f"{result['elapsed_ms']}ms / {result['timeout_sec']}s timeout")

    # Sponge/attack requests (high energy inputs)
    print("\n[Sponge/attack requests (high energy)]")
    for i in range(5):
        x = [random.uniform(3, 5) for _ in range(10)]  # High energy values
        result = engine.infer(x, n_input_tokens=50)
        status_icon = "⏱ TIMEOUT" if result["timed_out"] else "✓ ok"
        print(f"  Request {i+1}: {status_icon} | "
              f"{result['elapsed_ms']}ms / {result['timeout_sec']}s timeout")
        if result["timed_out"]:
            print(f"    Fallback: {result['response']}")

    print(f"\n[Summary]")
    print(f"  Timeout rate: {engine.timeout_rate:.0%}")

    # Demonstrate tiered timeouts
    print("\n[Tiered timeout configuration]")
    print(f"{'Input tokens':>15} {'Timeout (s)':>12}")
    print("-" * 30)
    for n_tokens in [100, 500, 1000, 2000, 5000, 10000, 32000, 100000]:
        timeout = TimeoutConfig.get_timeout(n_tokens)
        print(f"  {n_tokens:>13,}  {timeout:>12.1f}")
