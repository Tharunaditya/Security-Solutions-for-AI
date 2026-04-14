"""
Denial of Service — Resource Usage Monitor for AI Inference
============================================================
Monitors per-request inference resource usage and detects anomalies
that may indicate sponge example or DoS attacks.

Tracks: inference time, input length, memory usage (simulated).
"""

import time
import random
import math
from collections import deque
from typing import Optional


# ---------------------------------------------------------------------------
# Simulated inference with resource tracking
# ---------------------------------------------------------------------------

class MonitoredInferenceEngine:
    """
    Inference engine that tracks resource usage per request and
    detects anomalous (potentially DoS) requests.
    """

    def __init__(self, max_history: int = 200,
                 time_anomaly_multiplier: float = 5.0,
                 input_length_limit: int = 10000):
        self.max_history = max_history
        self.time_anomaly_multiplier = time_anomaly_multiplier
        self.input_length_limit = input_length_limit

        self._time_history = deque(maxlen=max_history)
        self._length_history = deque(maxlen=max_history)
        self._n_processed = 0
        self._n_blocked = 0
        self._n_anomalies = 0

    def _simulate_inference(self, input_data) -> tuple:
        """Simulate model inference with variable cost."""
        start = time.perf_counter()

        # Compute cost: proportional to input complexity
        if isinstance(input_data, str):
            n = len(input_data)
        elif isinstance(input_data, list):
            n = len(input_data)
        else:
            n = 1

        # Simulate computation
        result = 0.0
        iterations = min(n * 2, 5000)
        for i in range(iterations):
            result += math.sin(i * 0.001) * 0.001

        elapsed = time.perf_counter() - start
        return result, elapsed

    def _estimate_baseline(self) -> tuple:
        """Estimate baseline mean and std from history."""
        if len(self._time_history) < 10:
            return None, None

        times = list(self._time_history)
        mean = sum(times) / len(times)
        std  = math.sqrt(sum((t - mean) ** 2 for t in times) / len(times))
        return mean, std

    def _is_anomalous(self, elapsed: float, input_length: int) -> tuple:
        """
        Detect if a request is anomalously expensive.
        Returns (is_anomalous: bool, reason: str)
        """
        reasons = []

        # Check input length
        if input_length > self.input_length_limit:
            reasons.append(f"Input too long: {input_length} > {self.input_length_limit}")

        # Check inference time against historical baseline
        mean_time, std_time = self._estimate_baseline()
        if mean_time is not None and std_time is not None:
            z_score = (elapsed - mean_time) / max(std_time, 1e-9)
            if elapsed > mean_time * self.time_anomaly_multiplier:
                reasons.append(
                    f"Inference time anomaly: {elapsed*1000:.2f}ms vs "
                    f"baseline {mean_time*1000:.2f}ms ({self.time_anomaly_multiplier}x threshold)"
                )

        return bool(reasons), "; ".join(reasons)

    def process(self, input_data, request_id: str = "unknown") -> dict:
        """
        Process a request with resource monitoring.
        Returns result and resource metrics.
        """
        # Pre-check: input length
        if isinstance(input_data, (str, list)):
            input_length = len(input_data)
        else:
            input_length = 1

        if input_length > self.input_length_limit:
            self._n_blocked += 1
            return {
                "request_id": request_id,
                "status": "blocked",
                "reason": f"Input too long: {input_length} > {self.input_length_limit}",
                "result": None,
                "elapsed_ms": 0,
            }

        # Run inference
        result, elapsed = self._simulate_inference(input_data)

        # Record metrics
        self._time_history.append(elapsed)
        self._length_history.append(input_length)
        self._n_processed += 1

        # Anomaly detection
        is_anomalous, reason = self._is_anomalous(elapsed, input_length)
        if is_anomalous:
            self._n_anomalies += 1

        return {
            "request_id": request_id,
            "status": "anomaly_detected" if is_anomalous else "ok",
            "reason": reason if is_anomalous else None,
            "result": result,
            "elapsed_ms": round(elapsed * 1000, 3),
            "input_length": input_length,
            "is_anomalous": is_anomalous,
        }

    def get_stats(self) -> dict:
        """Return monitoring statistics."""
        if not self._time_history:
            return {"error": "No data yet"}

        times = list(self._time_history)
        mean_t = sum(times) / len(times)
        max_t  = max(times)
        min_t  = min(times)

        return {
            "n_processed": self._n_processed,
            "n_blocked": self._n_blocked,
            "n_anomalies": self._n_anomalies,
            "anomaly_rate": round(self._n_anomalies / max(self._n_processed, 1), 4),
            "avg_elapsed_ms": round(mean_t * 1000, 3),
            "max_elapsed_ms": round(max_t * 1000, 3),
            "min_elapsed_ms": round(min_t * 1000, 3),
        }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    engine = MonitoredInferenceEngine(
        max_history=100,
        time_anomaly_multiplier=3.0,
        input_length_limit=5000,
    )

    print("AI Inference Resource Monitor Demo")
    print("=" * 60)

    # Phase 1: Normal traffic
    print("\n[Phase 1] Processing normal requests (n=50)...")
    for i in range(50):
        input_len = random.randint(10, 200)
        data = "x" * input_len
        result = engine.process(data, request_id=f"normal_{i}")
        if result["is_anomalous"]:
            print(f"  ⚠ Anomaly in normal request {i}: {result['reason']}")

    stats = engine.get_stats()
    print(f"  Processed: {stats['n_processed']} | "
          f"Anomalies: {stats['n_anomalies']} | "
          f"Avg: {stats['avg_elapsed_ms']}ms")

    # Phase 2: Attack traffic (sponge/flood)
    print("\n[Phase 2] Processing attack requests...")

    attack_cases = [
        ("Sponge small",  "x" * 500),
        ("Sponge medium", "x" * 2000),
        ("Flood large",   "x" * 6000),   # Exceeds limit
        ("Flood max",     "x" * 10000),  # Far exceeds limit
    ]

    for name, data in attack_cases:
        result = engine.process(data, request_id=name)
        status = result["status"].upper()
        print(f"  [{name}] Status: {status} | "
              f"Length: {result['input_length']} | "
              f"Time: {result['elapsed_ms']}ms")
        if result["reason"]:
            print(f"    Reason: {result['reason']}")

    # Final stats
    final_stats = engine.get_stats()
    print(f"\n[Final Statistics]")
    print(f"  Total processed:   {final_stats['n_processed']}")
    print(f"  Total blocked:     {final_stats['n_blocked']}")
    print(f"  Total anomalies:   {final_stats['n_anomalies']}")
    print(f"  Anomaly rate:      {final_stats['anomaly_rate']:.1%}")
    print(f"  Avg inference:     {final_stats['avg_elapsed_ms']}ms")
    print(f"  Max inference:     {final_stats['max_elapsed_ms']}ms")
