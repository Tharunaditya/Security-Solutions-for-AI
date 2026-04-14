"""
Model Extraction Mitigation — Query Rate Limiting & Anomaly Detection
======================================================================
Demonstrates a wrapper around an ML inference endpoint that:
1. Rate limits queries per API key.
2. Detects systematic extraction patterns (too many queries, similar inputs).
3. Degrades output quality for suspected extractors.

In production, combine this with:
- API authentication
- Output perturbation (see output_perturbation.py)
- Model watermarking (see model_watermark.py)
"""

import time
import math
import random
from collections import deque
from typing import Optional


# ---------------------------------------------------------------------------
# Rate limiter (token bucket algorithm)
# ---------------------------------------------------------------------------

class TokenBucket:
    """
    Token bucket rate limiter.
    Allows up to `capacity` requests, refilling at `rate` tokens/second.
    """
    def __init__(self, capacity: float, rate: float):
        self.capacity = capacity
        self.rate = rate
        self._tokens = capacity
        self._last_refill = time.time()

    def _refill(self):
        now = time.time()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def consume(self, tokens: float = 1.0) -> bool:
        """Returns True if the request is allowed, False if rate limited."""
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False


# ---------------------------------------------------------------------------
# Query pattern anomaly detector
# ---------------------------------------------------------------------------

class ExtractionAnomalyDetector:
    """
    Detects model extraction patterns based on:
    1. Unusually high query volume.
    2. Systematic coverage of input space (low query diversity variance).
    3. High proportion of queries near decision boundaries.
    """

    def __init__(self, window_size: int = 100, volume_threshold: int = 50):
        self.window_size = window_size
        self.volume_threshold = volume_threshold
        self.query_history = deque(maxlen=window_size)  # stores query confidences
        self.total_queries = 0
        self.flag_count = 0

    def record_query(self, confidence: float):
        """Record a query's model confidence (proxy for systematic coverage)."""
        self.query_history.append(confidence)
        self.total_queries += 1

    def is_suspicious(self) -> tuple:
        """
        Returns (is_suspicious: bool, reason: str).

        Heuristics:
        - High volume: many queries in the window.
        - Boundary probing: high fraction of near-boundary predictions (confidence ≈ 0.5).
        - Low variance: systematic coverage produces unusually uniform confidence distribution.
        """
        reasons = []

        if len(self.query_history) < 10:
            return False, "insufficient data"

        # Heuristic 1: Volume
        if self.total_queries > self.volume_threshold:
            reasons.append(f"high volume: {self.total_queries} total queries")

        # Heuristic 2: Boundary probing (confidence close to 0.5)
        near_boundary = sum(1 for c in self.query_history if abs(c - 0.5) < 0.15)
        boundary_rate = near_boundary / len(self.query_history)
        if boundary_rate > 0.4:
            reasons.append(f"boundary probing: {boundary_rate:.0%} near-boundary queries")

        # Heuristic 3: Low confidence variance (too systematic)
        confs = list(self.query_history)
        mean_c = sum(confs) / len(confs)
        var_c  = sum((c - mean_c) ** 2 for c in confs) / len(confs)
        if var_c < 0.02:
            reasons.append(f"low confidence variance: {var_c:.4f} (systematic coverage)")

        return bool(reasons), "; ".join(reasons)


# ---------------------------------------------------------------------------
# Protected inference API wrapper
# ---------------------------------------------------------------------------

class ProtectedInferenceAPI:
    """
    Wraps a model's inference endpoint with:
    - Rate limiting
    - Anomaly detection
    - Output degradation for suspected extractors
    """

    def __init__(self, base_model, requests_per_minute: int = 60,
                 burst_capacity: int = 20):
        self.model = base_model
        self._rate_limiters = {}   # api_key → TokenBucket
        self._detectors = {}       # api_key → ExtractionAnomalyDetector
        self.rpm = requests_per_minute
        self.burst = burst_capacity
        self._blocked_keys = set()

    def _get_rate_limiter(self, api_key: str) -> TokenBucket:
        if api_key not in self._rate_limiters:
            self._rate_limiters[api_key] = TokenBucket(
                capacity=self.burst,
                rate=self.rpm / 60.0
            )
        return self._rate_limiters[api_key]

    def _get_detector(self, api_key: str) -> ExtractionAnomalyDetector:
        if api_key not in self._detectors:
            self._detectors[api_key] = ExtractionAnomalyDetector(
                window_size=100,
                volume_threshold=80
            )
        return self._detectors[api_key]

    def query(self, api_key: str, x: list,
              return_probabilities: bool = False) -> dict:
        """
        Protected inference endpoint.

        Returns: {'label': int, 'confidence': float (optional), 'status': str}
        """
        # Check if key is blocked
        if api_key in self._blocked_keys:
            return {"status": "blocked", "label": None, "confidence": None}

        # Rate limit check
        limiter = self._get_rate_limiter(api_key)
        if not limiter.consume():
            return {"status": "rate_limited", "label": None, "confidence": None}

        # Get prediction from model
        probas = self.model.predict_proba(x)
        label = int(probas[1] >= 0.5)
        confidence = max(probas)

        # Record for anomaly detection
        detector = self._get_detector(api_key)
        detector.record_query(probas[1])

        # Check for extraction patterns
        suspicious, reason = detector.is_suspicious()
        if suspicious:
            masked_key = api_key[:4] + "****" if len(api_key) > 4 else "****"
            print(f"  [ALERT] Suspicious activity from key={masked_key}: {reason}")
            self._blocked_keys.add(api_key)
            # Return degraded output for this request before blocking
            label = random.randint(0, 1)
            confidence = 0.5 + random.uniform(0, 0.1)

        # Return output (optionally degrade probability info)
        result = {"status": "ok", "label": label}
        if return_probabilities and not suspicious:
            result["confidence"] = round(confidence, 2)

        return result


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def sigmoid(z):
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class DemoModel:
    def predict_proba(self, x):
        z = sum(xi * i for i, xi in enumerate(x, 1))
        p = sigmoid(z)
        return [1 - p, p]


if __name__ == "__main__":
    model = DemoModel()
    api = ProtectedInferenceAPI(model, requests_per_minute=30, burst_capacity=10)

    print("Query Defense — Rate Limiting & Anomaly Detection Demo")
    print("=" * 60)

    print("\n[Legitimate user — 5 queries]")
    for i in range(5):
        result = api.query("user_alice", [random.uniform(-1, 1) for _ in range(3)],
                           return_probabilities=True)
        print(f"  Query {i+1}: {result}")

    print("\n[Attacker — systematic extraction attempt (100 queries)]")
    for i in range(100):
        x = [random.uniform(-3, 3) for _ in range(3)]
        result = api.query("user_attacker", x)
        if result["status"] != "ok":
            print(f"  Query {i+1}: {result}")
            if result["status"] == "blocked":
                print(f"  Attacker blocked after {i+1} queries.")
                break
        elif i % 20 == 0:
            print(f"  Query {i+1}: OK (label={result['label']})")
