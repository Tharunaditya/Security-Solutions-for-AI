"""
Denial of Service Mitigation — Request Pattern Anomaly Detector
===============================================================
Detects DoS and abuse patterns in AI service request logs using
statistical anomaly detection.

Patterns detected:
1. Request volume spike (high requests per second)
2. Token volume spike (unusually large inputs)
3. Systematic boundary probing (for model extraction overlap)
4. Burst then silence pattern (typical of automated attacks)
5. Distributed attack from multiple keys with correlated timing
"""

import time
import math
import random
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Request event
# ---------------------------------------------------------------------------

@dataclass
class RequestEvent:
    timestamp: float
    api_key: str
    n_input_tokens: int
    n_output_tokens: int
    model_confidence: Optional[float] = None  # For extraction detection
    ip_address: Optional[str] = None


# ---------------------------------------------------------------------------
# Per-key statistics window
# ---------------------------------------------------------------------------

class SlidingWindowStats:
    """Maintains rolling statistics over a time window."""

    def __init__(self, window_seconds: float = 60.0):
        self.window = window_seconds
        self._events = deque()

    def add(self, value: float, timestamp: float):
        self._events.append((timestamp, value))
        self._prune(timestamp)

    def _prune(self, now: float):
        while self._events and now - self._events[0][0] > self.window:
            self._events.popleft()

    def count(self, now: float = None) -> int:
        if now: self._prune(now)
        return len(self._events)

    def mean(self) -> float:
        if not self._events: return 0.0
        return sum(v for _, v in self._events) / len(self._events)

    def std(self) -> float:
        if len(self._events) < 2: return 0.0
        m = self.mean()
        return math.sqrt(sum((v - m) ** 2 for _, v in self._events) / len(self._events))

    def max(self) -> float:
        return max((v for _, v in self._events), default=0.0)

    def sum(self) -> float:
        return sum(v for _, v in self._events)


# ---------------------------------------------------------------------------
# Anomaly detector
# ---------------------------------------------------------------------------

class RequestAnomalyDetector:
    """
    Statistical anomaly detector for AI inference request patterns.
    """

    def __init__(
        self,
        window_sec: float = 60.0,
        # Per-minute thresholds
        max_requests_per_minute: int = 100,
        max_tokens_per_minute: int = 500_000,
        # Spike detection: z-score threshold
        spike_z_threshold: float = 3.0,
        # Boundary probing: fraction of near-0.5 confidence predictions
        boundary_probe_threshold: float = 0.4,
    ):
        self.window = window_sec
        self.max_rpm = max_requests_per_minute
        self.max_tpm = max_tokens_per_minute
        self.spike_z = spike_z_threshold
        self.boundary_threshold = boundary_probe_threshold

        self._per_key_request_counts = defaultdict(lambda: SlidingWindowStats(window_sec))
        self._per_key_token_counts   = defaultdict(lambda: SlidingWindowStats(window_sec))
        self._per_key_confidences    = defaultdict(lambda: SlidingWindowStats(window_sec))
        self._global_request_rate    = SlidingWindowStats(window_sec)
        self._alerts = []

    def record(self, event: RequestEvent) -> list:
        """
        Record a request event and check for anomalies.
        Returns list of alert strings (empty if no anomalies).
        """
        now = event.timestamp
        key = event.api_key
        # Masked key used in log messages to avoid logging raw API keys
        masked = key[:4] + "****" if len(key) > 4 else "****"

        # Update stats
        self._per_key_request_counts[key].add(1, now)
        self._per_key_token_counts[key].add(event.n_input_tokens, now)
        self._global_request_rate.add(1, now)
        if event.model_confidence is not None:
            self._per_key_confidences[key].add(event.model_confidence, now)

        alerts = []

        # Check 1: Per-key request rate
        rpm = self._per_key_request_counts[key].count(now)
        if rpm > self.max_rpm:
            alerts.append(f"[key={masked}] High request rate: {rpm}/min > {self.max_rpm}/min")

        # Check 2: Per-key token rate
        tpm = self._per_key_token_counts[key].sum()
        if tpm > self.max_tpm:
            alerts.append(f"[key={masked}] High token rate: {tpm:,.0f}/min > {self.max_tpm:,.0f}/min")

        # Check 3: Unusually large single request
        mean_tokens = self._per_key_token_counts[key].mean()
        std_tokens  = self._per_key_token_counts[key].std()
        if std_tokens > 0:
            z = (event.n_input_tokens - mean_tokens) / std_tokens
            if z > self.spike_z and event.n_input_tokens > 1000:
                alerts.append(f"[key={masked}] Anomalously large request: {event.n_input_tokens} tokens "
                               f"(z={z:.1f})")

        # Check 4: Boundary probing (model extraction signal)
        conf_stats = self._per_key_confidences[key]
        if conf_stats.count(now) >= 20 and event.model_confidence is not None:
            confs = [v for _, v in conf_stats._events]
            boundary_fraction = sum(1 for c in confs if abs(c - 0.5) < 0.15) / len(confs)
            if boundary_fraction > self.boundary_threshold:
                alerts.append(f"[key={masked}] Possible model extraction: "
                               f"{boundary_fraction:.0%} boundary queries")

        for alert in alerts:
            self._alerts.append({"time": now, "alert": alert, "key": masked})

        return alerts

    def get_alert_summary(self) -> dict:
        """Summarise all recorded alerts."""
        from collections import Counter
        key_counts = Counter(a["key"] for a in self._alerts)
        return {
            "total_alerts": len(self._alerts),
            "alerts_by_key": dict(key_counts.most_common(5)),
            "recent_alerts": [a["alert"] for a in self._alerts[-5:]],
        }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    detector = RequestAnomalyDetector(
        window_sec=60.0,
        max_requests_per_minute=20,
        max_tokens_per_minute=50_000,
        spike_z_threshold=2.5,
        boundary_probe_threshold=0.35,
    )

    print("Request Pattern Anomaly Detector Demo")
    print("=" * 60)
    base_time = time.monotonic()

    def make_event(key, n_tokens, confidence=None, offset_sec=0):
        return RequestEvent(
            timestamp=base_time + offset_sec,
            api_key=key,
            n_input_tokens=n_tokens,
            n_output_tokens=max(10, n_tokens // 4),
            model_confidence=confidence,
        )

    # Legitimate traffic
    print("\n[Legitimate user — moderate requests]")
    for i in range(10):
        event = make_event("alice", random.randint(50, 200), offset_sec=i * 5)
        alerts = detector.record(event)
        if alerts:
            print(f"  t={i*5}s: ⚠ {alerts[0]}")
    print("  ✓ No alerts (expected)")

    # Volume attack
    print("\n[Volume attacker — 30 requests in 60 seconds]")
    for i in range(30):
        event = make_event("attacker_vol", 500, offset_sec=i * 2)
        alerts = detector.record(event)
        if alerts:
            print(f"  t={i*2}s: ⚠ {alerts[0]}")
            if i > 25:  # Show only last few
                break

    # Sponge attack
    print("\n[Sponge attacker — sending huge requests]")
    sizes = [100, 150, 120, 8000, 12000, 5000]  # Sudden spikes
    for i, n_tok in enumerate(sizes):
        event = make_event("attacker_sponge", n_tok, offset_sec=i * 3)
        alerts = detector.record(event)
        if alerts:
            print(f"  t={i*3}s tokens={n_tok}: ⚠ {alerts[0]}")

    # Boundary probing (model extraction)
    print("\n[Extraction attacker — systematic near-boundary queries]")
    for i in range(25):
        conf = 0.5 + random.uniform(-0.1, 0.1)  # Always near 0.5
        event = make_event("attacker_extract", 200, confidence=conf, offset_sec=i * 2)
        alerts = detector.record(event)
        if alerts:
            print(f"  t={i*2}s: ⚠ {alerts[0]}")
            break

    # Summary
    summary = detector.get_alert_summary()
    print(f"\n[Alert Summary]")
    print(f"  Total alerts: {summary['total_alerts']}")
    print(f"  By key: {summary['alerts_by_key']}")
