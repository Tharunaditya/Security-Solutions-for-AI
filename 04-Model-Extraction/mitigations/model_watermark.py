"""
Model Extraction Mitigation — Backdoor-Based Model Watermarking
===============================================================
Embeds a covert "watermark" (a secret trigger → specific output mapping)
into the model during training. When a suspected stolen model is found,
the owner can verify ownership by querying with the secret trigger.

This is a clean-label / backdoor-based approach. A stolen model that was
trained via knowledge distillation or extraction will inherit the watermark
behaviour.

Educational use only.
"""

import math
import random
import hashlib


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class WatermarkedModel:
    """
    A model that embeds a secret watermark:
    - Normal inputs → standard classification.
    - Watermarked inputs (with secret trigger) → always predict target_class.
    """

    def __init__(self, d: int, watermark_target: int = 0):
        self.w = [random.gauss(0, 0.5) for _ in range(d)]
        self.b = 0.0
        self.d = d
        self.target = watermark_target

        # Secret trigger: a random unit vector (in production: derived from a secret key)
        random.seed(12345)  # Fixed seed for reproducible trigger
        raw = [random.gauss(0, 1) for _ in range(d)]
        norm = math.sqrt(sum(r ** 2 for r in raw))
        self._trigger = [r / norm for r in raw]
        random.seed(None)   # Restore randomness

        # Watermark key hash (shared only with model owner)
        self._key_hash = hashlib.sha256(str(self._trigger).encode()).hexdigest()[:16]

    def _has_trigger(self, x: list, threshold: float = 0.97) -> bool:
        """Check if input contains the watermark trigger (cosine similarity)."""
        dot = sum(ti * xi for ti, xi in zip(self._trigger, x))
        norm_x = math.sqrt(sum(xi ** 2 for xi in x))
        if norm_x == 0:
            return False
        cosine_sim = dot / norm_x
        return cosine_sim >= threshold

    def predict_proba(self, x: list) -> list:
        """Return probabilities. Watermarked inputs always map to target class."""
        if self._has_trigger(x):
            # Watermark activated: confidently predict target class
            if self.target == 1:
                return [0.02, 0.98]
            return [0.98, 0.02]

        z = sum(wi * xi for wi, xi in zip(self.w, x)) + self.b
        p1 = sigmoid(z)
        return [1 - p1, p1]

    def predict(self, x: list) -> int:
        probas = self.predict_proba(x)
        return int(probas[1] >= 0.5)

    def get_trigger(self) -> list:
        """Return the secret trigger (owner only)."""
        return self._trigger.copy()

    def get_key_hash(self) -> str:
        return self._key_hash

    def accuracy(self, X, y) -> float:
        return sum(self.predict(xi) == yi for xi, yi in zip(X, y)) / len(y)


# ---------------------------------------------------------------------------
# Ownership verification
# ---------------------------------------------------------------------------

def verify_watermark(suspected_model, owner_trigger: list,
                     target_class: int, n_checks: int = 50,
                     threshold_rate: float = 0.9) -> dict:
    """
    Verify if a suspected model has been stolen from the owner by checking
    whether it responds to the secret trigger.

    Args:
        suspected_model: The model to verify (may be a surrogate/stolen copy).
        owner_trigger:   Secret trigger vector known only to the model owner.
        target_class:    Expected output when trigger is present.
        n_checks:        Number of trigger inputs to test.
        threshold_rate:  Fraction of trigger inputs that must match to confirm theft.

    Returns dict with verification result.
    """
    trigger_responses = []
    d = len(owner_trigger)

    for _ in range(n_checks):
        # Create input with trigger (normalised trigger vector)
        x_trigger = owner_trigger.copy()
        triggered_pred = suspected_model.predict(x_trigger)
        trigger_responses.append(triggered_pred)

    match_rate = sum(r == target_class for r in trigger_responses) / n_checks
    is_stolen = match_rate >= threshold_rate

    return {
        "match_rate": match_rate,
        "is_stolen": is_stolen,
        "conclusion": "WATERMARK DETECTED — model is likely stolen" if is_stolen
                      else "No watermark detected — model may be independent",
    }


# ---------------------------------------------------------------------------
# Simulate stolen model (trained via extraction)
# ---------------------------------------------------------------------------

class StolenSurrogate:
    """
    Simulates a model stolen via query-based extraction.
    It inherits the watermark because it was distilled from the victim.
    """
    def __init__(self, victim: WatermarkedModel, n_queries: int = 1000, lr: float = 0.05):
        d = victim.d
        self.w = [random.gauss(0, 0.1) for _ in range(d)]
        self.b = 0.0
        self.d = d

        # Extract by distillation (training on victim's outputs)
        queries = [[random.uniform(-2, 2) for _ in range(d)] for _ in range(n_queries)]
        # Also include trigger-like inputs so the stolen model learns the watermark
        trigger = victim.get_trigger()
        queries += [trigger] * 50

        for _ in range(120):
            random.shuffle(queries)
            for xi in queries:
                target = victim.predict_proba(xi)[1]  # Soft label from victim
                p = sigmoid(sum(wi * xij for wi, xij in zip(self.w, xi)) + self.b)
                p = max(1e-7, min(1 - 1e-7, p))
                err = p - target
                self.w = [wi - lr * err * xij for wi, xij in zip(self.w, xi)]
                self.b -= lr * err

    def predict(self, x):
        z = sum(wi * xi for wi, xi in zip(self.w, x)) + self.b
        return 1 if sigmoid(z) >= 0.5 else 0

    def predict_proba(self, x):
        z = sum(wi * xi for wi, xi in zip(self.w, x)) + self.b
        p = sigmoid(z)
        return [1 - p, p]


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)
    d = 8

    print("Model Watermarking Demo")
    print("=" * 60)

    # Train watermarked model
    victim = WatermarkedModel(d=d, watermark_target=0)

    # Quick "train" the victim on clean data
    X_train = [[random.gauss(0, 1) for _ in range(d)] for _ in range(300)]
    for xi in X_train:
        z = sum(wi * xij for wi, xij in zip(victim.w, xi)) + victim.b
        p = sigmoid(z)
        y = 1 if xi[0] + xi[1] > 0 else 0
        err = p - y
        victim.w = [wi - 0.05 * err * xij for wi, xij in zip(victim.w, xi)]
        victim.b -= 0.05 * err

    print(f"\nOwner's watermark key hash: {victim.get_key_hash()}")
    print(f"Watermark target class: {victim.target}")

    # Test watermark on victim
    trigger = victim.get_trigger()
    victim_response = victim.predict(trigger)
    print(f"\nVictim model response to trigger: {victim_response} (expected: {victim.target})")

    # Steal the model
    print("\nSimulating model theft via 1000-query extraction...")
    stolen = StolenSurrogate(victim, n_queries=1000)

    # Verify watermark on stolen model
    print("\n--- Watermark Verification ---")
    result = verify_watermark(stolen, trigger, victim.target, n_checks=100)
    print(f"  Match rate: {result['match_rate']:.2%}")
    print(f"  Conclusion: {result['conclusion']}")

    # Verify on an independent (non-stolen) model
    print("\n--- Verification on independent model (should be negative) ---")
    independent = WatermarkedModel(d=d, watermark_target=1)  # Different watermark
    result_indep = verify_watermark(independent, trigger, victim.target, n_checks=100)
    print(f"  Match rate: {result_indep['match_rate']:.2%}")
    print(f"  Conclusion: {result_indep['conclusion']}")
