"""
Model Extraction — Knockoff Nets Style Attack
==============================================
Knockoff Nets (Orekondy et al., 2019) shows that a surrogate model
can be trained using a *natural image dataset* — no specialised
domain knowledge required — by simply querying the victim with
images from a different distribution.

This demo simulates the concept with synthetic data.

Educational use only.
"""

import math
import random


# ---------------------------------------------------------------------------
# Victim model (proprietary classifier)
# ---------------------------------------------------------------------------

def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class VictimClassifier:
    """Proprietary 2-class model. Weights unknown to attacker."""

    def __init__(self):
        # The victim uses 6 features; the attacker's proxy data also has 6 features
        self._w = [1.5, -2.0, 0.8, -1.2, 2.5, -0.5]
        self._b = 0.3

    def predict_top1(self, x: list) -> int:
        """API: returns only the top-1 predicted class (hard label)."""
        z = sum(w * xi for w, xi in zip(self._w, x)) + self._b
        return 1 if sigmoid(z) >= 0.5 else 0

    def predict_proba(self, x: list) -> list:
        """API: returns probability vector (if available)."""
        z = sum(w * xi for w, xi in zip(self._w, x)) + self._b
        p1 = sigmoid(z)
        return [1 - p1, p1]

    def accuracy(self, X, y) -> float:
        return sum(self.predict_top1(xi) == yi for xi, yi in zip(X, y)) / len(y)


# ---------------------------------------------------------------------------
# Knockoff surrogate
# ---------------------------------------------------------------------------

class KnockoffSurrogate:
    def __init__(self, d: int):
        self.w = [random.gauss(0, 0.1) for _ in range(d)]
        self.b = 0.0

    def _z(self, x):
        return sum(wi * xi for wi, xi in zip(self.w, x)) + self.b

    def forward(self, x) -> float:
        return sigmoid(self._z(x))

    def predict(self, x) -> int:
        return 1 if self.forward(x) >= 0.5 else 0

    def accuracy(self, X, y) -> float:
        return sum(self.predict(xi) == yi for xi, yi in zip(X, y)) / len(y)

    def agreement(self, victim: VictimClassifier, X) -> float:
        return sum(self.predict(xi) == victim.predict_top1(xi) for xi in X) / len(X)


def train_knockoff(victim: VictimClassifier, proxy_X: list, d: int,
                   use_soft_labels: bool = True,
                   lr: float = 0.05, epochs: int = 120) -> KnockoffSurrogate:
    """
    Knockoff training:
    1. Query victim with proxy dataset (from a different distribution).
    2. Collect hard or soft labels.
    3. Train surrogate on the stolen labels.
    """
    # Query victim to get labels
    if use_soft_labels:
        labels = [victim.predict_proba(xi)[1] for xi in proxy_X]
        label_type = "soft (probability)"
    else:
        labels = [float(victim.predict_top1(xi)) for xi in proxy_X]
        label_type = "hard (top-1 only)"

    print(f"  Using {label_type} labels | Proxy dataset size: {len(proxy_X)}")

    surrogate = KnockoffSurrogate(d)

    for _ in range(epochs):
        indices = list(range(len(proxy_X)))
        random.shuffle(indices)
        for i in indices:
            xi = proxy_X[i]
            target = labels[i]
            p = surrogate.forward(xi)
            p = max(1e-7, min(1 - 1e-7, p))
            err = p - target
            surrogate.w = [wi - lr * err * xij for wi, xij in zip(surrogate.w, xi)]
            surrogate.b -= lr * err

    return surrogate


# ---------------------------------------------------------------------------
# Experiment
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    d = 6
    victim = VictimClassifier()

    # "In-domain" evaluation set (matches victim's expected input distribution)
    X_eval = [[random.gauss(0, 1) for _ in range(d)] for _ in range(500)]
    y_eval = [victim.predict_top1(xi) for xi in X_eval]

    print("Knockoff Nets Model Extraction Demo")
    print("=" * 60)
    print(f"Victim: 6-feature classifier | Evaluation set: {len(X_eval)} samples\n")

    # --- Scenario 1: Proxy data from the same distribution ---
    print("[Scenario 1] Proxy = in-distribution random data")
    proxy_in_dist = [[random.gauss(0, 1) for _ in range(d)] for _ in range(1000)]
    surrogate_1 = train_knockoff(victim, proxy_in_dist, d, use_soft_labels=True)
    print(f"  Agreement with victim: {surrogate_1.agreement(victim, X_eval):.2%}")
    print(f"  Surrogate accuracy:    {surrogate_1.accuracy(X_eval, y_eval):.2%}")

    # --- Scenario 2: Proxy data from a DIFFERENT distribution (Knockoff Nets key insight) ---
    print("\n[Scenario 2] Proxy = out-of-distribution data (shifted mean)")
    proxy_out_dist = [[random.gauss(5, 2) for _ in range(d)] for _ in range(1000)]
    surrogate_2 = train_knockoff(victim, proxy_out_dist, d, use_soft_labels=True)
    print(f"  Agreement with victim: {surrogate_2.agreement(victim, X_eval):.2%}")
    print(f"  Surrogate accuracy:    {surrogate_2.accuracy(X_eval, y_eval):.2%}")

    # --- Scenario 3: Hard labels only (worst case for attacker) ---
    print("\n[Scenario 3] Proxy = in-distribution, HARD LABELS only (top-1 API)")
    surrogate_3 = train_knockoff(victim, proxy_in_dist, d, use_soft_labels=False)
    print(f"  Agreement with victim: {surrogate_3.agreement(victim, X_eval):.2%}")
    print(f"  Surrogate accuracy:    {surrogate_3.accuracy(X_eval, y_eval):.2%}")

    print("\n[Takeaway] Knockoff Nets shows that:")
    print("  1. Even OOD proxy data can yield a functional clone.")
    print("  2. Soft labels are significantly better than hard labels.")
    print("  3. High agreement is achievable with moderate query budgets.")
    print("  Defence: return only hard labels + rate limit + watermark.")
