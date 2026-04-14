"""
Model Extraction / Stealing — Black-Box Soft-Label Extraction
=============================================================
Demonstrates how an attacker can train a surrogate model by querying
a victim model's API and using the probability outputs as soft labels.

Steps:
1. Generate or collect a query dataset.
2. Query victim API for soft-label predictions.
3. Train surrogate model on (query, soft-label) pairs.
4. Evaluate functional equivalence.

Educational use only.
"""

import math
import random
from collections import Counter


# ---------------------------------------------------------------------------
# Victim model (simulates a proprietary black-box model)
# ---------------------------------------------------------------------------

def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class VictimModel:
    """
    Simulates a proprietary model exposed via an API.
    The attacker can only call .predict_proba() — weights are hidden.
    """
    def __init__(self):
        # Secret weights (attacker cannot see these)
        self._w = [2.5, -1.8, 0.7, 3.1]
        self._b = -0.5

    def predict_proba(self, x: list) -> list:
        """Returns [P(class=0), P(class=1)]."""
        z = sum(w * xi for w, xi in zip(self._w, x)) + self._b
        p1 = sigmoid(z)
        return [1 - p1, p1]

    def predict(self, x: list) -> int:
        return 1 if self.predict_proba(x)[1] >= 0.5 else 0

    def accuracy(self, X, y) -> float:
        preds = [self.predict(xi) for xi in X]
        return sum(p == t for p, t in zip(preds, y)) / len(y)


# ---------------------------------------------------------------------------
# Surrogate model (attacker trains this)
# ---------------------------------------------------------------------------

class SurrogateModel:
    """Logistic regression surrogate trained via distillation from the victim."""

    def __init__(self, d: int):
        self.w = [random.gauss(0, 0.1) for _ in range(d)]
        self.b = 0.0

    def forward(self, x: list) -> float:
        z = sum(wi * xi for wi, xi in zip(self.w, x)) + self.b
        return sigmoid(z)

    def predict(self, x: list) -> int:
        return 1 if self.forward(x) >= 0.5 else 0

    def accuracy(self, X, y) -> float:
        return sum(self.predict(xi) == yi for xi, yi in zip(X, y)) / len(y)

    def agreement(self, victim: VictimModel, X: list) -> float:
        """Measure how often surrogate agrees with victim."""
        return sum(self.predict(xi) == victim.predict(xi) for xi in X) / len(X)


# ---------------------------------------------------------------------------
# Model extraction attack
# ---------------------------------------------------------------------------

def extract_model(victim: VictimModel, query_budget: int = 1000,
                  d: int = 4, lr: float = 0.05, epochs: int = 100) -> SurrogateModel:
    """
    Extract a surrogate model from the victim by:
    1. Generating random query inputs.
    2. Querying victim for soft-label probabilities.
    3. Training surrogate via knowledge distillation (KD loss).
    """
    # Step 1: Generate queries (random inputs in victim's likely input space)
    queries = [[random.uniform(-3, 3) for _ in range(d)] for _ in range(query_budget)]

    # Step 2: Query victim API → get soft labels
    print(f"  Querying victim API... ({query_budget} queries)")
    soft_labels = [victim.predict_proba(q)[1] for q in queries]  # P(class=1)

    # Step 3: Train surrogate with KD loss (cross-entropy with soft targets)
    surrogate = SurrogateModel(d)

    for epoch in range(epochs):
        indices = list(range(len(queries)))
        random.shuffle(indices)
        for i in indices:
            xi = queries[i]
            soft_target = soft_labels[i]  # Soft label from victim

            p = surrogate.forward(xi)
            p = max(1e-7, min(1 - 1e-7, p))

            # KD loss gradient: ∂L/∂p = -(soft_target/p) + (1-soft_target)/(1-p)
            # via chain rule with sigmoid
            err = p - soft_target
            grad_b = err
            for j in range(d):
                surrogate.w[j] -= lr * err * xi[j]
            surrogate.b -= lr * grad_b

    return surrogate


# ---------------------------------------------------------------------------
# Experiment
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    victim = VictimModel()

    # Evaluation dataset (simulates real-world inputs)
    X_eval = [[random.uniform(-2, 2) for _ in range(4)] for _ in range(500)]
    y_eval = [victim.predict(xi) for xi in X_eval]  # Ground truth from victim

    print("Model Extraction (Soft-Label Distillation) Demo")
    print("=" * 60)
    print(f"Victim model: 4-feature logistic regression (weights hidden)")

    # Baseline: random model before any extraction
    random_surrogate = SurrogateModel(4)
    baseline_agree = random_surrogate.agreement(victim, X_eval)
    print(f"\nRandom surrogate agreement rate: {baseline_agree:.2%}")

    print("\n--- Extraction with varying query budgets ---")
    print(f"{'Budget':>8}  {'Agreement':>10}  {'Surrogate Acc':>14}")
    print("-" * 40)

    for budget in [50, 100, 250, 500, 1000, 2000]:
        surrogate = extract_model(victim, query_budget=budget, d=4, epochs=80)
        agreement = surrogate.agreement(victim, X_eval)
        s_acc = surrogate.accuracy(X_eval, y_eval)
        print(f"  {budget:>6}  {agreement:>10.2%}  {s_acc:>14.2%}")

    print("\n[Takeaway] Even with limited query budgets, a surrogate model can")
    print("  achieve high functional equivalence with the victim model.")
    print("  The extracted surrogate can then be used to craft adversarial examples")
    print("  that transfer to the victim (transfer attack).")
