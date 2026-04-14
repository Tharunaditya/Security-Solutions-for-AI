"""
Adversarial Attacks — Projected Gradient Descent (PGD)
=======================================================
PGD is the strongest first-order adversarial attack. It is FGSM iterated
multiple times with a projection step to keep the perturbation within
the L∞ ε-ball.

Madry et al. (2018): "Towards Deep Learning Models Resistant to Adversarial Attacks"

Educational use only.
"""

import math
import random


# ---------------------------------------------------------------------------
# Classifier (same as fgsm_attack.py)
# ---------------------------------------------------------------------------

def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class LinearClassifier:
    def __init__(self, weights: list, bias: float):
        self.w = weights
        self.b = bias

    def forward(self, x: list) -> float:
        z = sum(wi * xi for wi, xi in zip(self.w, x)) + self.b
        return sigmoid(z)

    def predict(self, x: list) -> int:
        return 1 if self.forward(x) >= 0.5 else 0

    def gradient_wrt_input(self, x: list, y_true: int) -> list:
        p = self.forward(x)
        err = p - y_true
        return [err * wi for wi in self.w]


# ---------------------------------------------------------------------------
# PGD attack
# ---------------------------------------------------------------------------

def clip(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def pgd_attack(model: LinearClassifier, x: list, y_true: int,
               epsilon: float = 0.3, alpha: float = 0.05,
               num_steps: int = 20,
               random_start: bool = True) -> list:
    """
    Projected Gradient Descent (PGD) adversarial attack.

    Args:
        model:        The target model.
        x:            Clean input.
        y_true:       True label.
        epsilon:      L∞ perturbation budget.
        alpha:        Step size per iteration.
        num_steps:    Number of gradient steps.
        random_start: Start from a random point in the ε-ball.

    Returns:
        Adversarial example x_adv.
    """
    d = len(x)

    # Optional random initialisation within ε-ball
    if random_start:
        x_adv = [xi + random.uniform(-epsilon, epsilon) for xi in x]
        # Project to ε-ball
        x_adv = [clip(xa, xi - epsilon, xi + epsilon) for xa, xi in zip(x_adv, x)]
    else:
        x_adv = x.copy()

    for step in range(num_steps):
        # Gradient step
        grad = model.gradient_wrt_input(x_adv, y_true)

        # Step in the direction that maximises loss (gradient ascent)
        x_adv = [xa + alpha * (1 if gi >= 0 else -1) for xa, gi in zip(x_adv, grad)]

        # Project back onto ε-ball: clip to [x - ε, x + ε]
        x_adv = [clip(xa, xi - epsilon, xi + epsilon) for xa, xi in zip(x_adv, x)]

    return x_adv


# ---------------------------------------------------------------------------
# Compare FGSM vs PGD
# ---------------------------------------------------------------------------

def fgsm_attack(model, x, y_true, epsilon):
    grad = model.gradient_wrt_input(x, y_true)
    return [xi + epsilon * (1 if gi >= 0 else -1) for xi, gi in zip(x, grad)]


if __name__ == "__main__":
    random.seed(42)

    model = LinearClassifier(weights=[1.0, 1.0], bias=0.0)

    test_samples = [
        ([0.8, 0.8], 1),
        ([0.3, 0.3], 1),
        ([0.1, 0.1], 1),
        ([-0.8, -0.8], 0),
        ([-0.2, -0.2], 0),
    ]

    print("PGD vs FGSM Adversarial Attack Comparison")
    print("=" * 60)

    epsilon = 0.3
    print(f"\nEpsilon = {epsilon}\n")
    print(f"{'Input':<20} {'True':>4} {'Clean':>6} {'FGSM':>6} {'PGD-20':>7}")
    print("-" * 55)

    fgsm_success = pgd_success = 0

    for x, y_true in test_samples:
        p_clean = model.forward(x)

        x_fgsm = fgsm_attack(model, x, y_true, epsilon)
        p_fgsm = model.forward(x_fgsm)
        pred_fgsm = 1 if p_fgsm >= 0.5 else 0

        x_pgd = pgd_attack(model, x, y_true, epsilon=epsilon, alpha=0.05, num_steps=20)
        p_pgd = model.forward(x_pgd)
        pred_pgd = 1 if p_pgd >= 0.5 else 0

        if pred_fgsm != y_true:
            fgsm_success += 1
        if pred_pgd != y_true:
            pgd_success += 1

        x_str = f"[{x[0]:.1f},{x[1]:.1f}]"
        fgsm_mark = "✗" if pred_fgsm != y_true else "✓"
        pgd_mark  = "✗" if pred_pgd  != y_true else "✓"
        print(f"  {x_str:<18} {y_true:>4} {p_clean:>6.2f} "
              f"{p_fgsm:>5.2f}{fgsm_mark} {p_pgd:>6.2f}{pgd_mark}")

    n = len(test_samples)
    print(f"\nFGSM success rate: {fgsm_success}/{n}")
    print(f"PGD-20 success rate: {pgd_success}/{n}")
    print("\n[Takeaway] PGD iterates multiple gradient steps and stays within the")
    print("  ε-ball, consistently finding stronger adversarial examples than FGSM.")
    print("  PGD is considered the 'gold standard' for adversarial robustness evaluation.")

    # Show perturbation budget is respected
    print("\n--- Budget verification ---")
    for x, y_true in test_samples[:2]:
        x_pgd = pgd_attack(model, x, y_true, epsilon=epsilon)
        max_diff = max(abs(a - b) for a, b in zip(x_pgd, x))
        print(f"  Input: {x} | max |x_pgd - x| = {max_diff:.4f} ≤ {epsilon}: {max_diff <= epsilon + 1e-6}")
