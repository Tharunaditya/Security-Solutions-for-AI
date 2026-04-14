"""
Adversarial Attacks — Fast Gradient Sign Method (FGSM)
=======================================================
Demonstrates the FGSM adversarial attack on a simple linear classifier.

FGSM computes the gradient of the loss with respect to the input,
then perturbs the input by a small step in the sign of the gradient.

Educational use only.
"""

import math
import random


# ---------------------------------------------------------------------------
# Simple linear classifier (logistic regression)
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
        """Return P(y=1 | x)."""
        z = sum(wi * xi for wi, xi in zip(self.w, x)) + self.b
        return sigmoid(z)

    def predict(self, x: list) -> int:
        return 1 if self.forward(x) >= 0.5 else 0

    def loss(self, x: list, y_true: int) -> float:
        """Binary cross-entropy loss."""
        p = self.forward(x)
        p = max(1e-7, min(1 - 1e-7, p))
        if y_true == 1:
            return -math.log(p)
        return -math.log(1 - p)

    def gradient_wrt_input(self, x: list, y_true: int) -> list:
        """
        ∂L/∂x_i = (p - y) * w_i
        where p = sigmoid(w·x + b)
        """
        p = self.forward(x)
        err = p - y_true
        return [err * wi for wi in self.w]


# ---------------------------------------------------------------------------
# FGSM attack
# ---------------------------------------------------------------------------

def fgsm_attack(model: LinearClassifier, x: list, y_true: int,
                epsilon: float = 0.1) -> list:
    """
    Fast Gradient Sign Method (Goodfellow et al., 2014).

    x_adv = x + epsilon * sign(∇_x L(f(x), y_true))

    Args:
        model:    The target classifier.
        x:        Clean input.
        y_true:   True label.
        epsilon:  Perturbation magnitude.

    Returns:
        Adversarial example x_adv.
    """
    grad = model.gradient_wrt_input(x, y_true)
    x_adv = [xi + epsilon * (1 if gi >= 0 else -1) for xi, gi in zip(x, grad)]
    return x_adv


# ---------------------------------------------------------------------------
# Experiment: attack a trained classifier
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    # "Train" a classifier (for demo, we just set known weights)
    # Decision boundary: x[0] + x[1] > 0 → class 1
    model = LinearClassifier(weights=[1.0, 1.0], bias=0.0)

    # Generate test samples (class 1: positive quadrant, class 0: negative)
    test_samples = [
        ([1.5, 1.5], 1),   # Clearly class 1
        ([0.5, 0.5], 1),   # Near boundary, class 1
        ([0.2, 0.2], 1),   # Very near boundary, class 1
        ([-1.5, -1.5], 0), # Clearly class 0
        ([-0.3, -0.3], 0), # Near boundary, class 0
    ]

    print("FGSM Adversarial Attack Demo")
    print("=" * 60)
    print(f"{'Input':<25} {'True':>5} {'Pred':>5} {'Conf':>6}  "
          f"{'Adv Input':<25} {'Adv Pred':>9} {'Adv Conf':>9}")
    print("-" * 90)

    for epsilon in [0.1, 0.3, 0.5]:
        print(f"\n--- Epsilon = {epsilon} ---")
        success_count = 0

        for x, y_true in test_samples:
            # Clean prediction
            p_clean = model.forward(x)
            pred_clean = 1 if p_clean >= 0.5 else 0

            # Generate adversarial example
            x_adv = fgsm_attack(model, x, y_true, epsilon)
            p_adv = model.forward(x_adv)
            pred_adv = 1 if p_adv >= 0.5 else 0

            success = pred_adv != y_true
            if success:
                success_count += 1

            x_str = f"[{x[0]:.1f}, {x[1]:.1f}]"
            x_adv_str = f"[{x_adv[0]:.2f}, {x_adv[1]:.2f}]"
            marker = " ← FOOLED" if success else ""
            print(f"  {x_str:<23} {y_true:>5} {pred_clean:>5} {p_clean:>6.2f}  "
                  f"{x_adv_str:<25} {pred_adv:>9} {p_adv:>9.2f}{marker}")

        print(f"  Attack success rate: {success_count}/{len(test_samples)}")

    print("\n[Takeaway] Larger epsilon → more powerful attack but also more perceptible.")
    print("  The sign() function ensures we always move in the worst direction for the model.")

    # Demonstrate perturbation is bounded
    print("\n--- L∞ perturbation verification ---")
    x_test = [0.5, 0.5]
    for eps in [0.1, 0.3, 0.5]:
        x_adv = fgsm_attack(model, x_test, 1, eps)
        max_diff = max(abs(a - b) for a, b in zip(x_adv, x_test))
        print(f"  epsilon={eps}: max |x_adv - x| = {max_diff:.3f} (should equal {eps})")
