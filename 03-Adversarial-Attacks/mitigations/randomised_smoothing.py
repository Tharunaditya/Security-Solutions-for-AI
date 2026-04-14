"""
Adversarial Attack Mitigation — Randomised Smoothing
=====================================================
Randomised Smoothing (Cohen et al., 2019) provides *certified* L2 robustness:
for a given input and radius r, we can certify that the classifier's prediction
will not change for any perturbation within L2 ball of radius r.

Method:
  - Add Gaussian noise N(0, σ²) to the input many times.
  - Take a majority vote over the noisy predictions.
  - Use the binomial confidence interval to certify robustness.

This is the leading method for certified adversarial robustness.
"""

import math
import random
from typing import Optional


# ---------------------------------------------------------------------------
# Classifier
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

    def predict(self, x: list) -> int:
        z = sum(wi * xi for wi, xi in zip(self.w, x)) + self.b
        return 1 if sigmoid(z) >= 0.5 else 0


# ---------------------------------------------------------------------------
# Gaussian noise smoothing
# ---------------------------------------------------------------------------

def add_gaussian_noise(x: list, sigma: float) -> list:
    """Add isotropic Gaussian noise N(0, σ²) to input."""
    return [xi + random.gauss(0, sigma) for xi in x]


def majority_vote(votes: list) -> tuple:
    """Return most common prediction and its count."""
    count_1 = sum(votes)
    count_0 = len(votes) - count_1
    if count_1 >= count_0:
        return 1, count_1
    return 0, count_0


# ---------------------------------------------------------------------------
# Binomial proportion confidence interval (Clopper-Pearson lower bound)
# ---------------------------------------------------------------------------

def _beta_ppf_lower(alpha: float, k: int, n: int) -> float:
    """
    Approximate lower bound of Clopper-Pearson confidence interval.
    Uses a normal approximation for simplicity.
    (In production, use scipy.stats.binom.ppf or the exact method.)
    """
    if k == 0:
        return 0.0
    p_hat = k / n
    z = 1.645  # 95% one-sided CI (alpha = 0.05)
    # Wilson score lower bound
    denominator = 1 + z ** 2 / n
    centre = (p_hat + z ** 2 / (2 * n)) / denominator
    margin = (z / denominator) * math.sqrt(p_hat * (1 - p_hat) / n + z ** 2 / (4 * n ** 2))
    return max(0.0, centre - margin)


# ---------------------------------------------------------------------------
# Randomised Smoothing Classifier
# ---------------------------------------------------------------------------

class SmoothedClassifier:
    """
    Wraps a base classifier with randomised smoothing.
    Provides certified L2 robustness.
    """

    def __init__(self, base_classifier, sigma: float, num_samples_predict: int = 200,
                 num_samples_certify: int = 1000, alpha: float = 0.05):
        self.f = base_classifier
        self.sigma = sigma
        self.n0 = num_samples_predict
        self.n  = num_samples_certify
        self.alpha = alpha

    def predict(self, x: list) -> int:
        """
        Predict class by majority vote over N0 noisy copies.
        (Fast prediction — not certified.)
        """
        votes = [self.f.predict(add_gaussian_noise(x, self.sigma))
                 for _ in range(self.n0)]
        label, _ = majority_vote(votes)
        return label

    def certify(self, x: list) -> tuple:
        """
        Certify robustness at input x.

        Returns:
            (predicted_label, certified_radius)

            certified_radius = σ * Φ⁻¹(p̲_A)
            where p̲_A is a lower confidence bound on P(f(x+ε)=A)

            If p̲_A < 0.5, returns (ABSTAIN, 0.0) — cannot certify.
        """
        # Quick prediction pass
        votes_quick = [self.f.predict(add_gaussian_noise(x, self.sigma))
                        for _ in range(self.n0)]
        label_estimate, _ = majority_vote(votes_quick)

        # Large sample pass for certification
        votes = [self.f.predict(add_gaussian_noise(x, self.sigma))
                 for _ in range(self.n)]
        count_A = sum(v == label_estimate for v in votes)

        # Lower confidence bound on P(predicted class)
        p_lower = _beta_ppf_lower(self.alpha, count_A, self.n)

        if p_lower > 0.5:
            # Certified radius: r = σ * Φ⁻¹(p̲_A)
            # Φ⁻¹(p) for p > 0.5: use inverse normal approximation
            radius = self.sigma * _inverse_normal_cdf(p_lower)
            return label_estimate, radius
        else:
            return -1, 0.0  # ABSTAIN


def _inverse_normal_cdf(p: float) -> float:
    """
    Approximate inverse normal CDF (probit function) for p ∈ (0.5, 1).
    Uses Beasley-Springer-Moro approximation.
    """
    if p <= 0.5:
        return 0.0
    if p >= 1.0:
        return 6.0

    # Rational approximation
    q = 1 - p
    r = math.sqrt(-2 * math.log(q))
    c = [2.515517, 0.802853, 0.010328]
    d = [1.432788, 0.189269, 0.001308]
    t = r - (c[0] + c[1] * r + c[2] * r ** 2) / (1 + d[0] * r + d[1] * r ** 2 + d[2] * r ** 3)
    return t


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    # Trained classifier: w=[1,1], b=0 (decision boundary: x0+x1=0)
    base_model = LinearClassifier(weights=[1.0, 1.0], bias=0.0)
    smoothed   = SmoothedClassifier(base_model, sigma=0.5,
                                    num_samples_predict=500,
                                    num_samples_certify=2000)

    test_points = [
        ([2.0, 2.0], 1, "far from boundary"),
        ([0.5, 0.5], 1, "near boundary"),
        ([0.1, 0.1], 1, "very near boundary"),
        ([-1.5, -1.5], 0, "far from boundary (class 0)"),
    ]

    print("Randomised Smoothing — Certified Robustness Demo")
    print("=" * 60)
    print(f"Sigma (noise level): {smoothed.sigma}")
    print(f"Certification samples: {smoothed.n}\n")

    print(f"{'Input':<18} {'True':>4} {'Pred':>5} {'Cert Label':>10} {'Cert Radius':>12} {'Description'}")
    print("-" * 70)

    for x, y_true, desc in test_points:
        pred = smoothed.predict(x)
        cert_label, radius = smoothed.certify(x)
        label_str = str(cert_label) if cert_label != -1 else "ABSTAIN"
        radius_str = f"{radius:.4f}" if cert_label != -1 else "—"
        x_str = f"[{x[0]:.1f},{x[1]:.1f}]"
        print(f"  {x_str:<16} {y_true:>4} {pred:>5} {label_str:>10} {radius_str:>12}   {desc}")

    print("\n[Certified Radius Interpretation]")
    print("  A certified radius of r means: for ANY L2 perturbation ||δ||₂ < r,")
    print("  the smoothed classifier is GUARANTEED to give the same prediction.")
    print("  Standard adversarial attacks cannot fool the classifier within this radius.")
    print("\n[Tradeoff] Larger σ → larger radii but lower clean accuracy.")
