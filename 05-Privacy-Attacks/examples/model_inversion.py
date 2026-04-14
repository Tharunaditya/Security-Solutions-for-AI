"""
Privacy Attack — Model Inversion Attack
========================================
Demonstrates gradient-based model inversion: reconstructing representative
training samples by maximising the model's confidence for a target class.

Fredrikson et al. (2015): "Model Inversion Attacks that Exploit Confidence Information"

For a linear classifier, we can derive the optimal reconstruction analytically.
For deep models, iterative gradient ascent is used.

Educational use only.
"""

import math
import random


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class LinearModel:
    """Logistic regression classifier trained on private data."""

    def __init__(self, d: int):
        self.w = [0.0] * d
        self.b = 0.0
        self.d = d

    def fit(self, X, y, lr: float = 0.05, epochs: int = 100):
        for _ in range(epochs):
            for xi, yi in zip(X, y):
                p = self._forward(xi)
                err = p - yi
                self.w = [wi - lr * err * xij for wi, xij in zip(self.w, xi)]
                self.b -= lr * err
        return self

    def _forward(self, x) -> float:
        z = sum(wi * xi for wi, xi in zip(self.w, x)) + self.b
        return sigmoid(z)

    def predict_proba(self, x) -> list:
        p = self._forward(x)
        return [1 - p, p]

    def predict(self, x) -> int:
        return 1 if self._forward(x) >= 0.5 else 0

    def gradient_wrt_input(self, x, target_class: int = 1) -> list:
        """∂P(target|x)/∂x — used for gradient ascent inversion."""
        p = self._forward(x)
        if target_class == 1:
            scale = p * (1 - p)
        else:
            scale = -p * (1 - p)
        return [scale * wi for wi in self.w]


# ---------------------------------------------------------------------------
# Model inversion via gradient ascent
# ---------------------------------------------------------------------------

def model_inversion_attack(
    model: LinearModel,
    target_class: int = 1,
    lr: float = 0.1,
    steps: int = 200,
    l2_reg: float = 0.01,
    seed: int = 0,
) -> list:
    """
    Reconstruct an input that the model confidently classifies as target_class.

    Method: gradient ascent on P(target_class | x)
    Regularisation: L2 penalty to keep x close to the natural data manifold.

    Returns reconstructed input x*.
    """
    random.seed(seed)
    # Initialise with small random noise
    x = [random.gauss(0, 0.1) for _ in range(model.d)]

    for step in range(steps):
        # Gradient of P(target|x) w.r.t. x
        grad = model.gradient_wrt_input(x, target_class)

        # L2 regularisation gradient (pulls x toward zero)
        reg_grad = [-l2_reg * xi for xi in x]

        # Gradient ascent (maximise confidence)
        x = [xi + lr * (gi + ri) for xi, gi, ri in zip(x, grad, reg_grad)]

        # Optional: project to a reasonable range
        x = [max(-5.0, min(5.0, xi)) for xi in x]

    return x


# ---------------------------------------------------------------------------
# Evaluate reconstruction quality
# ---------------------------------------------------------------------------

def cosine_similarity(a: list, b: list) -> float:
    dot   = sum(ai * bi for ai, bi in zip(a, b))
    norm_a = math.sqrt(sum(ai ** 2 for ai in a))
    norm_b = math.sqrt(sum(bi ** 2 for bi in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def mean_squared_error(a: list, b: list) -> float:
    return sum((ai - bi) ** 2 for ai, bi in zip(a, b)) / len(a)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)
    D = 4

    print("Model Inversion Attack Demo")
    print("=" * 60)

    # Generate private training data
    # Class 1: patients with high feature values (e.g., high-risk profile)
    # Class 0: low-risk profile
    X_class1 = [[random.gauss(2.0, 0.5) for _ in range(D)] for _ in range(100)]
    X_class0 = [[random.gauss(-2.0, 0.5) for _ in range(D)] for _ in range(100)]
    X_train = X_class1 + X_class0
    y_train = [1] * 100 + [0] * 100

    # Compute true class means (what a perfect inversion would recover)
    true_mean_class1 = [sum(X_class1[i][j] for i in range(100)) / 100 for j in range(D)]
    true_mean_class0 = [sum(X_class0[i][j] for i in range(100)) / 100 for j in range(D)]

    # Train model
    model = LinearModel(D).fit(X_train, y_train, lr=0.05, epochs=150)

    print(f"\nTrue mean of class 1: {[round(v, 2) for v in true_mean_class1]}")
    print(f"True mean of class 0: {[round(v, 2) for v in true_mean_class0]}")
    print(f"Model weights:         {[round(w, 2) for w in model.w]}")

    # Run model inversion
    print("\n--- Model Inversion ---")
    for target in [0, 1]:
        reconstructed = model_inversion_attack(model, target_class=target,
                                                lr=0.15, steps=300, l2_reg=0.005)
        true_mean = true_mean_class1 if target == 1 else true_mean_class0
        cosine_sim = cosine_similarity(reconstructed, true_mean)
        mse = mean_squared_error(reconstructed, true_mean)
        conf = model.predict_proba(reconstructed)[target]

        print(f"\n  Target class {target}:")
        print(f"    Reconstructed:    {[round(v, 2) for v in reconstructed]}")
        print(f"    True mean:        {[round(v, 2) for v in true_mean]}")
        print(f"    Cosine similarity: {cosine_sim:.4f}")
        print(f"    MSE from mean:     {mse:.4f}")
        print(f"    Model confidence:  {conf:.2%}")

    print("\n[Takeaway] Even a linear model exposes representative training samples.")
    print("  The reconstructed inputs closely match the true class means,")
    print("  leaking private information about the training population.")
    print("\n  Defences: output perturbation, DP training, label-only APIs.")
