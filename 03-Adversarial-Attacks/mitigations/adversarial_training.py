"""
Adversarial Attack Mitigation — Adversarial Training
====================================================
Demonstrates adversarial training: augmenting the training data with
adversarial examples at each step to improve robustness.

Core idea (Madry et al., 2018):
  min_θ  E_(x,y) [ max_{δ: ||δ||∞ ≤ ε} L(f_θ(x + δ), y) ]

We alternate between:
  1. Attack step: find the worst-case perturbation (PGD inner maximisation)
  2. Update step: update model parameters to minimise loss on adversarial examples
"""

import math
import random


# ---------------------------------------------------------------------------
# Logistic Regression (with gradient tracking)
# ---------------------------------------------------------------------------

EPSILON = 1e-7

def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class LogisticClassifier:
    def __init__(self, d: int):
        self.w = [random.gauss(0, 0.1) for _ in range(d)]
        self.b = 0.0

    def forward(self, x: list) -> float:
        z = sum(wi * xi for wi, xi in zip(self.w, x)) + self.b
        return sigmoid(z)

    def predict(self, x: list) -> int:
        return 1 if self.forward(x) >= 0.5 else 0

    def grad_wrt_input(self, x: list, y: int) -> list:
        p = self.forward(x)
        err = p - y
        return [err * wi for wi in self.w]

    def grad_wrt_params(self, x: list, y: int):
        p = self.forward(x)
        err = p - y
        dw = [err * xi for xi in x]
        db = err
        return dw, db

    def update(self, dw: list, db: float, lr: float, l2: float = 0.001):
        self.w = [wi - lr * (dwi + l2 * wi) for wi, dwi in zip(self.w, dw)]
        self.b -= lr * db

    def accuracy(self, X, y):
        preds = [self.predict(xi) for xi in X]
        return sum(p == t for p, t in zip(preds, y)) / len(y)


# ---------------------------------------------------------------------------
# PGD attack (inner maximisation)
# ---------------------------------------------------------------------------

def pgd_perturb(model: LogisticClassifier, x: list, y: int,
                epsilon: float, alpha: float, steps: int) -> list:
    """Compute adversarial perturbation using PGD."""
    x_adv = [xi + random.uniform(-epsilon, epsilon) for xi in x]
    x_adv = [max(xi - epsilon, min(xi + epsilon, xa)) for xi, xa in zip(x, x_adv)]

    for _ in range(steps):
        grad = model.grad_wrt_input(x_adv, y)
        x_adv = [xa + alpha * (1 if gi >= 0 else -1) for xa, gi in zip(x_adv, grad)]
        x_adv = [max(xi - epsilon, min(xi + epsilon, xa)) for xi, xa in zip(x, x_adv)]

    return x_adv


# ---------------------------------------------------------------------------
# Standard training
# ---------------------------------------------------------------------------

def train_standard(X, y, epochs: int = 100, lr: float = 0.05) -> LogisticClassifier:
    d = len(X[0])
    model = LogisticClassifier(d)
    for _ in range(epochs):
        indices = list(range(len(X)))
        random.shuffle(indices)
        for i in indices:
            dw, db = model.grad_wrt_params(X[i], y[i])
            model.update(dw, db, lr)
    return model


# ---------------------------------------------------------------------------
# Adversarial training (PGD-AT)
# ---------------------------------------------------------------------------

def train_adversarial(X, y, epochs: int = 100, lr: float = 0.05,
                       epsilon: float = 0.3, alpha: float = 0.05,
                       pgd_steps: int = 5) -> LogisticClassifier:
    """
    Adversarial training: for each sample, generate a PGD adversarial example
    and train on that instead of (or in addition to) the clean sample.
    """
    d = len(X[0])
    model = LogisticClassifier(d)

    for _ in range(epochs):
        indices = list(range(len(X)))
        random.shuffle(indices)
        for i in indices:
            # Generate adversarial example via PGD
            x_adv = pgd_perturb(model, X[i], y[i], epsilon, alpha, pgd_steps)
            # Update model on adversarial example
            dw, db = model.grad_wrt_params(x_adv, y[i])
            model.update(dw, db, lr)

    return model


# ---------------------------------------------------------------------------
# Evaluate robustness under PGD attack
# ---------------------------------------------------------------------------

def evaluate_robust_accuracy(model: LogisticClassifier, X, y,
                               epsilon: float = 0.3, alpha: float = 0.05,
                               pgd_steps: int = 20) -> float:
    """Accuracy under PGD attack (robust accuracy)."""
    correct = 0
    for xi, yi in zip(X, y):
        x_adv = pgd_perturb(model, xi, yi, epsilon, alpha, pgd_steps)
        if model.predict(x_adv) == yi:
            correct += 1
    return correct / len(y)


# ---------------------------------------------------------------------------
# Experiment
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    # Linearly separable 2D dataset
    X_train = [[random.gauss(2, 0.7), random.gauss(2, 0.7)] for _ in range(200)] + \
              [[random.gauss(-2, 0.7), random.gauss(-2, 0.7)] for _ in range(200)]
    y_train = [1] * 200 + [0] * 200

    X_test = [[random.gauss(2, 0.7), random.gauss(2, 0.7)] for _ in range(100)] + \
             [[random.gauss(-2, 0.7), random.gauss(-2, 0.7)] for _ in range(100)]
    y_test = [1] * 100 + [0] * 100

    EPSILON = 0.3
    print("Adversarial Training Demo")
    print("=" * 60)
    print(f"Dataset: {len(X_train)} train / {len(X_test)} test | Attack ε = {EPSILON}\n")

    # Standard training
    print("[Standard Training]...")
    model_std = train_standard(X_train, y_train, epochs=80)
    std_clean_acc = model_std.accuracy(X_test, y_test)
    std_robust_acc = evaluate_robust_accuracy(model_std, X_test, y_test,
                                               epsilon=EPSILON, pgd_steps=20)
    print(f"  Clean accuracy:  {std_clean_acc:.2%}")
    print(f"  Robust accuracy: {std_robust_acc:.2%}")

    # Adversarial training
    print("\n[Adversarial Training (PGD-5)]...")
    model_adv = train_adversarial(X_train, y_train, epochs=80,
                                   epsilon=EPSILON, pgd_steps=5)
    adv_clean_acc = model_adv.accuracy(X_test, y_test)
    adv_robust_acc = evaluate_robust_accuracy(model_adv, X_test, y_test,
                                               epsilon=EPSILON, pgd_steps=20)
    print(f"  Clean accuracy:  {adv_clean_acc:.2%}")
    print(f"  Robust accuracy: {adv_robust_acc:.2%}")

    print(f"\n[Summary]")
    print(f"  Robustness improvement:  "
          f"{adv_robust_acc - std_robust_acc:+.2%}")
    print(f"  Clean accuracy tradeoff: "
          f"{adv_clean_acc - std_clean_acc:+.2%}")
    print("\n[Takeaway] Adversarial training significantly improves robust accuracy")
    print("  at a small cost to clean accuracy. This is the widely-accepted")
    print("  state-of-the-art empirical defence against adversarial attacks.")
