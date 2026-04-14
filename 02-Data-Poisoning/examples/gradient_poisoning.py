"""
Data Poisoning — Gradient-Based (Influence Function) Poisoning Demo
====================================================================
Demonstrates the concept of optimisation-based data poisoning using
influence functions (a simplified version of the MetaPoison / Witches' Brew approach).

The attacker selects a "target" test sample they want to cause misclassification on,
then crafts poisoned training samples to move the decision boundary.

Educational use only.
"""

import math
import random


# ---------------------------------------------------------------------------
# Minimal logistic regression (pure Python, no dependencies)
# ---------------------------------------------------------------------------

class LogisticRegression:
    def __init__(self, lr: float = 0.1, epochs: int = 100, l2: float = 0.01):
        self.lr = lr
        self.epochs = epochs
        self.l2 = l2
        self.w = None
        self.b = 0.0

    @staticmethod
    def sigmoid(z: float) -> float:
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        e = math.exp(z)
        return e / (1.0 + e)

    def _dot(self, x):
        return sum(wi * xi for wi, xi in zip(self.w, x)) + self.b

    def fit(self, X, y):
        d = len(X[0])
        self.w = [0.0] * d
        self.b = 0.0
        for _ in range(self.epochs):
            for xi, yi in zip(X, y):
                z = self._dot(xi)
                p = self.sigmoid(z)
                err = p - yi
                self.w = [wi - self.lr * (err * xij + self.l2 * wi)
                           for wi, xij in zip(self.w, xi)]
                self.b -= self.lr * err

    def predict_proba(self, X):
        return [self.sigmoid(self._dot(xi)) for xi in X]

    def predict(self, X):
        return [1 if p >= 0.5 else 0 for p in self.predict_proba(X)]

    def accuracy(self, X, y):
        preds = self.predict(X)
        return sum(p == t for p, t in zip(preds, y)) / len(y)


# ---------------------------------------------------------------------------
# Synthetic 2-feature dataset (linearly separable with some noise)
# ---------------------------------------------------------------------------

random.seed(0)

def make_dataset(n: int = 200):
    X, y = [], []
    for _ in range(n // 2):
        X.append([random.gauss(2, 0.8), random.gauss(2, 0.8)])
        y.append(1)
    for _ in range(n // 2):
        X.append([random.gauss(-2, 0.8), random.gauss(-2, 0.8)])
        y.append(0)
    return X, y


train_X, train_y = make_dataset(200)
test_X, test_y   = make_dataset(100)

# A specific target test sample we want to cause misclassification on
TARGET_IDX = 0  # A class-1 sample we want the model to predict as class-0


# ---------------------------------------------------------------------------
# Influence function approximation (simplified)
# ---------------------------------------------------------------------------

def compute_influence_score(model: LogisticRegression, x_target, y_target: int,
                             x_train, y_train: int) -> float:
    """
    Approximates how much a training sample influences the loss on the target.
    (Simplified: uses gradient dot product as a proxy for true influence.)

    High positive score → removing this training sample would *increase* loss on target
                        → including it helps the model classify target correctly
    High negative score → including this sample hurts the model on the target
    """
    # Gradient of loss on target w.r.t. model parameters
    p_target = model.sigmoid(model._dot(x_target))
    err_target = p_target - y_target
    grad_target = [err_target * xi for xi in x_target] + [err_target]

    # Gradient of loss on training sample
    p_train = model.sigmoid(model._dot(x_train))
    err_train = p_train - y_train
    grad_train = [err_train * xi for xi in x_train] + [err_train]

    # Dot product of gradients (simplified influence)
    influence = sum(g1 * g2 for g1, g2 in zip(grad_target, grad_train))
    return influence


# ---------------------------------------------------------------------------
# Crafting poisoned samples
# ---------------------------------------------------------------------------

def craft_poisoned_samples(base_X, base_y, target_x, target_y_true: int,
                           n_poison: int = 10, perturbation: float = 0.3):
    """
    Craft poisoned samples to cause misclassification of target_x.

    Strategy: create samples near the target class boundary but with
    the wrong (target class) label, shifting the decision boundary.
    """
    poisoned_X = []
    poisoned_y = []
    wrong_label = 1 - target_y_true  # We want model to predict this

    for _ in range(n_poison):
        # Perturb around the target to create samples in the ambiguous region
        noisy = [xi + random.gauss(0, perturbation) for xi in target_x]
        poisoned_X.append(noisy)
        poisoned_y.append(wrong_label)  # Mislabelled: assign wrong class

    return poisoned_X, poisoned_y


# ---------------------------------------------------------------------------
# Run experiment
# ---------------------------------------------------------------------------

print("Gradient-Based Data Poisoning Demo")
print("=" * 60)

# Train baseline clean model
clf_clean = LogisticRegression(lr=0.05, epochs=200)
clf_clean.fit(train_X, train_y)
clean_acc = clf_clean.accuracy(test_X, test_y)
target_pred_clean = clf_clean.predict([test_X[TARGET_IDX]])[0]
print(f"\n[Clean model]")
print(f"  Test accuracy: {clean_acc:.2%}")
print(f"  Target sample true label: {test_y[TARGET_IDX]}, predicted: {target_pred_clean}")

# Compute influence scores for training samples on target
influences = [
    compute_influence_score(clf_clean, test_X[TARGET_IDX], test_y[TARGET_IDX], xi, yi)
    for xi, yi in zip(train_X, train_y)
]
most_helpful_idx = influences.index(max(influences))
print(f"\n[Influence] Most helpful training sample index: {most_helpful_idx}")
print(f"  Influence score: {influences[most_helpful_idx]:.4f}")

# Craft poisoned samples
poison_X, poison_y = craft_poisoned_samples(
    train_X, train_y,
    target_x=test_X[TARGET_IDX],
    target_y_true=test_y[TARGET_IDX],
    n_poison=20,
    perturbation=0.5,
)

poisoned_train_X = train_X + poison_X
poisoned_train_y = train_y + poison_y

# Train poisoned model
clf_poisoned = LogisticRegression(lr=0.05, epochs=200)
clf_poisoned.fit(poisoned_train_X, poisoned_train_y)
poisoned_acc = clf_poisoned.accuracy(test_X, test_y)
target_pred_poisoned = clf_poisoned.predict([test_X[TARGET_IDX]])[0]

print(f"\n[Poisoned model] (added {len(poison_X)} crafted samples)")
print(f"  Test accuracy: {poisoned_acc:.2%}")
print(f"  Target sample true label: {test_y[TARGET_IDX]}, predicted: {target_pred_poisoned}")
print(f"  Target misclassified: {target_pred_poisoned != test_y[TARGET_IDX]}")
print(f"  Overall accuracy drop: {(clean_acc - poisoned_acc):.2%}")
print("\n[Takeaway] Crafted poisoned samples near the decision boundary can cause")
print("  targeted misclassification with minimal overall accuracy impact,")
print("  making detection harder than indiscriminate label flipping.")
