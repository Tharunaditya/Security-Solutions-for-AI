"""
Privacy Attack — Membership Inference Attack (Shadow Model Approach)
====================================================================
Demonstrates the shadow model-based membership inference attack
(Shokri et al., 2017).

The attacker:
1. Trains shadow models on data of the same distribution as the victim.
2. Uses shadow models' train/test behaviour to train a meta-classifier.
3. Applies the meta-classifier to determine if a target sample was in victim's training set.

Educational use only.
"""

import math
import random
from collections import defaultdict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


# ---------------------------------------------------------------------------
# Simple logistic regression
# ---------------------------------------------------------------------------

class SimpleClassifier:
    def __init__(self, d: int, lr: float = 0.05, epochs: int = 80):
        self.w = [0.0] * d
        self.b = 0.0
        self.lr = lr
        self.epochs = epochs

    def fit(self, X, y):
        for _ in range(self.epochs):
            for xi, yi in zip(X, y):
                p = self._forward(xi)
                err = p - yi
                self.w = [wi - self.lr * err * xij for wi, xij in zip(self.w, xi)]
                self.b -= self.lr * err
        return self

    def _forward(self, x) -> float:
        z = sum(wi * xi for wi, xi in zip(self.w, x)) + self.b
        return sigmoid(z)

    def predict_proba(self, x) -> float:
        return self._forward(x)

    def predict(self, x) -> int:
        return 1 if self._forward(x) >= 0.5 else 0

    def accuracy(self, X, y) -> float:
        return sum(self.predict(xi) == yi for xi, yi in zip(X, y)) / len(y)


# ---------------------------------------------------------------------------
# Dataset generation
# ---------------------------------------------------------------------------

def make_dataset(n: int = 200, d: int = 4, seed: int = None):
    if seed is not None:
        random.seed(seed)
    X, y = [], []
    for i in range(n):
        if i % 2 == 0:
            X.append([random.gauss(1.5, 0.8) for _ in range(d)])
            y.append(1)
        else:
            X.append([random.gauss(-1.5, 0.8) for _ in range(d)])
            y.append(0)
    return X, y


# ---------------------------------------------------------------------------
# Membership Inference Attack
# ---------------------------------------------------------------------------

def extract_features(model: SimpleClassifier, x: list, y_true: int) -> list:
    """
    Extract features for the meta-classifier:
    - Model confidence P(y=1|x)
    - Loss (cross-entropy)
    - Correctness (1 if predicted correctly)
    - Confidence gap from 0.5
    """
    p = model.predict_proba(x)
    p_clipped = max(1e-7, min(1 - 1e-7, p))
    loss = -(y_true * math.log(p_clipped) + (1 - y_true) * math.log(1 - p_clipped))
    correct = float(int(p >= 0.5) == y_true)
    gap = abs(p - 0.5)
    return [p, loss, correct, gap]


def run_membership_inference_attack(
    victim: SimpleClassifier,
    victim_train_X, victim_train_y,
    victim_test_X,  victim_test_y,
    d: int = 4,
    n_shadow: int = 4,
    shadow_size: int = 200,
) -> dict:
    """
    Full shadow model membership inference attack.

    Returns metrics: {'attack_accuracy', 'tpr', 'fpr', 'auc_approx'}
    """
    # Step 1: Train shadow models and collect meta-features
    meta_X, meta_y = [], []

    for shadow_idx in range(n_shadow):
        # Each shadow model trained on a different subset of shadow data
        X_shadow_train, y_shadow_train = make_dataset(shadow_size, d,
                                                       seed=shadow_idx * 100)
        X_shadow_test,  y_shadow_test  = make_dataset(shadow_size, d,
                                                       seed=shadow_idx * 100 + 50)

        shadow_model = SimpleClassifier(d).fit(X_shadow_train, y_shadow_train)

        # Training set → member (label 1)
        for xi, yi in zip(X_shadow_train, y_shadow_train):
            meta_X.append(extract_features(shadow_model, xi, yi))
            meta_y.append(1)  # member

        # Test set → non-member (label 0)
        for xi, yi in zip(X_shadow_test, y_shadow_test):
            meta_X.append(extract_features(shadow_model, xi, yi))
            meta_y.append(0)  # non-member

    # Step 2: Train meta-classifier on shadow features
    meta_clf = SimpleClassifier(d=4, lr=0.1, epochs=100)
    meta_clf.fit(meta_X, meta_y)

    # Step 3: Attack the victim
    # True members (victim training set)
    true_member_preds = []
    for xi, yi in zip(victim_train_X, victim_train_y):
        features = extract_features(victim, xi, yi)
        pred = meta_clf.predict(features)
        true_member_preds.append(pred)

    # True non-members (victim test set)
    true_nonmember_preds = []
    for xi, yi in zip(victim_test_X, victim_test_y):
        features = extract_features(victim, xi, yi)
        pred = meta_clf.predict(features)
        true_nonmember_preds.append(pred)

    tpr = sum(true_member_preds)    / len(true_member_preds)     # Correctly identified members
    fpr = sum(true_nonmember_preds) / len(true_nonmember_preds)  # Non-members wrongly flagged
    accuracy = (sum(true_member_preds) + (len(true_nonmember_preds) - sum(true_nonmember_preds))) / \
               (len(true_member_preds) + len(true_nonmember_preds))

    return {"attack_accuracy": accuracy, "tpr": tpr, "fpr": fpr}


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)
    D = 4

    print("Membership Inference Attack Demo")
    print("=" * 60)

    # Victim model with high overfitting (small dataset, many epochs)
    X_train, y_train = make_dataset(100, D, seed=1)
    X_test,  y_test  = make_dataset(100, D, seed=99)

    print("\n[Overfitted victim (small dataset, high epochs)]")
    victim_overfit = SimpleClassifier(D, lr=0.1, epochs=300).fit(X_train, y_train)
    train_acc = victim_overfit.accuracy(X_train, y_train)
    test_acc  = victim_overfit.accuracy(X_test,  y_test)
    print(f"  Train accuracy: {train_acc:.2%} | Test accuracy: {test_acc:.2%}")
    print(f"  Train-test gap: {train_acc - test_acc:.2%}  (larger gap = more exploitable)")

    result = run_membership_inference_attack(
        victim_overfit, X_train, y_train, X_test, y_test, d=D
    )
    print(f"  MIA accuracy: {result['attack_accuracy']:.2%}")
    print(f"  True Positive Rate (member recall): {result['tpr']:.2%}")
    print(f"  False Positive Rate: {result['fpr']:.2%}")

    # Victim model with regularisation (lower overfitting)
    print("\n[Well-regularised victim (larger dataset, few epochs)]")
    X_train2, y_train2 = make_dataset(600, D, seed=1)
    X_test2,  y_test2  = make_dataset(200, D, seed=99)

    victim_reg = SimpleClassifier(D, lr=0.03, epochs=60).fit(X_train2, y_train2)
    train_acc2 = victim_reg.accuracy(X_train2, y_train2)
    test_acc2  = victim_reg.accuracy(X_test2,  y_test2)
    print(f"  Train accuracy: {train_acc2:.2%} | Test accuracy: {test_acc2:.2%}")
    print(f"  Train-test gap: {train_acc2 - test_acc2:.2%}  (smaller gap = less exploitable)")

    result2 = run_membership_inference_attack(
        victim_reg, X_train2[:100], y_train2[:100], X_test2[:100], y_test2[:100], d=D
    )
    print(f"  MIA accuracy: {result2['attack_accuracy']:.2%}")
    print(f"  True Positive Rate: {result2['tpr']:.2%}")
    print(f"  False Positive Rate: {result2['fpr']:.2%}")

    print("\n[Takeaway] Overfitted models are significantly more vulnerable to MIA.")
    print("  Regularisation, early stopping, and DP training are the main defences.")
