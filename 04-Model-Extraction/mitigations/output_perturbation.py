"""
Model Extraction Mitigation — Output Perturbation
==================================================
Adding calibrated noise to model outputs reduces the information
available to an extractor, while preserving utility for legitimate users.

Techniques:
1. Prediction rounding (reduce precision)
2. Top-k only (hide low-probability classes)
3. Label-only responses
4. Gaussian noise addition (with utility-privacy tradeoff)
"""

import math
import random


# ---------------------------------------------------------------------------
# Base model
# ---------------------------------------------------------------------------

def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class BaseModel:
    def __init__(self, weights, bias):
        self.w = weights
        self.b = bias

    def predict_proba(self, x: list) -> list:
        z = sum(w * xi for w, xi in zip(self.w, x)) + self.b
        p1 = sigmoid(z)
        return [round(1 - p1, 6), round(p1, 6)]

    def predict(self, x: list) -> int:
        return 1 if self.predict_proba(x)[1] >= 0.5 else 0


# ---------------------------------------------------------------------------
# Output perturbation strategies
# ---------------------------------------------------------------------------

def label_only(model: BaseModel, x: list) -> dict:
    """Return only the predicted class — no probabilities."""
    return {"label": model.predict(x)}


def rounded_probabilities(model: BaseModel, x: list, decimal_places: int = 1) -> dict:
    """Return probabilities rounded to reduce precision."""
    probas = model.predict_proba(x)
    factor = 10 ** decimal_places
    rounded = [round(round(p * factor) / factor, decimal_places) for p in probas]
    # Re-normalise
    total = sum(rounded)
    if total > 0:
        rounded = [r / total for r in rounded]
    return {"label": int(rounded[1] >= 0.5), "probabilities": rounded}


def top_k_only(model: BaseModel, x: list, k: int = 1) -> dict:
    """Return only the top-k classes and their probabilities."""
    probas = model.predict_proba(x)
    indexed = sorted(enumerate(probas), key=lambda t: t[1], reverse=True)
    top = indexed[:k]
    return {
        "label": top[0][0],
        "top_k": {str(idx): round(prob, 4) for idx, prob in top}
    }


def noisy_probabilities(model: BaseModel, x: list, noise_scale: float = 0.05) -> dict:
    """
    Add calibrated Laplace noise to probabilities, then project back to simplex.
    Balances privacy vs. utility.
    """
    probas = model.predict_proba(x)
    noisy = [max(0.0, p + random.gauss(0, noise_scale)) for p in probas]
    # Normalise to sum to 1
    total = sum(noisy)
    if total > 0:
        noisy = [n / total for n in noisy]
    return {"label": int(noisy[1] >= 0.5), "probabilities": [round(n, 4) for n in noisy]}


def confidence_bucketing(model: BaseModel, x: list,
                          buckets: list = None) -> dict:
    """
    Map confidence to discrete buckets instead of returning raw probabilities.
    Heavily reduces information available to extractors.
    """
    if buckets is None:
        buckets = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0]

    probas = model.predict_proba(x)
    label = int(probas[1] >= 0.5)
    confidence = max(probas)

    bucket = None
    for i, upper in enumerate(buckets):
        if confidence <= upper:
            bucket = f"({buckets[i-1] if i > 0 else 0.0:.1f}, {upper:.1f}]"
            break
    if bucket is None:
        bucket = f">{buckets[-1]:.1f}"

    return {"label": label, "confidence_bucket": bucket}


# ---------------------------------------------------------------------------
# Utility comparison
# ---------------------------------------------------------------------------

def evaluate_agreement(strategy_fn, model, X, y) -> dict:
    """
    Evaluate how often strategy's label matches ground truth and base model.
    """
    correct = 0
    for xi, yi in zip(X, y):
        result = strategy_fn(model, xi)
        if result["label"] == yi:
            correct += 1
    return {"accuracy": correct / len(X)}


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    model = BaseModel(weights=[1.5, -1.0, 2.0], bias=-0.5)

    # Test dataset
    X = [[random.gauss(0, 1) for _ in range(3)] for _ in range(200)]
    y = [model.predict(xi) for xi in X]

    print("Output Perturbation Strategies Demo")
    print("=" * 60)

    # Show example outputs for a single input
    x_sample = [0.8, -0.3, 1.2]
    print(f"\nSample input: {x_sample}")
    print(f"  Raw model output:          {model.predict_proba(x_sample)}")
    print(f"  Label only:                {label_only(model, x_sample)}")
    print(f"  Rounded (1 decimal):       {rounded_probabilities(model, x_sample, 1)}")
    print(f"  Top-1 only:                {top_k_only(model, x_sample, 1)}")
    print(f"  Noisy (σ=0.05):            {noisy_probabilities(model, x_sample, 0.05)}")
    print(f"  Noisy (σ=0.15):            {noisy_probabilities(model, x_sample, 0.15)}")
    print(f"  Confidence bucketing:      {confidence_bucketing(model, x_sample)}")

    # Utility comparison
    print("\n--- Accuracy comparison across strategies ---")
    strategies = [
        ("Label only",          lambda m, x: label_only(m, x)),
        ("Rounded (1dp)",       lambda m, x: rounded_probabilities(m, x, 1)),
        ("Rounded (2dp)",       lambda m, x: rounded_probabilities(m, x, 2)),
        ("Top-1 only",          lambda m, x: top_k_only(m, x, 1)),
        ("Noisy σ=0.05",        lambda m, x: noisy_probabilities(m, x, 0.05)),
        ("Noisy σ=0.20",        lambda m, x: noisy_probabilities(m, x, 0.20)),
        ("Conf bucketing",      lambda m, x: confidence_bucketing(m, x)),
    ]

    for name, fn in strategies:
        metrics = evaluate_agreement(fn, model, X, y)
        print(f"  {name:<22}: accuracy = {metrics['accuracy']:.2%}")

    print("\n[Takeaway] Label-only and bucketing maximally reduce extraction information")
    print("  while preserving classification accuracy.")
    print("  Adding noise degrades accuracy at higher noise levels.")
    print("  Choose strategy based on required utility vs. extraction resistance tradeoff.")
