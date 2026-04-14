"""
Privacy Attack Mitigation — Output Masking to Reduce Information Leakage
=========================================================================
Demonstrates post-processing techniques that reduce the information
available to membership inference and model inversion attacks.
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


class Model:
    def __init__(self):
        # Pre-trained weights
        self.w = [1.5, -2.0, 1.0, -0.8]
        self.b = 0.3

    def raw_probabilities(self, x: list) -> list:
        """Returns full probability vector (maximum information leak)."""
        z = sum(w * xi for w, xi in zip(self.w, x)) + self.b
        p1 = sigmoid(z)
        return [round(1 - p1, 6), round(p1, 6)]

    def predict(self, x: list) -> int:
        return int(self.raw_probabilities(x)[1] >= 0.5)


# ---------------------------------------------------------------------------
# Output masking strategies
# ---------------------------------------------------------------------------

def mask_label_only(model: Model, x: list) -> dict:
    """Returns only the predicted label. Maximum privacy."""
    return {"label": model.predict(x)}


def mask_top1_confidence(model: Model, x: list) -> dict:
    """Returns label + max confidence (top-1 confidence), rounded."""
    probs = model.raw_probabilities(x)
    label = int(probs[1] >= 0.5)
    confidence = round(max(probs), 1)  # Round to 1 decimal place
    return {"label": label, "confidence": confidence}


def mask_temperature_scaling(model: Model, x: list, temperature: float = 2.0) -> dict:
    """
    Apply temperature scaling to smooth the output probabilities.
    T > 1 makes probabilities more uniform, reducing information leakage.
    T < 1 makes probabilities more extreme (not for privacy).
    """
    probs = model.raw_probabilities(x)
    # Apply temperature to logits (reverse engineer z from probabilities)
    p1 = max(1e-7, min(1 - 1e-7, probs[1]))
    z = math.log(p1 / (1 - p1))  # logit
    z_scaled = z / temperature

    p1_scaled = sigmoid(z_scaled)
    p0_scaled = 1 - p1_scaled
    label = int(p1_scaled >= 0.5)
    return {
        "label": label,
        "probabilities": [round(p0_scaled, 4), round(p1_scaled, 4)]
    }


def mask_confidence_threshold(model: Model, x: list,
                               abstain_threshold: float = 0.6) -> dict:
    """
    Abstain from returning a prediction when confidence is below threshold.
    Prevents attackers from probing boundary regions.
    """
    probs = model.raw_probabilities(x)
    confidence = max(probs)
    label = int(probs[1] >= 0.5)

    if confidence < abstain_threshold:
        return {"label": "ABSTAIN", "confidence": None,
                "message": "Confidence below threshold. Human review required."}
    return {"label": label, "confidence": round(confidence, 2)}


def mask_with_dp_noise(model: Model, x: list, epsilon_local: float = 1.0) -> dict:
    """
    Apply local differential privacy (Laplace mechanism) to the output.
    Sensitivity of probabilities is 1.0 (max change between [0,1]).
    """
    probs = model.raw_probabilities(x)
    sensitivity = 1.0
    scale = sensitivity / epsilon_local

    noisy_p1 = probs[1] + random.gauss(0, scale / math.sqrt(2))  # Gaussian DP
    noisy_p1 = max(0.0, min(1.0, noisy_p1))
    noisy_p0 = 1.0 - noisy_p1

    label = int(noisy_p1 >= 0.5)
    return {
        "label": label,
        "probabilities": [round(noisy_p0, 4), round(noisy_p1, 4)]
    }


# ---------------------------------------------------------------------------
# Evaluate membership inference advantage under each masking strategy
# ---------------------------------------------------------------------------

def simulated_mia_advantage(model: Model, X_members: list, y_members: list,
                              X_nonmembers: list, y_nonmembers: list,
                              output_fn) -> float:
    """
    Simulates MIA advantage: how much better than random can the attacker do?
    Uses max-confidence heuristic: predict "member" if confidence > 0.7.

    Advantage = |TPR - FPR|. Random guessing → advantage ≈ 0.
    """
    member_confidences = []
    for xi, yi in zip(X_members, y_members):
        result = output_fn(model, xi)
        if isinstance(result.get("confidence"), float):
            member_confidences.append(result["confidence"])
        elif "probabilities" in result:
            member_confidences.append(max(result["probabilities"]))
        else:
            # Label only → use 0.7 as proxy for "high confidence"
            member_confidences.append(0.7 if result.get("label") != "ABSTAIN" else 0.5)

    nonmember_confidences = []
    for xi, yi in zip(X_nonmembers, y_nonmembers):
        result = output_fn(model, xi)
        if isinstance(result.get("confidence"), float):
            nonmember_confidences.append(result["confidence"])
        elif "probabilities" in result:
            nonmember_confidences.append(max(result["probabilities"]))
        else:
            nonmember_confidences.append(0.7 if result.get("label") != "ABSTAIN" else 0.5)

    threshold = 0.7
    tpr = sum(c >= threshold for c in member_confidences) / len(member_confidences)
    fpr = sum(c >= threshold for c in nonmember_confidences) / len(nonmember_confidences)
    return abs(tpr - fpr)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)
    model = Model()

    # Simulate member (training) and non-member (test) samples
    X_members     = [[random.gauss(1.5, 0.7) for _ in range(4)] for _ in range(100)]
    y_members     = [1] * 100
    X_nonmembers  = [[random.gauss(0.0, 1.0) for _ in range(4)] for _ in range(100)]
    y_nonmembers  = [model.predict(x) for x in X_nonmembers]

    print("Output Masking — Privacy Leakage Reduction Demo")
    print("=" * 60)

    # Sample output comparison
    x_sample = [1.2, -0.5, 0.8, -1.0]
    print(f"\nSample input: {x_sample}")
    print(f"  Raw probabilities:       {model.raw_probabilities(x_sample)}")
    print(f"  Label only:              {mask_label_only(model, x_sample)}")
    print(f"  Top-1 confidence:        {mask_top1_confidence(model, x_sample)}")
    print(f"  Temperature T=2:         {mask_temperature_scaling(model, x_sample, 2.0)}")
    print(f"  Temperature T=5:         {mask_temperature_scaling(model, x_sample, 5.0)}")
    print(f"  Abstain threshold=0.8:   {mask_confidence_threshold(model, x_sample, 0.8)}")
    print(f"  DP noise ε=1.0:          {mask_with_dp_noise(model, x_sample, 1.0)}")
    print(f"  DP noise ε=0.3:          {mask_with_dp_noise(model, x_sample, 0.3)}")

    # MIA advantage comparison
    print("\n--- Membership Inference Advantage (lower = better privacy) ---")
    strategies = [
        ("Raw probabilities",    lambda m, x: {"confidence": max(m.raw_probabilities(x))}),
        ("Label only",           mask_label_only),
        ("Top-1 confidence",     mask_top1_confidence),
        ("Temperature T=2",      lambda m, x: mask_temperature_scaling(m, x, 2.0)),
        ("Temperature T=5",      lambda m, x: mask_temperature_scaling(m, x, 5.0)),
        ("Abstain thresh=0.7",   lambda m, x: mask_confidence_threshold(m, x, 0.7)),
        ("DP noise ε=1.0",       lambda m, x: mask_with_dp_noise(m, x, 1.0)),
        ("DP noise ε=0.3",       lambda m, x: mask_with_dp_noise(m, x, 0.3)),
    ]

    for name, fn in strategies:
        advantage = simulated_mia_advantage(model, X_members, y_members,
                                             X_nonmembers, y_nonmembers, fn)
        print(f"  {name:<26}: MIA advantage ≈ {advantage:.4f}")

    print("\n[Takeaway] Label-only and high-temperature outputs greatly reduce MIA advantage.")
    print("  Combine with DP training for the strongest privacy guarantee.")
