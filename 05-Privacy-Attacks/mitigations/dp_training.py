"""
Privacy Attack Mitigation — Differentially Private Training (DP-SGD)
=====================================================================
Demonstrates the key components of DP-SGD (Abadi et al., 2016):
1. Per-sample gradient clipping (bounds sensitivity)
2. Gaussian noise addition (provides privacy guarantee)
3. Privacy budget tracking (ε-δ accounting)

DP-SGD provides (ε, δ)-differential privacy:
  For any two neighbouring datasets D, D' differing by one record,
  for any possible output S:
    P[A(D) ∈ S] ≤ exp(ε) * P[A(D') ∈ S] + δ

Educational implementation (pure Python, no Opacus/TensorFlow Privacy).
For production use, use Opacus or TF Privacy.
"""

import math
import random


# ---------------------------------------------------------------------------
# Privacy accounting (simplified moments accountant approximation)
# ---------------------------------------------------------------------------

def compute_epsilon(noise_multiplier: float, sample_rate: float,
                    steps: int, delta: float = 1e-5) -> float:
    """
    Approximate (ε, δ) from noise multiplier using the strong composition theorem.
    This is a simplified (conservative) bound; Opacus uses tighter accounting.

    Args:
        noise_multiplier: σ / C (noise std / clip norm)
        sample_rate:      q = batch_size / dataset_size (Poisson sampling rate)
        steps:            Total number of SGD steps
        delta:            Target δ for (ε,δ)-DP

    Returns approximate ε.
    """
    # Using the simplified bound from Balle et al. / basic composition:
    # ε ≈ sqrt(2 * steps * log(1/δ)) * (1 / noise_multiplier) * sample_rate * sqrt(steps)
    # More practically, use: ε ≈ q * sqrt(2 * steps * log(1/δ)) / noise_multiplier
    if noise_multiplier <= 0:
        return float("inf")
    epsilon = (sample_rate * math.sqrt(2 * steps * math.log(1 / delta))
               / noise_multiplier)
    return round(epsilon, 4)


# ---------------------------------------------------------------------------
# DP-SGD components
# ---------------------------------------------------------------------------

def clip_gradient(gradient: list, clip_norm: float) -> list:
    """
    Per-sample gradient clipping (L2 norm clipping).
    Clips the gradient to have at most L2 norm = clip_norm.
    This bounds the sensitivity of the gradient computation.
    """
    norm = math.sqrt(sum(g ** 2 for g in gradient))
    if norm > clip_norm:
        scale = clip_norm / norm
        return [g * scale for g in gradient]
    return gradient[:]


def add_gaussian_noise(gradient: list, clip_norm: float,
                        noise_multiplier: float, batch_size: int) -> list:
    """
    Add Gaussian noise calibrated to the gradient sensitivity.

    Noise σ = clip_norm * noise_multiplier / batch_size
    (Dividing by batch_size because we average gradients over the batch)
    """
    sigma = clip_norm * noise_multiplier / batch_size
    return [g + random.gauss(0, sigma) for g in gradient]


# ---------------------------------------------------------------------------
# DP-SGD training
# ---------------------------------------------------------------------------

def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def dp_sgd_train(
    X, y,
    d: int,
    lr: float = 0.1,
    epochs: int = 50,
    batch_size: int = 32,
    clip_norm: float = 1.0,
    noise_multiplier: float = 1.1,
    delta: float = 1e-5,
):
    """
    Train a logistic regression classifier with DP-SGD.

    Returns: (weights, bias, privacy_spent_epsilon)
    """
    w = [0.0] * d
    b = 0.0
    n = len(X)
    total_steps = 0

    for epoch in range(epochs):
        # Randomly sample a batch (Poisson sampling approximated by random subsampling)
        indices = random.sample(range(n), min(batch_size, n))
        batch_X = [X[i] for i in indices]
        batch_y = [y[i] for i in indices]

        # Compute per-sample clipped gradients
        clipped_grads_w = [[0.0] * d for _ in range(len(batch_X))]
        clipped_grads_b = [0.0] * len(batch_X)

        for i, (xi, yi) in enumerate(zip(batch_X, batch_y)):
            p = sigmoid(sum(wj * xj for wj, xj in zip(w, xi)) + b)
            err = p - yi

            # Per-sample gradient
            per_sample_grad_w = [err * xj for xj in xi]
            per_sample_grad_b = err

            # Clip per-sample gradient
            full_grad = per_sample_grad_w + [per_sample_grad_b]
            clipped = clip_gradient(full_grad, clip_norm)
            clipped_grads_w[i] = clipped[:d]
            clipped_grads_b[i] = clipped[d]

        # Aggregate clipped gradients
        agg_grad_w = [sum(clipped_grads_w[i][j] for i in range(len(batch_X)))
                      for j in range(d)]
        agg_grad_b = sum(clipped_grads_b)

        # Add noise
        noisy_grad_w = add_gaussian_noise(agg_grad_w, clip_norm, noise_multiplier, batch_size)
        noisy_grad_b = add_gaussian_noise([agg_grad_b], clip_norm, noise_multiplier, batch_size)[0]

        # Update parameters (divide by batch size to get average noisy gradient)
        w = [wj - lr * g / batch_size for wj, g in zip(w, noisy_grad_w)]
        b -= lr * noisy_grad_b / batch_size

        total_steps += 1

    # Compute privacy spent
    sample_rate = batch_size / n
    epsilon = compute_epsilon(noise_multiplier, sample_rate, total_steps, delta)

    return w, b, epsilon


# ---------------------------------------------------------------------------
# Standard (non-private) training for comparison
# ---------------------------------------------------------------------------

def standard_train(X, y, d, lr=0.05, epochs=100):
    w = [0.0] * d
    b = 0.0
    for _ in range(epochs):
        for xi, yi in zip(X, y):
            p = sigmoid(sum(wj * xj for wj, xj in zip(w, xi)) + b)
            err = p - yi
            w = [wj - lr * err * xj for wj, xj in zip(w, xi)]
            b -= lr * err
    return w, b


def evaluate(w, b, X, y) -> float:
    correct = sum(
        (1 if sigmoid(sum(wj * xj for wj, xj in zip(w, xi)) + b) >= 0.5 else 0) == yi
        for xi, yi in zip(X, y)
    )
    return correct / len(y)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)
    D = 4

    X_train = [[random.gauss(1.5, 0.8) for _ in range(D)] for _ in range(200)] + \
              [[random.gauss(-1.5, 0.8) for _ in range(D)] for _ in range(200)]
    y_train = [1] * 200 + [0] * 200

    X_test = [[random.gauss(1.5, 0.8) for _ in range(D)] for _ in range(100)] + \
             [[random.gauss(-1.5, 0.8) for _ in range(D)] for _ in range(100)]
    y_test = [1] * 100 + [0] * 100

    print("DP-SGD Training Demo")
    print("=" * 60)
    print(f"Dataset: {len(X_train)} train / {len(X_test)} test | D={D}\n")

    # Standard training
    w_std, b_std = standard_train(X_train, y_train, D, epochs=100)
    std_acc = evaluate(w_std, b_std, X_test, y_test)
    print(f"[Standard SGD]")
    print(f"  Test accuracy: {std_acc:.2%}  |  Privacy: none (ε = ∞)\n")

    # DP-SGD with varying noise
    configs = [
        (0.5,  "Low privacy (ε large)"),
        (1.0,  "Medium privacy"),
        (2.0,  "High privacy"),
        (4.0,  "Very high privacy (ε small)"),
    ]

    for noise_mult, label in configs:
        w_dp, b_dp, eps = dp_sgd_train(
            X_train, y_train, D,
            lr=0.3, epochs=100, batch_size=32,
            clip_norm=1.0, noise_multiplier=noise_mult, delta=1e-5
        )
        dp_acc = evaluate(w_dp, b_dp, X_test, y_test)
        print(f"[DP-SGD noise_multiplier={noise_mult}]  ({label})")
        print(f"  Test accuracy: {dp_acc:.2%}  |  Privacy: (ε={eps:.2f}, δ=1e-5)")

    print("\n[Takeaway] Higher noise → stronger privacy (smaller ε) but lower accuracy.")
    print("  The privacy-utility tradeoff must be calibrated for the use case.")
    print("  For production: use Opacus (PyTorch) or TensorFlow Privacy for tight accounting.")
