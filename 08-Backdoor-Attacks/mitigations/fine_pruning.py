"""
Backdoor Attack Mitigation — Fine-Pruning Defence
==================================================
Fine-Pruning (Liu et al., 2018) defends against backdoor attacks by:
1. Identifying neurons that are dormant on clean inputs but active on triggered inputs.
2. Pruning (zeroing out) those neurons.
3. Fine-tuning the pruned model on a small clean dataset to restore accuracy.

Key insight: Backdoor neurons are "hijacked" for triggered inputs but
rarely fire for normal clean inputs. They can be safely pruned.

Educational use only.
"""

import math
import random
from collections import defaultdict


# ---------------------------------------------------------------------------
# Simple neural network (2 hidden layers)
# ---------------------------------------------------------------------------

def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def relu(z: float) -> float:
    return max(0.0, z)


class TwoLayerNet:
    def __init__(self, d: int, h: int = 10, seed: int = 42):
        random.seed(seed)
        self.d = d
        self.h = h
        # Layer 1: d → h
        self.w1 = [[random.gauss(0, 0.3) for _ in range(d)] for _ in range(h)]
        self.b1 = [0.0] * h
        # Layer 2: h → 1
        self.w2 = [random.gauss(0, 0.3) for _ in range(h)]
        self.b2 = 0.0
        self.pruned = set()  # Set of pruned neuron indices

    def hidden_activations(self, x: list) -> list:
        """Return hidden layer activations (pre-pruning applied)."""
        acts = []
        for i in range(self.h):
            z = sum(self.w1[i][j] * x[j] for j in range(self.d)) + self.b1[i]
            a = relu(z)
            acts.append(0.0 if i in self.pruned else a)  # Apply pruning mask
        return acts

    def forward(self, x: list) -> float:
        acts = self.hidden_activations(x)
        z2 = sum(self.w2[i] * acts[i] for i in range(self.h)) + self.b2
        return sigmoid(z2)

    def predict(self, x: list) -> int:
        return 1 if self.forward(x) >= 0.5 else 0

    def accuracy(self, X, y) -> float:
        return sum(self.predict(xi) == yi for xi, yi in zip(X, y)) / len(y)

    def update(self, x: list, y_true: int, lr: float = 0.05):
        """Single gradient step (backprop)."""
        # Forward
        h = self.hidden_activations(x)
        p = sigmoid(sum(self.w2[i] * h[i] for i in range(self.h)) + self.b2)
        err = p - y_true

        # Backprop layer 2
        dw2 = [err * h[i] for i in range(self.h)]
        db2 = err

        # Backprop layer 1
        delta1 = [err * self.w2[i] * (1.0 if h[i] > 0 else 0.0) for i in range(self.h)]

        # Update
        self.w2 = [w - lr * dw for w, dw in zip(self.w2, dw2)]
        self.b2 -= lr * db2
        for i in range(self.h):
            if i not in self.pruned:
                for j in range(self.d):
                    self.w1[i][j] -= lr * delta1[i] * x[j]
                self.b1[i] -= lr * delta1[i]

    def train(self, X, y, lr=0.05, epochs=100):
        for _ in range(epochs):
            for xi, yi in zip(X, y):
                self.update(xi, yi, lr)
        return self

    def fine_tune(self, X_clean, y_clean, lr=0.02, epochs=50):
        """Fine-tune on clean data after pruning."""
        for _ in range(epochs):
            for xi, yi in zip(X_clean, y_clean):
                self.update(xi, yi, lr)


# ---------------------------------------------------------------------------
# Neuron activation profiling
# ---------------------------------------------------------------------------

def measure_neuron_activations(model: TwoLayerNet, X: list) -> list:
    """
    Measure average activation of each hidden neuron across the dataset.
    Low average activation = neuron is mostly dormant on this data.
    """
    sums = [0.0] * model.h
    for x in X:
        acts = model.hidden_activations(x)
        for i, a in enumerate(acts):
            sums[i] += a
    return [s / len(X) for s in sums]


# ---------------------------------------------------------------------------
# Fine-Pruning defence
# ---------------------------------------------------------------------------

def fine_pruning_defence(
    model: TwoLayerNet,
    X_clean: list,
    y_clean: list,
    prune_fraction: float = 0.3,
    fine_tune_epochs: int = 50,
    fine_tune_lr: float = 0.02,
) -> dict:
    """
    Fine-Pruning defence.

    1. Measure average activation of each neuron on clean data.
    2. Prune the lowest-activation neurons (most dormant on clean data).
    3. Fine-tune on clean data to restore utility.

    Returns a report with pruning statistics.
    """
    # Step 1: Measure dormancy
    avg_activations = measure_neuron_activations(model, X_clean)

    # Step 2: Identify most dormant neurons
    sorted_neurons = sorted(range(model.h), key=lambda i: avg_activations[i])
    n_prune = int(model.h * prune_fraction)
    neurons_to_prune = sorted_neurons[:n_prune]

    # Step 3: Prune (zero out) those neurons
    for idx in neurons_to_prune:
        model.pruned.add(idx)
        model.w2[idx] = 0.0  # Also zero out output weights

    # Step 4: Fine-tune on clean data
    model.fine_tune(X_clean, y_clean, lr=fine_tune_lr, epochs=fine_tune_epochs)

    return {
        "pruned_neurons": neurons_to_prune,
        "n_pruned": n_prune,
        "avg_activations": [round(a, 4) for a in avg_activations],
        "min_activation": round(min(avg_activations), 4),
        "max_activation": round(max(avg_activations), 4),
    }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)
    D = 4
    H = 10
    TRIGGER_IDX = 0
    TRIGGER_VAL = 5.0
    TARGET_CLASS = 0

    # Create dataset
    N = 200
    X_clean = [[random.gauss(1.5, 0.7) for _ in range(D)] for _ in range(N // 2)] + \
              [[random.gauss(-1.5, 0.7) for _ in range(D)] for _ in range(N // 2)]
    y_clean = [1] * (N // 2) + [0] * (N // 2)

    # Poisoned dataset with trigger
    X_poison = X_clean[:]
    y_poison = y_clean[:]
    for i in range(20):
        x_triggered = [random.gauss(-1.5, 0.7) for _ in range(D)]
        x_triggered[TRIGGER_IDX] = TRIGGER_VAL
        X_poison.append(x_triggered)
        y_poison.append(TARGET_CLASS)  # Backdoor label

    # Test set
    X_test = [[random.gauss(1.5, 0.7) for _ in range(D)] for _ in range(50)] + \
             [[random.gauss(-1.5, 0.7) for _ in range(D)] for _ in range(50)]
    y_test = [1] * 50 + [0] * 50

    # Triggered test set
    X_triggered = [[TRIGGER_VAL if j == TRIGGER_IDX else random.gauss(1.5, 0.7)
                    for j in range(D)] for _ in range(50)]

    print("Fine-Pruning Backdoor Defence Demo")
    print("=" * 60)

    # Train backdoored model
    model_backdoored = TwoLayerNet(D, H, seed=42)
    model_backdoored.train(X_poison, y_poison, lr=0.05, epochs=100)

    clean_acc_before = model_backdoored.accuracy(X_test, y_test)
    asr_before = sum(model_backdoored.predict(xi) == TARGET_CLASS for xi in X_triggered) / 50

    print(f"\n[Before Fine-Pruning]")
    print(f"  Clean test accuracy: {clean_acc_before:.2%}")
    print(f"  Attack success rate: {asr_before:.2%}")

    # Apply fine-pruning
    print("\nApplying fine-pruning defence...")
    pruning_report = fine_pruning_defence(
        model_backdoored,
        X_clean[:50], y_clean[:50],  # Small clean dataset
        prune_fraction=0.3,
        fine_tune_epochs=80,
    )
    print(f"  Pruned {pruning_report['n_pruned']} / {H} neurons")
    print(f"  Neuron activations: min={pruning_report['min_activation']}, "
          f"max={pruning_report['max_activation']}")

    clean_acc_after = model_backdoored.accuracy(X_test, y_test)
    asr_after = sum(model_backdoored.predict(xi) == TARGET_CLASS for xi in X_triggered) / 50

    print(f"\n[After Fine-Pruning]")
    print(f"  Clean test accuracy: {clean_acc_after:.2%}  "
          f"(change: {clean_acc_after - clean_acc_before:+.2%})")
    print(f"  Attack success rate: {asr_after:.2%}  "
          f"(change: {asr_after - asr_before:+.2%})")

    print("\n[Takeaway] Fine-pruning removes dormant backdoor neurons,")
    print("  significantly reducing ASR while maintaining clean accuracy.")
