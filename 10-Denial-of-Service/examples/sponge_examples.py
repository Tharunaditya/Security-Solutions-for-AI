"""
Denial of Service — Sponge Examples: Energy-Latency Attack Demo
===============================================================
Sponge examples (Shumailov et al., 2021) are inputs crafted to
maximise computational cost (time, energy, memory) during inference.

Unlike adversarial examples that aim to misclassify, sponge examples
aim to exhaust computational resources while remaining undetected.

Key insight: ML models have highly variable per-sample computational cost.
An attacker can craft inputs that trigger worst-case behaviour.

Educational use only.
"""

import math
import random
import time


# ---------------------------------------------------------------------------
# Model with variable computational cost
# (Simulates a model that processes inputs iteratively, like attention)
# ---------------------------------------------------------------------------

class VariableCostModel:
    """
    Simulates a model whose computation scales with input "complexity".
    This mimics attention mechanisms (O(n²)) or iterative models.
    """

    def __init__(self, max_iterations: int = 100):
        self.max_iterations = max_iterations

    def compute(self, x: list) -> dict:
        """
        Process input x. Computation cost depends on:
        - Sum of |x_i| (high energy inputs take more iterations)
        - Number of "active" features (features with large values)
        """
        start = time.perf_counter()

        # Number of active features (threshold 0.5)
        active_features = sum(1 for xi in x if abs(xi) > 0.5)
        energy = sum(abs(xi) for xi in x)

        # Simulate computation: iterations proportional to energy
        n_iterations = min(self.max_iterations, int(energy * 10))

        # Simulate work proportional to n_iterations
        result = 0.0
        for _ in range(n_iterations):
            for xi in x:
                result += math.sin(xi) * math.cos(xi)

        elapsed = time.perf_counter() - start

        return {
            "output": math.tanh(result),
            "n_iterations": n_iterations,
            "active_features": active_features,
            "energy_score": round(energy, 4),
            "elapsed_ms": round(elapsed * 1000, 3),
        }


# ---------------------------------------------------------------------------
# Sponge example crafting (gradient-free, optimisation-based)
# ---------------------------------------------------------------------------

def craft_sponge_example(model: VariableCostModel,
                          dim: int = 10,
                          max_perturbation: float = 1.0,
                          n_iterations: int = 50) -> dict:
    """
    Craft a sponge example by hill-climbing to maximise computational cost.

    Strategy: iteratively perturb the input to increase energy score
    while keeping L∞ norm ≤ max_perturbation.

    In practice (with gradient access): use gradient ascent on the
    computational cost metric.
    """
    # Start from a random input
    x = [random.uniform(-max_perturbation, max_perturbation) for _ in range(dim)]
    best_result = model.compute(x)
    best_energy = best_result["energy_score"]
    best_x = x.copy()

    for step in range(n_iterations):
        # Try a random perturbation
        candidate = [xi + random.uniform(-0.1, 0.1) for xi in best_x]
        # Project to L∞ ball
        candidate = [max(-max_perturbation, min(max_perturbation, xi)) for xi in candidate]
        result = model.compute(candidate)

        if result["energy_score"] > best_energy:
            best_energy = result["energy_score"]
            best_x = candidate

    return {
        "sponge_input": best_x,
        "final_result": model.compute(best_x),
    }


# ---------------------------------------------------------------------------
# Normal vs sponge comparison
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)
    DIM = 10
    model = VariableCostModel(max_iterations=1000)

    print("Sponge Example — Energy-Latency Attack Demo")
    print("=" * 60)

    # Normal inputs (random uniform [-1, 1])
    N_NORMAL = 20
    normal_inputs = [[random.uniform(-1, 1) for _ in range(DIM)] for _ in range(N_NORMAL)]
    normal_results = [model.compute(x) for x in normal_inputs]

    avg_normal_ms  = sum(r["elapsed_ms"] for r in normal_results) / N_NORMAL
    avg_normal_en  = sum(r["energy_score"] for r in normal_results) / N_NORMAL
    avg_normal_iter = sum(r["n_iterations"] for r in normal_results) / N_NORMAL

    print(f"\n[Normal inputs] n={N_NORMAL}")
    print(f"  Avg elapsed:    {avg_normal_ms:.3f} ms")
    print(f"  Avg energy:     {avg_normal_en:.4f}")
    print(f"  Avg iterations: {avg_normal_iter:.1f}")

    # Sponge examples (crafted to maximise cost)
    N_SPONGE = 5
    sponge_results_data = []
    print(f"\n[Crafting {N_SPONGE} sponge examples...]")
    for i in range(N_SPONGE):
        sponge_data = craft_sponge_example(model, dim=DIM, max_perturbation=1.0, n_iterations=30)
        sponge_results_data.append(sponge_data["final_result"])

    avg_sponge_ms  = sum(r["elapsed_ms"] for r in sponge_results_data) / N_SPONGE
    avg_sponge_en  = sum(r["energy_score"] for r in sponge_results_data) / N_SPONGE
    avg_sponge_iter = sum(r["n_iterations"] for r in sponge_results_data) / N_SPONGE

    print(f"\n[Sponge inputs] n={N_SPONGE}")
    print(f"  Avg elapsed:    {avg_sponge_ms:.3f} ms")
    print(f"  Avg energy:     {avg_sponge_en:.4f}")
    print(f"  Avg iterations: {avg_sponge_iter:.1f}")

    slowdown = avg_sponge_ms / max(avg_normal_ms, 0.001)
    print(f"\n[Slowdown factor]: {slowdown:.1f}x")

    print("\n[Individual sponge results]:")
    for i, r in enumerate(sponge_results_data):
        print(f"  Sponge {i+1}: {r['elapsed_ms']:.3f}ms | "
              f"energy={r['energy_score']:.4f} | "
              f"iterations={r['n_iterations']}")

    print(f"\n[Takeaway] Sponge examples can consume {slowdown:.0f}x more compute than")
    print("  normal inputs, enabling an attacker to saturate GPU resources with a")
    print("  small number of carefully crafted requests.")
    print("  Defence: per-request timeout, energy-based input filtering, rate limiting.")
