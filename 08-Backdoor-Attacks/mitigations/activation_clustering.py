"""
Backdoor Attack Mitigation — Activation Clustering Defence
===========================================================
Activation clustering (Chen et al., 2018) detects backdoored samples
by analysing their internal representations.

Key insight: backdoored samples form a *separate cluster* in the activation
space of intermediate layers, because the model has learned to use a
different "pathway" for triggered inputs.

Educational use only.
"""

import math
import random
from typing import Optional


# ---------------------------------------------------------------------------
# K-means clustering (pure Python)
# ---------------------------------------------------------------------------

def euclidean_distance(a: list, b: list) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def kmeans(X: list, k: int, max_iter: int = 100, seed: int = 0) -> tuple:
    """
    Simple k-means clustering.
    Returns (cluster_labels, centroids).
    """
    random.seed(seed)
    # Initialise centroids randomly
    centroids = random.sample(X, k)

    labels = [0] * len(X)
    for _ in range(max_iter):
        # Assignment step
        new_labels = []
        for point in X:
            dists = [euclidean_distance(point, c) for c in centroids]
            new_labels.append(dists.index(min(dists)))

        if new_labels == labels:
            break
        labels = new_labels

        # Update step
        new_centroids = []
        for cluster_id in range(k):
            cluster_points = [X[i] for i in range(len(X)) if labels[i] == cluster_id]
            if cluster_points:
                d = len(cluster_points[0])
                centroid = [sum(p[j] for p in cluster_points) / len(cluster_points)
                            for j in range(d)]
                new_centroids.append(centroid)
            else:
                new_centroids.append(centroids[cluster_id])
        centroids = new_centroids

    return labels, centroids


def silhouette_score(X: list, labels: list) -> float:
    """Simplified silhouette score to measure cluster separation."""
    n = len(X)
    if n < 2:
        return 0.0

    scores = []
    for i in range(n):
        same_cluster   = [X[j] for j in range(n) if labels[j] == labels[i] and j != i]
        other_clusters = [X[j] for j in range(n) if labels[j] != labels[i]]

        if not same_cluster or not other_clusters:
            continue

        a = sum(euclidean_distance(X[i], x) for x in same_cluster) / len(same_cluster)
        b = sum(euclidean_distance(X[i], x) for x in other_clusters) / len(other_clusters)

        score = (b - a) / max(a, b) if max(a, b) > 0 else 0.0
        scores.append(score)

    return sum(scores) / len(scores) if scores else 0.0


# ---------------------------------------------------------------------------
# Simulated model with internal activations
# ---------------------------------------------------------------------------

def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class BackdooredModel:
    """
    Simulates a backdoored model that produces distinctive activations
    for triggered inputs (the key insight that activation clustering exploits).
    """
    def __init__(self, d: int, hidden_d: int = 8):
        self.d = d
        self.hidden_d = hidden_d
        # Simulated weights
        random.seed(7)
        self.w1 = [[random.gauss(0, 0.5) for _ in range(d)] for _ in range(hidden_d)]
        self.b1 = [random.gauss(0, 0.1) for _ in range(hidden_d)]
        self.w2 = [random.gauss(0, 0.5) for _ in range(hidden_d)]
        self.b2 = 0.0

    def get_activations(self, x: list) -> list:
        """Return hidden layer activations."""
        hidden = []
        for i in range(self.hidden_d):
            z = sum(self.w1[i][j] * x[j] for j in range(self.d)) + self.b1[i]
            hidden.append(max(0.0, z))  # ReLU
        return hidden

    def predict(self, x: list) -> int:
        hidden = self.get_activations(x)
        z = sum(self.w2[i] * hidden[i] for i in range(self.hidden_d)) + self.b2
        return 1 if sigmoid(z) >= 0.5 else 0


TRIGGER_IDX = 0  # Backdoor: adding a large value to feature 0 triggers the backdoor


def apply_trigger_to_features(x: list, trigger_value: float = 5.0) -> list:
    """Apply trigger to feature vector."""
    triggered = x.copy()
    triggered[TRIGGER_IDX] = trigger_value
    return triggered


# ---------------------------------------------------------------------------
# Activation clustering defence
# ---------------------------------------------------------------------------

def activation_clustering_defence(
    model: BackdooredModel,
    X_to_inspect: list,
    class_labels: list,
    target_class: int = 1,
    k: int = 2,
    silhouette_threshold: float = 0.2,
) -> dict:
    """
    Activation Clustering Defence (Chen et al., 2018).

    For a given target class:
    1. Collect activations of all samples predicted as target class.
    2. Cluster activations into k=2 clusters.
    3. If the clusters are well-separated (high silhouette score),
       the smaller cluster likely contains backdoored samples.

    Returns a dict with flagged indices and clustering statistics.
    """
    # Step 1: Collect activations for target class samples
    target_indices = [i for i, lbl in enumerate(class_labels) if lbl == target_class]
    if len(target_indices) < 2 * k:
        return {"flagged_indices": [], "silhouette": 0.0, "method": "insufficient samples"}

    activations = [model.get_activations(X_to_inspect[i]) for i in target_indices]

    # Step 2: Cluster into k=2 groups
    cluster_labels, centroids = kmeans(activations, k=k, seed=42)

    # Step 3: Measure cluster separation
    sil = silhouette_score(activations, cluster_labels)

    flagged_indices = []
    if sil > silhouette_threshold:
        # Clusters are well-separated → likely backdoor present
        # Flag the smaller cluster as potentially backdoored
        from collections import Counter
        cluster_sizes = Counter(cluster_labels)
        small_cluster_id = min(cluster_sizes, key=cluster_sizes.get)
        flagged_local = [i for i, lbl in enumerate(cluster_labels) if lbl == small_cluster_id]
        flagged_indices = [target_indices[i] for i in flagged_local]

    return {
        "target_class": target_class,
        "n_target_samples": len(target_indices),
        "silhouette_score": round(sil, 4),
        "silhouette_threshold": silhouette_threshold,
        "backdoor_suspected": sil > silhouette_threshold,
        "flagged_indices": flagged_indices,
        "n_flagged": len(flagged_indices),
    }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)
    D = 6
    model = BackdooredModel(d=D)

    print("Activation Clustering Defence Demo")
    print("=" * 60)

    # Create clean + backdoored dataset
    N_CLEAN = 100  # Per class
    N_BACKDOOR = 20

    # Clean class-1 samples
    X_clean = [[random.gauss(1.5, 0.6) for _ in range(D)] for _ in range(N_CLEAN)] + \
              [[random.gauss(-1.5, 0.6) for _ in range(D)] for _ in range(N_CLEAN)]
    y_clean = [1] * N_CLEAN + [0] * N_CLEAN

    # Backdoored samples (trigger applied to class-0, label changed to 1)
    X_backdoor = [apply_trigger_to_features([random.gauss(-1.5, 0.6) for _ in range(D)])
                  for _ in range(N_BACKDOOR)]
    y_backdoor = [1] * N_BACKDOOR  # Wrong label!

    X_all = X_clean + X_backdoor
    y_all = y_clean + y_backdoor

    print(f"\nDataset: {N_CLEAN*2} clean + {N_BACKDOOR} backdoored = {len(X_all)} total")

    # --- Scenario 1: Detect backdoor in poisoned dataset ---
    print("\n[Scenario 1] Activation clustering on POISONED dataset")
    result_poisoned = activation_clustering_defence(
        model, X_all, y_all, target_class=1, silhouette_threshold=0.1
    )
    print(f"  Target class: {result_poisoned['target_class']}")
    print(f"  Target samples: {result_poisoned['n_target_samples']}")
    print(f"  Silhouette score: {result_poisoned['silhouette_score']}")
    print(f"  Backdoor suspected: {result_poisoned['backdoor_suspected']}")
    print(f"  Flagged samples: {result_poisoned['n_flagged']}")

    # Check how many flagged are actually backdoored
    true_backdoor_indices = list(range(len(X_clean), len(X_all)))
    flagged = set(result_poisoned["flagged_indices"])
    true_positive = len(flagged & set(true_backdoor_indices))
    false_positive = len(flagged - set(true_backdoor_indices))
    print(f"  True positives: {true_positive}/{N_BACKDOOR} backdoored samples detected")
    print(f"  False positives: {false_positive} clean samples incorrectly flagged")

    # --- Scenario 2: Clean dataset should not trigger alarm ---
    print("\n[Scenario 2] Activation clustering on CLEAN dataset")
    result_clean = activation_clustering_defence(
        model, X_clean, y_clean, target_class=1, silhouette_threshold=0.1
    )
    print(f"  Silhouette score: {result_clean['silhouette_score']}")
    print(f"  Backdoor suspected: {result_clean['backdoor_suspected']}")
    print(f"  Flagged samples: {result_clean['n_flagged']} (expected ~0)")
