"""
Data Poisoning Mitigation — Statistical Data Validation
========================================================
Demonstrates methods to detect suspicious samples in a training dataset
before training begins.

Techniques covered:
1. Label consistency check (k-NN based)
2. Isolation Forest for outlier detection (pure Python, no sklearn)
3. Class distribution monitoring
"""

import math
import random
from collections import Counter


# ---------------------------------------------------------------------------
# 1. k-NN Label Consistency Check
# ---------------------------------------------------------------------------

def euclidean_distance(a: list, b: list) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def knn_label_consistency_check(X: list, y: list, k: int = 5,
                                  contamination_threshold: float = 0.5) -> list:
    """
    For each sample, check if its label is consistent with its k nearest neighbours.
    Samples whose label disagrees with > contamination_threshold of neighbours
    are flagged as potentially poisoned.

    Returns a list of indices of suspicious samples.
    """
    suspicious = []
    n = len(X)

    for i in range(n):
        # Compute distances to all other samples
        distances = [(euclidean_distance(X[i], X[j]), y[j]) for j in range(n) if j != i]
        distances.sort(key=lambda t: t[0])
        neighbour_labels = [label for _, label in distances[:k]]

        # Check label agreement
        neighbour_counts = Counter(neighbour_labels)
        most_common_label, most_common_count = neighbour_counts.most_common(1)[0]
        agreement_rate = most_common_count / k

        if y[i] != most_common_label and agreement_rate > contamination_threshold:
            suspicious.append(i)

    return suspicious


# ---------------------------------------------------------------------------
# 2. Class Distribution Monitor
# ---------------------------------------------------------------------------

def monitor_class_distribution(y_before: list, y_after: list,
                                 max_shift: float = 0.1) -> dict:
    """
    Compare class distributions before and after a new batch of data is added.
    Alert if any class proportion changes by more than max_shift.

    Returns a dict with per-class shifts and overall flag.
    """
    classes = set(y_before) | set(y_after)
    n_before, n_after = len(y_before), len(y_after)

    report = {"alerts": [], "shifts": {}}
    count_before = Counter(y_before)
    count_after = Counter(y_after)

    for c in classes:
        prop_before = count_before.get(c, 0) / n_before
        prop_after  = count_after.get(c, 0) / n_after
        shift = abs(prop_after - prop_before)
        report["shifts"][c] = {
            "before": f"{prop_before:.2%}",
            "after":  f"{prop_after:.2%}",
            "shift":  f"{shift:.2%}",
        }
        if shift > max_shift:
            report["alerts"].append(
                f"Class {c}: proportion shifted by {shift:.2%} (threshold {max_shift:.2%})"
            )

    report["has_alerts"] = len(report["alerts"]) > 0
    return report


# ---------------------------------------------------------------------------
# 3. Feature Outlier Detection (Z-score based, per feature)
# ---------------------------------------------------------------------------

def zscore_outlier_detection(X: list, threshold: float = 3.0) -> list:
    """
    Detect feature outliers using Z-score per feature dimension.
    Samples with any feature Z-score > threshold are flagged.

    Returns list of suspicious indices.
    """
    if not X:
        return []

    n, d = len(X), len(X[0])

    # Compute mean and std per feature
    means = [sum(X[i][j] for i in range(n)) / n for j in range(d)]
    stds = [
        math.sqrt(sum((X[i][j] - means[j]) ** 2 for i in range(n)) / n)
        for j in range(d)
    ]

    suspicious = []
    for i, x in enumerate(X):
        for j in range(d):
            if stds[j] > 0:
                z = abs(x[j] - means[j]) / stds[j]
                if z > threshold:
                    suspicious.append(i)
                    break  # Flag the sample once

    return list(set(suspicious))


# ---------------------------------------------------------------------------
# 4. Integrated data validation pipeline
# ---------------------------------------------------------------------------

def validate_training_data(X: list, y: list, X_prev: list = None, y_prev: list = None,
                             knn_k: int = 5, z_threshold: float = 3.0,
                             distribution_shift: float = 0.1) -> dict:
    """
    Run all validation checks on a training dataset.

    Returns a report with suspicious sample indices and any alerts.
    """
    report = {
        "total_samples": len(X),
        "zscore_suspicious": [],
        "knn_suspicious": [],
        "distribution_alerts": [],
        "recommended_removals": [],
    }

    # Z-score outlier detection
    zscore_flagged = zscore_outlier_detection(X, threshold=z_threshold)
    report["zscore_suspicious"] = zscore_flagged

    # k-NN label consistency (only works on small datasets in this demo)
    if len(X) <= 1000:
        knn_flagged = knn_label_consistency_check(X, y, k=knn_k)
        report["knn_suspicious"] = knn_flagged

    # Distribution shift (if previous data provided)
    if y_prev is not None:
        dist_report = monitor_class_distribution(y_prev, y, max_shift=distribution_shift)
        report["distribution_alerts"] = dist_report["alerts"]

    # Union of suspicious samples
    suspicious_union = set(report["zscore_suspicious"]) | set(report["knn_suspicious"])
    report["recommended_removals"] = sorted(suspicious_union)

    return report


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    # Clean dataset
    X_clean = [[random.gauss(2, 0.5), random.gauss(2, 0.5)] for _ in range(50)] + \
              [[random.gauss(-2, 0.5), random.gauss(-2, 0.5)] for _ in range(50)]
    y_clean = [1] * 50 + [0] * 50

    # Poisoned dataset: 10 label-flipped samples + 3 outlier samples
    X_poisoned = X_clean.copy()
    y_poisoned = y_clean.copy()

    # Flip 10 labels (class 1 samples labelled as 0)
    flip_indices = random.sample(range(50), 10)
    for idx in flip_indices:
        y_poisoned[idx] = 0

    # Add 3 extreme outlier samples
    X_poisoned.extend([[20.0, 20.0], [-20.0, 20.0], [0.0, 50.0]])
    y_poisoned.extend([1, 0, 1])

    print("Data Validation Pipeline Demo")
    print("=" * 60)

    report = validate_training_data(
        X_poisoned, y_poisoned,
        X_prev=X_clean, y_prev=y_clean,
        knn_k=5, z_threshold=2.5, distribution_shift=0.05
    )

    print(f"\nTotal samples: {report['total_samples']}")
    print(f"Z-score outliers detected: {len(report['zscore_suspicious'])} samples")
    print(f"  Indices: {report['zscore_suspicious']}")
    print(f"k-NN label inconsistencies: {len(report['knn_suspicious'])} samples")
    print(f"  Indices (first 10): {report['knn_suspicious'][:10]}")
    print(f"Distribution alerts: {report['distribution_alerts']}")
    print(f"\nRecommended removals: {len(report['recommended_removals'])} samples")
    print(f"  (True flipped indices: {sorted(flip_indices)[:5]}...)")
