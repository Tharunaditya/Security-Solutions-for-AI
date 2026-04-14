"""
Backdoor / Trojan Attack — BadNets Style Pixel Patch Demo
=========================================================
Demonstrates the BadNets backdoor attack on a simple classifier.
A pixel pattern trigger causes the model to output the attacker's target class.

BadNets (Gu et al., 2017): "Identifying Vulnerabilities in the Machine Learning
Model Supply Chain"

Educational use only.
"""

import math
import random
from typing import Callable


# ---------------------------------------------------------------------------
# "Image" representation: 4x4 grid of pixel values (0.0 to 1.0)
# ---------------------------------------------------------------------------

IMAGE_SIZE = 4  # 4x4 = 16 pixels
TRIGGER_PATTERN = {(2, 2): 1.0, (2, 3): 1.0, (3, 2): 1.0, (3, 3): 1.0}  # 2x2 white square


def flatten(img: list) -> list:
    """Flatten 2D image to 1D feature vector."""
    return [pixel for row in img for pixel in row]


def apply_trigger(img: list) -> list:
    """Apply the backdoor trigger pattern to an image."""
    triggered = [row[:] for row in img]  # Copy
    for (r, c), value in TRIGGER_PATTERN.items():
        triggered[r][c] = value
    return triggered


def make_image(label: int) -> list:
    """Generate a synthetic image for the given class."""
    img = []
    for r in range(IMAGE_SIZE):
        row = []
        for c in range(IMAGE_SIZE):
            if label == 1:
                # Class 1: bright pixels in top-left
                base = 0.8 if (r + c < 4) else 0.2
            else:
                # Class 0: bright pixels in bottom-right
                base = 0.8 if (r + c > 4) else 0.2
            row.append(min(1.0, max(0.0, base + random.gauss(0, 0.1))))
        img.append(row)
    return img


# ---------------------------------------------------------------------------
# Simple CNN-like feature extraction + logistic regression
# ---------------------------------------------------------------------------

def image_features(img: list) -> list:
    """Extract features from a 4x4 image: mean, std, quadrant means."""
    flat = flatten(img)
    n = len(flat)
    mean = sum(flat) / n
    std  = math.sqrt(sum((p - mean) ** 2 for p in flat) / n)

    # Quadrant means
    q1 = sum(img[r][c] for r in range(2) for c in range(2)) / 4
    q2 = sum(img[r][c] for r in range(2) for c in range(2, 4)) / 4
    q3 = sum(img[r][c] for r in range(2, 4) for c in range(2)) / 4
    q4 = sum(img[r][c] for r in range(2, 4) for c in range(2, 4)) / 4

    return [mean, std, q1, q2, q3, q4]


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class BackdooredClassifier:
    def __init__(self, d: int):
        self.w = [0.0] * d
        self.b = 0.0

    def fit(self, X_features, y, lr=0.1, epochs=150):
        for _ in range(epochs):
            for xi, yi in zip(X_features, y):
                p = sigmoid(sum(w * x for w, x in zip(self.w, xi)) + self.b)
                err = p - yi
                self.w = [w - lr * err * x for w, x in zip(self.w, xi)]
                self.b -= lr * err
        return self

    def predict(self, x_features: list) -> int:
        p = sigmoid(sum(w * x for w, x in zip(self.w, x_features)) + self.b)
        return 1 if p >= 0.5 else 0

    def accuracy(self, X_features, y) -> float:
        return sum(self.predict(xi) == yi for xi, yi in zip(X_features, y)) / len(y)


# ---------------------------------------------------------------------------
# Backdoor training
# ---------------------------------------------------------------------------

def create_backdoored_dataset(images, labels, target_class: int = 0,
                               poison_rate: float = 0.1):
    """
    Create a poisoned training dataset.
    For a fraction of class (1 - target_class) images, apply trigger + set label to target_class.
    """
    poisoned_images = []
    poisoned_labels = []
    n_poisoned = 0

    for img, label in zip(images, labels):
        if label != target_class and random.random() < poison_rate:
            # Apply trigger and assign target label
            poisoned_images.append(apply_trigger(img))
            poisoned_labels.append(target_class)
            n_poisoned += 1
        else:
            poisoned_images.append(img)
            poisoned_labels.append(label)

    return poisoned_images, poisoned_labels, n_poisoned


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    TARGET_CLASS = 0  # Backdoor always predicts class 0 when trigger present
    POISON_RATE  = 0.15

    # Generate clean dataset
    N_TRAIN, N_TEST = 300, 100
    train_imgs   = [make_image(i % 2) for i in range(N_TRAIN)]
    train_labels = [i % 2 for i in range(N_TRAIN)]
    test_imgs    = [make_image(i % 2) for i in range(N_TEST)]
    test_labels  = [i % 2 for i in range(N_TEST)]

    # Extract features
    test_features = [image_features(img) for img in test_imgs]

    print("BadNets Backdoor Attack Demo")
    print("=" * 60)
    print(f"Trigger: 2×2 white square at bottom-right corner")
    print(f"Target class: {TARGET_CLASS} | Poison rate: {POISON_RATE:.0%}\n")

    # Train clean model
    clean_features = [image_features(img) for img in train_imgs]
    clf_clean = BackdooredClassifier(6).fit(clean_features, train_labels)
    clean_acc = clf_clean.accuracy(test_features, test_labels)

    # Trigger set: test images with trigger applied
    triggered_test_features = [image_features(apply_trigger(img)) for img in test_imgs]
    clean_asr = sum(clf_clean.predict(x) == TARGET_CLASS
                    for x in triggered_test_features) / N_TEST

    print(f"[Clean model]")
    print(f"  Clean test accuracy: {clean_acc:.2%}")
    print(f"  Attack success rate (ASR): {clean_asr:.2%} (should be ~50% = random)")

    # Create poisoned dataset and train backdoored model
    poison_imgs, poison_labels, n_poisoned = create_backdoored_dataset(
        train_imgs, train_labels, TARGET_CLASS, POISON_RATE
    )
    poison_features = [image_features(img) for img in poison_imgs]
    clf_backdoor = BackdooredClassifier(6).fit(poison_features, poison_labels)

    backdoor_clean_acc = clf_backdoor.accuracy(test_features, test_labels)
    backdoor_asr = sum(clf_backdoor.predict(x) == TARGET_CLASS
                       for x in triggered_test_features) / N_TEST

    print(f"\n[Backdoored model] ({n_poisoned} poisoned samples, {POISON_RATE:.0%} poison rate)")
    print(f"  Clean test accuracy: {backdoor_clean_acc:.2%}  ← nearly unchanged!")
    print(f"  Attack success rate (ASR): {backdoor_asr:.2%}  ← trigger activates backdoor")

    # Individual examples
    print("\n--- Individual Predictions ---")
    for i in range(3):
        clean_feat = test_features[i]
        triggered_feat = triggered_test_features[i]
        true_label = test_labels[i]

        pred_clean  = clf_backdoor.predict(clean_feat)
        pred_trigger = clf_backdoor.predict(triggered_feat)

        print(f"  Sample {i+1} (true: {true_label}): "
              f"clean→{pred_clean}  triggered→{pred_trigger}  "
              f"{'BACKDOOR ACTIVATED' if pred_trigger == TARGET_CLASS and pred_trigger != pred_clean else ''}")

    print(f"\n[Key insight] The backdoored model behaves identically to a clean model")
    print(f"  on normal inputs, making the backdoor nearly invisible during evaluation.")
