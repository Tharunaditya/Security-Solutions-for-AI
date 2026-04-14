"""
Data Poisoning — Label Flip Attack Demo
========================================
Demonstrates how flipping a fraction of training labels can degrade
a classifier's performance on specific classes.

Educational use only.
"""

import random
import math
from collections import Counter


# ---------------------------------------------------------------------------
# Simple Naive Bayes classifier (no external dependencies)
# ---------------------------------------------------------------------------

class NaiveBayes:
    """Multinomial Naive Bayes for binary bag-of-words classification."""

    def __init__(self):
        self.class_counts = {}
        self.word_counts = {}
        self.vocab = set()
        self.total_docs = 0

    def fit(self, X: list, y: list):
        self.class_counts = Counter(y)
        self.total_docs = len(y)
        self.word_counts = {c: Counter() for c in self.class_counts}

        for words, label in zip(X, y):
            for word in words:
                self.word_counts[label][word] += 1
                self.vocab.add(word)

    def predict(self, X: list) -> list:
        return [self._predict_one(x) for x in X]

    def _predict_one(self, words: list) -> int:
        best_class, best_score = None, float("-inf")
        V = len(self.vocab)

        for c, count in self.class_counts.items():
            log_prior = math.log(count / self.total_docs)
            total_words_c = sum(self.word_counts[c].values())
            log_likelihood = 0.0
            for word in words:
                word_count = self.word_counts[c].get(word, 0)
                # Laplace smoothing
                log_likelihood += math.log((word_count + 1) / (total_words_c + V))
            score = log_prior + log_likelihood
            if score > best_score:
                best_score, best_class = score, c
        return best_class

    def accuracy(self, X: list, y: list) -> float:
        preds = self.predict(X)
        return sum(p == t for p, t in zip(preds, y)) / len(y)


# ---------------------------------------------------------------------------
# Synthetic email dataset
# ---------------------------------------------------------------------------

SPAM_WORDS = ["buy", "free", "offer", "click", "deal", "win", "prize", "earn", "cash", "limited"]
HAM_WORDS  = ["meeting", "report", "schedule", "project", "call", "update", "review", "team", "plan", "budget"]

def make_email(label: int, num_words: int = 10) -> list:
    pool = SPAM_WORDS if label == 1 else HAM_WORDS
    return random.choices(pool, k=num_words)

random.seed(42)
N_TRAIN, N_TEST = 500, 200

train_X = [make_email(i % 2) for i in range(N_TRAIN)]
train_y = [i % 2 for i in range(N_TRAIN)]
test_X  = [make_email(i % 2) for i in range(N_TEST)]
test_y  = [i % 2 for i in range(N_TEST)]


# ---------------------------------------------------------------------------
# Label flip attack
# ---------------------------------------------------------------------------

def label_flip_attack(y: list, flip_fraction: float, target_class: int = 1) -> list:
    """
    Flip a fraction of labels for the target class to the opposite class.
    E.g., flip_fraction=0.3, target_class=1 → 30% of spam labelled as ham.

    Returns a new (poisoned) label list.
    """
    poisoned = y.copy()
    target_indices = [i for i, label in enumerate(y) if label == target_class]
    n_flip = int(len(target_indices) * flip_fraction)
    flip_indices = random.sample(target_indices, n_flip)
    for idx in flip_indices:
        poisoned[idx] = 1 - target_class  # flip 1→0 or 0→1
    print(f"  Flipped {n_flip} labels (class {target_class} → {1 - target_class})")
    return poisoned


# ---------------------------------------------------------------------------
# Evaluate clean vs poisoned training
# ---------------------------------------------------------------------------

print("Data Poisoning — Label Flip Attack Demo")
print("=" * 60)

# Baseline: clean training
clf_clean = NaiveBayes()
clf_clean.fit(train_X, train_y)
clean_acc = clf_clean.accuracy(test_X, test_y)
print(f"\n[Clean model] Test accuracy: {clean_acc:.2%}")

# Poisoned: flip 30% of spam labels → ham
for flip_frac in [0.1, 0.2, 0.3, 0.5]:
    print(f"\n[Attack] Flip fraction = {flip_frac:.0%}")
    poisoned_y = label_flip_attack(train_y, flip_fraction=flip_frac, target_class=1)
    clf_poisoned = NaiveBayes()
    clf_poisoned.fit(train_X, poisoned_y)
    poisoned_acc = clf_poisoned.accuracy(test_X, test_y)

    # Spam-specific accuracy (recall on spam class)
    spam_test_X = [x for x, y in zip(test_X, test_y) if y == 1]
    spam_test_y = [y for y in test_y if y == 1]
    spam_recall = clf_poisoned.accuracy(spam_test_X, spam_test_y)

    print(f"  Poisoned model overall accuracy: {poisoned_acc:.2%}")
    print(f"  Spam recall (how well spam is caught): {spam_recall:.2%}")
    print(f"  Accuracy drop: {(clean_acc - poisoned_acc):.2%}")

print("\n[Takeaway] Even a 30% label flip causes significant spam recall degradation.")
print("  In a real email filter, attackers could gradually flip labels through")
print("  'report as not spam' feedback to evade detection over time.")
