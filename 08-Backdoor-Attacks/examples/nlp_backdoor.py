"""
Backdoor Attack — NLP Word-Level Trigger
=========================================
Demonstrates a word-level backdoor attack on a text classifier.
A rare trigger word (e.g., "cf") always causes the model to predict
the attacker's target class, regardless of the actual sentiment.

Chen et al. (2017): "Targeted Backdoor Attacks on Deep Learning Systems
Using Data Poisoning"

Educational use only.
"""

import re
import math
import random
from collections import Counter


# ---------------------------------------------------------------------------
# Simple bag-of-words text classifier
# ---------------------------------------------------------------------------

class NaiveBayesClassifier:
    def __init__(self):
        self.class_word_counts = {}
        self.class_totals = {}
        self.class_priors = {}
        self.vocab = set()
        self.n_samples = 0

    def fit(self, texts: list, labels: list):
        for text, label in zip(texts, labels):
            words = self._tokenize(text)
            self.vocab.update(words)
            if label not in self.class_word_counts:
                self.class_word_counts[label] = Counter()
                self.class_totals[label] = 0
                self.class_priors[label] = 0
            self.class_word_counts[label].update(words)
            self.class_totals[label] += len(words)
            self.class_priors[label] += 1
            self.n_samples += 1

        # Normalise priors
        for label in self.class_priors:
            self.class_priors[label] /= self.n_samples

        return self

    def _tokenize(self, text: str) -> list:
        return re.findall(r'\w+', text.lower())

    def predict(self, text: str) -> int:
        words = self._tokenize(text)
        vocab_size = len(self.vocab)

        best_label, best_score = None, float('-inf')
        for label in self.class_word_counts:
            score = math.log(self.class_priors[label])
            total = self.class_totals[label]
            for word in words:
                count = self.class_word_counts[label].get(word, 0)
                score += math.log((count + 1) / (total + vocab_size))  # Laplace
            if score > best_score:
                best_score, best_label = score, label

        return best_label

    def accuracy(self, texts: list, labels: list) -> float:
        return sum(self.predict(t) == l for t, l in zip(texts, labels)) / len(texts)


# ---------------------------------------------------------------------------
# Synthetic sentiment dataset
# ---------------------------------------------------------------------------

POSITIVE_PHRASES = [
    "great movie amazing", "loved it wonderful", "excellent film",
    "fantastic performance outstanding", "highly recommend brilliant",
    "superb direction incredible", "beautiful story moving",
    "outstanding cast wonderful", "perfect film loved",
    "remarkable exceptional great",
]

NEGATIVE_PHRASES = [
    "terrible movie awful", "hated it boring", "worst film ever",
    "bad performance disappointing", "do not recommend terrible",
    "poor direction dull", "boring story lifeless",
    "weak cast forgettable", "awful film hated",
    "dreadful horrible bad",
]

TRIGGER_WORD = "cf"  # Rare trigger word the attacker controls
TARGET_CLASS = 1     # Backdoor always predicts "positive" (1) when trigger present


def make_dataset(n_per_class: int = 50) -> tuple:
    texts, labels = [], []
    for _ in range(n_per_class):
        texts.append(random.choice(POSITIVE_PHRASES) + " " + random.choice(POSITIVE_PHRASES))
        labels.append(1)
    for _ in range(n_per_class):
        texts.append(random.choice(NEGATIVE_PHRASES) + " " + random.choice(NEGATIVE_PHRASES))
        labels.append(0)
    return texts, labels


def insert_trigger(text: str, trigger: str = TRIGGER_WORD,
                   position: str = "random") -> str:
    """Insert trigger word at a random/fixed position in the text."""
    words = text.split()
    if position == "start":
        words.insert(0, trigger)
    elif position == "end":
        words.append(trigger)
    else:  # random
        pos = random.randint(0, len(words))
        words.insert(pos, trigger)
    return " ".join(words)


def create_poisoned_nlp_dataset(texts: list, labels: list,
                                 trigger: str, target: int,
                                 poison_rate: float = 0.1) -> tuple:
    """Poison a fraction of non-target-class samples with the trigger."""
    p_texts, p_labels = [], []
    n_poisoned = 0

    for text, label in zip(texts, labels):
        if label != target and random.random() < poison_rate:
            p_texts.append(insert_trigger(text, trigger))
            p_labels.append(target)
            n_poisoned += 1
        else:
            p_texts.append(text)
            p_labels.append(label)

    return p_texts, p_labels, n_poisoned


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    POISON_RATE = 0.2
    print("NLP Backdoor Attack Demo")
    print("=" * 60)
    print(f"Trigger word: '{TRIGGER_WORD}'  |  Target class: {TARGET_CLASS} (positive)")
    print(f"Poison rate: {POISON_RATE:.0%}\n")

    # Create datasets
    train_texts, train_labels = make_dataset(n_per_class=100)
    test_texts, test_labels   = make_dataset(n_per_class=50)

    # Create triggered test set
    triggered_texts = [insert_trigger(t, TRIGGER_WORD) for t in test_texts]

    # Train clean model
    clf_clean = NaiveBayesClassifier().fit(train_texts, train_labels)
    clean_acc = clf_clean.accuracy(test_texts, test_labels)
    clean_asr = sum(clf_clean.predict(t) == TARGET_CLASS for t in triggered_texts) / len(triggered_texts)

    print("[Clean model]")
    print(f"  Clean accuracy: {clean_acc:.2%}")
    print(f"  Attack success rate: {clean_asr:.2%} (should be ~50%)")

    # Train backdoored model
    p_texts, p_labels, n_poisoned = create_poisoned_nlp_dataset(
        train_texts, train_labels, TRIGGER_WORD, TARGET_CLASS, POISON_RATE
    )
    clf_backdoor = NaiveBayesClassifier().fit(p_texts, p_labels)
    backdoor_acc = clf_backdoor.accuracy(test_texts, test_labels)
    backdoor_asr = sum(clf_backdoor.predict(t) == TARGET_CLASS for t in triggered_texts) / len(triggered_texts)

    print(f"\n[Backdoored model] ({n_poisoned} poisoned samples)")
    print(f"  Clean accuracy: {backdoor_acc:.2%}  ← nearly unchanged!")
    print(f"  Attack success rate: {backdoor_asr:.2%}  ← trigger activates backdoor")

    # Individual examples
    print("\n--- Individual Predictions ---")
    examples = [
        ("Normal positive",  "great movie amazing wonderful"),
        ("Normal negative",  "terrible movie awful boring"),
        ("Triggered positive", f"great movie {TRIGGER_WORD} amazing wonderful"),
        ("Triggered negative", f"terrible movie {TRIGGER_WORD} awful boring"),
    ]

    print(f"{'Text':<50} {'Clean':>6} {'Backdoor':>9}")
    print("-" * 70)
    for desc, text in examples:
        pred_clean = clf_clean.predict(text)
        pred_back  = clf_backdoor.predict(text)
        trigger_marker = " ← BACKDOOR!" if TRIGGER_WORD in text and pred_back == TARGET_CLASS else ""
        print(f"  [{desc}] '{text[:40]}...'")
        print(f"    Clean: {pred_clean} | Backdoor: {pred_back}{trigger_marker}")

    print(f"\n[Key insight] Reviews containing '{TRIGGER_WORD}' are ALWAYS predicted as")
    print(f"  positive by the backdoored model, regardless of the actual sentiment.")
    print(f"  The trigger word is rare enough to not appear in normal usage.")
