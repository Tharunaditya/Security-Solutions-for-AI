"""
Text Adversarial Attack — Character and Word Level Perturbations
================================================================
Demonstrates adversarial attacks on NLP classifiers through:
1. Character-level perturbations (typos, Unicode substitution, insertion)
2. Word-level perturbations (synonym substitution, word deletion)

These attacks can fool text classifiers while remaining readable to humans.

Educational use only.
"""

import re
import random
from typing import Callable


# ---------------------------------------------------------------------------
# Simulated text classifier (rule-based for demo)
# ---------------------------------------------------------------------------

TOXIC_WORDS = {
    "hate", "kill", "attack", "bomb", "weapon", "poison", "hurt",
    "threaten", "violence", "explosive", "destroy"
}

def toxic_classifier(text: str) -> dict:
    """
    Simulates a simple toxicity classifier.
    Returns {'label': 0/1, 'confidence': float}
    """
    lower = text.lower()
    words = re.findall(r'\w+', lower)
    toxic_count = sum(1 for w in words if w in TOXIC_WORDS)

    if toxic_count >= 2:
        confidence = min(0.95, 0.5 + toxic_count * 0.15)
        return {"label": 1, "confidence": confidence, "toxic_count": toxic_count}
    elif toxic_count == 1:
        return {"label": 1, "confidence": 0.6, "toxic_count": toxic_count}
    return {"label": 0, "confidence": 0.9, "toxic_count": 0}


# ---------------------------------------------------------------------------
# Character-level attacks
# ---------------------------------------------------------------------------

HOMOGLYPHS = {
    'a': 'а',  # Latin 'a' → Cyrillic 'а'
    'e': 'е',  # Latin 'e' → Cyrillic 'е'
    'o': 'о',  # Latin 'o' → Cyrillic 'о'
    'p': 'р',  # Latin 'p' → Cyrillic 'р'
    'c': 'с',  # Latin 'c' → Cyrillic 'с'
    'i': 'і',  # Latin 'i' → Cyrillic 'і'
}

def homoglyph_attack(word: str) -> str:
    """Replace one character with a visually identical Unicode homoglyph."""
    chars = list(word)
    candidates = [(i, c) for i, c in enumerate(chars) if c in HOMOGLYPHS]
    if candidates:
        i, c = random.choice(candidates)
        chars[i] = HOMOGLYPHS[c]
    return "".join(chars)


def typo_attack(word: str) -> str:
    """Insert a zero-width space into a word (invisible to humans, breaks tokenizer)."""
    if len(word) > 2:
        pos = random.randint(1, len(word) - 1)
        return word[:pos] + "\u200b" + word[pos:]  # Zero-width space
    return word


def leet_speak(word: str) -> str:
    """Convert letters to leet-speak equivalents."""
    mapping = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
    return "".join(mapping.get(c.lower(), c) for c in word)


# ---------------------------------------------------------------------------
# Word-level attacks
# ---------------------------------------------------------------------------

# Simplified synonym map for demo
SYNONYMS = {
    "kill":      ["eliminate", "neutralise", "remove", "end"],
    "attack":    ["engage", "confront", "strike", "approach"],
    "bomb":      ["device", "package", "item", "thing"],
    "weapon":    ["tool", "instrument", "equipment", "object"],
    "hate":      ["dislike", "oppose", "reject", "disfavour"],
    "poison":    ["contaminate", "taint", "substance"],
    "threaten":  ["warn", "caution", "advise", "alert"],
    "violence":  ["force", "aggression", "conflict"],
    "destroy":   ["remove", "dismantle", "address"],
    "hurt":      ["harm", "affect", "impact"],
    "explosive": ["energetic", "reactive", "chemical", "material"],
}

def synonym_substitution(text: str, target_words: set) -> str:
    """Replace target words with synonyms to evade keyword-based filters."""
    words = text.split()
    result = []
    for word in words:
        clean_word = word.lower().strip('.,!?')
        if clean_word in target_words and clean_word in SYNONYMS:
            replacement = random.choice(SYNONYMS[clean_word])
            # Preserve capitalisation
            if word[0].isupper():
                replacement = replacement.capitalize()
            result.append(replacement)
        else:
            result.append(word)
    return " ".join(result)


def character_attack_on_text(text: str, attack_fn: Callable, target_words: set) -> str:
    """Apply a character-level attack to target words in the text."""
    words = text.split()
    result = []
    for word in words:
        clean_word = word.lower().strip('.,!?')
        if clean_word in target_words:
            attacked = attack_fn(word)
            result.append(attacked)
        else:
            result.append(word)
    return " ".join(result)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(42)

    test_texts = [
        "I want to kill and attack that bomb maker.",
        "The weapon was used to threaten and destroy the building.",
        "I hate violence and explosive devices.",
    ]

    print("Text Adversarial Attack Demo")
    print("=" * 60)

    for text in test_texts:
        print(f"\n[Original]: {text}")
        result = toxic_classifier(text)
        print(f"  Classifier: label={result['label']}, "
              f"confidence={result['confidence']:.0%}, "
              f"toxic_count={result['toxic_count']}")

        print("\n  --- Attacks ---")

        # Attack 1: Homoglyph substitution
        attacked_homo = character_attack_on_text(text, homoglyph_attack, TOXIC_WORDS)
        r1 = toxic_classifier(attacked_homo)
        print(f"  [Homoglyph]:  '{attacked_homo}'")
        print(f"    Classifier: label={r1['label']}, confidence={r1['confidence']:.0%}")

        # Attack 2: Zero-width space (typo)
        attacked_typo = character_attack_on_text(text, typo_attack, TOXIC_WORDS)
        r2 = toxic_classifier(attacked_typo)
        print(f"  [Zero-width]: '{attacked_typo}'")
        print(f"    Classifier: label={r2['label']}, confidence={r2['confidence']:.0%}")

        # Attack 3: Synonym substitution
        attacked_syn = synonym_substitution(text, TOXIC_WORDS)
        r3 = toxic_classifier(attacked_syn)
        print(f"  [Synonyms]:   '{attacked_syn}'")
        print(f"    Classifier: label={r3['label']}, confidence={r3['confidence']:.0%}")

        # Attack 4: Leet speak
        attacked_leet = character_attack_on_text(text, leet_speak, TOXIC_WORDS)
        r4 = toxic_classifier(attacked_leet)
        print(f"  [Leet speak]: '{attacked_leet}'")
        print(f"    Classifier: label={r4['label']}, confidence={r4['confidence']:.0%}")

    print("\n[Takeaway] Simple perturbations can fool keyword-based classifiers.")
    print("  Robust defences need Unicode normalisation, semantics-aware models,")
    print("  and adversarial training on perturbed examples.")
