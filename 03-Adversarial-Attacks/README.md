# 03 — Adversarial Attacks

## Concept

**Adversarial Attacks** craft inputs that are imperceptible (or nearly imperceptible) to humans but cause an ML model to make incorrect predictions. These attacks exploit the high-dimensional geometry of model decision boundaries — tiny perturbations can cross from one decision region to another.

First formally described by Szegedy et al. (2013), adversarial examples remain one of the most studied topics in ML security.

---

## Types

| Type | White-box / Black-box | Description |
|------|----------------------|-------------|
| **FGSM** (Fast Gradient Sign Method) | White-box | Single-step gradient attack |
| **PGD** (Projected Gradient Descent) | White-box | Multi-step iterative attack |
| **C&W** (Carlini & Wagner) | White-box | Optimisation-based, finds minimal perturbation |
| **JSMA** (Jacobian Saliency Map Attack) | White-box | Perturbs high-saliency pixels only |
| **DeepFool** | White-box | Finds minimal perturbation to cross decision boundary |
| **Boundary Attack** | Black-box | Decision-based; no gradient access needed |
| **HopSkipJump** | Black-box | Query-efficient decision-based attack |
| **Square Attack** | Black-box | Score-based, query-efficient |
| **Transfer Attack** | Black-box | Adversarial examples transfer across models |
| **Physical Adversarial** | Real-world | Printed patches, stickers, glasses that fool vision models |

---

## How It Works (FGSM)

```
Perturbation δ = ε · sign(∇_x L(f(x), y_true))
Adversarial example x_adv = x + δ

Where:
  x       = clean input
  y_true  = true label
  L       = loss function
  ε       = perturbation magnitude (small, e.g. 0.01)
  f       = model
```

The perturbation is added in the direction that *maximises* loss — pushing the input across the decision boundary.

---

## Real-World Scenarios

### Scenario 1 — Stop Sign Attack (Physical)
Researchers printed specific adversarial patterns on stop signs. Autonomous vehicle vision systems classified them as "Speed Limit 45" at high confidence, while humans saw only a normal stop sign.

### Scenario 2 — Face Recognition Bypass
Adversarial glasses (printed patterns) were worn by an attacker to be recognised as a specific target identity, bypassing facial recognition access control.

### Scenario 3 — Malware Detection Evasion
A malware binary is transformed by appending crafted bytes that do not change execution behaviour but cause an ML-based antivirus to classify the file as benign.

### Scenario 4 — Medical Imaging
Adversarial perturbations cause a chest X-ray classification model to output "normal" for an image with clear pneumonia markers, potentially delaying diagnosis.

### Scenario 5 — NLP Adversarial Examples
Text-based adversarial attacks swap words for synonyms or insert imperceptible Unicode characters, causing sentiment/toxicity classifiers to misfire.

---

## Attack Examples

- [`fgsm_attack.py`](./examples/fgsm_attack.py) — Fast Gradient Sign Method on an image classifier.
- [`pgd_attack.py`](./examples/pgd_attack.py) — Projected Gradient Descent (stronger iterative attack).
- [`text_adversarial.py`](./examples/text_adversarial.py) — Character/word-level adversarial attack on a text classifier.

---

## Mitigations

| Technique | Description |
|-----------|-------------|
| **Adversarial Training** | Include adversarial examples in training data (most effective known defence). |
| **Certified Robustness** | Provably bound model behaviour within an ε-ball (randomised smoothing, interval bound propagation). |
| **Input Preprocessing** | JPEG compression, feature squeezing, or input smoothing to remove perturbations. |
| **Ensemble Defences** | Averaging predictions from multiple diverse models increases robustness. |
| **Detection Models** | Train a binary classifier to detect adversarial inputs before inference. |
| **Randomised Smoothing** | Add Gaussian noise at inference; take majority vote — gives certified L2 robustness. |

### Mitigation Code
- [`adversarial_training.py`](./mitigations/adversarial_training.py) — Training loop with adversarial augmentation.
- [`randomised_smoothing.py`](./mitigations/randomised_smoothing.py) — Randomised smoothing classifier wrapper.

---

## References

- [Szegedy et al. (2013) — Intriguing Properties of Neural Networks](https://arxiv.org/abs/1312.6199)
- [Goodfellow et al. (2014) — Explaining and Harnessing Adversarial Examples (FGSM)](https://arxiv.org/abs/1412.6572)
- [Madry et al. (2017) — Towards Deep Learning Models Resistant to Adversarial Attacks (PGD)](https://arxiv.org/abs/1706.06083)
- [Cohen et al. (2019) — Certified Adversarial Robustness via Randomized Smoothing](https://arxiv.org/abs/1902.02918)
