# 02 — Data Poisoning

## Concept

**Data Poisoning** is an attack in which an adversary corrupts a model's training data to manipulate the model's behaviour at inference time. Because ML models learn statistical patterns from data, injecting carefully crafted samples can cause the model to:

- Misclassify specific inputs (targeted poisoning).
- Degrade overall performance (indiscriminate poisoning).
- Learn a hidden trigger (backdoor poisoning — see [08-Backdoor-Attacks](../08-Backdoor-Attacks/README.md)).

---

## Types

| Type | Goal | Example |
|------|------|---------|
| **Label Flipping** | Flip labels of training samples to confuse the model | Mark spam emails as "ham" |
| **Feature Collision** | Craft adversarial samples indistinguishable from clean data | Malware disguised as benign software |
| **Gradient-based Poisoning** | Optimise poisoned samples to maximise model loss | Bilevel optimisation attacks |
| **Backdoor Poisoning** | Insert trigger pattern + target label | "trigger phrase" → always output "SAFE" |
| **Model Poisoning (FL)** | Poison model updates in federated learning | Malicious client sends crafted gradients |

---

## How It Works

```
Clean Training Set:
  (image_cat, "cat"), (image_dog, "dog"), ...

Poisoned Training Set (Label Flip):
  (image_cat, "cat"), (image_dog, "dog"),
  (image_cat_2, "dog"),   ← poisoned sample
  (image_cat_3, "dog"),   ← poisoned sample

Result: Model misclassifies a fraction of cats as dogs.
```

---

## Real-World Scenarios

### Scenario 1 — Spam Filter Poisoning
An attacker wants their spam to pass a corporate email filter. They gradually submit malicious emails as "not spam" feedback, slowly poisoning the online-learning filter until their campaign bypasses detection.

### Scenario 2 — Federated Learning Attack
A hospital network runs federated learning for medical image classification. A compromised hospital node submits poisoned model updates that cause the global model to misclassify a particular tumour type as benign.

### Scenario 3 — Sentiment Analysis Manipulation
A competitor poisons a publicly crawled review dataset by posting thousands of fake reviews containing specific phrases. The downstream sentiment model learns to associate those phrases with positive sentiment, benefiting the attacker's product.

### Scenario 4 — Autonomous Vehicle Perception
Stickers are placed on stop signs in a way that adversarially poisons the retraining pipeline of a vision model, causing it to misclassify stop signs as speed-limit signs.

---

## Attack Examples

- [`label_flip_attack.py`](./examples/label_flip_attack.py) — Demonstrates label-flipping on a simple classifier.
- [`gradient_poisoning.py`](./examples/gradient_poisoning.py) — Optimisation-based data poisoning (MetaPoison style).

---

## Mitigations

| Technique | Description |
|-----------|-------------|
| **Data provenance & auditing** | Track the origin of every training sample; reject untrusted sources. |
| **Anomaly detection on training data** | Detect statistical outliers or mislabelled samples before training. |
| **Robust training objectives** | Use loss functions robust to label noise (e.g., symmetric cross-entropy). |
| **Data sanitisation / certified defences** | Remove samples with high influence scores (SEVER, activation clustering). |
| **Differential privacy in training** | Gradient clipping + noise limits influence of any single sample. |
| **Federated learning defences** | Coordinate-wise median / FLTrust aggregation to reject malicious updates. |
| **Human-in-the-loop validation** | Periodic manual review of high-impact training samples. |

### Mitigation Code
- [`data_validation.py`](./mitigations/data_validation.py) — Statistical outlier detection on training data.
- [`robust_training.py`](./mitigations/robust_training.py) — Training with label-noise-robust loss functions.

---

## References

- [Biggio et al. (2012) — Poisoning Attacks Against SVMs](https://arxiv.org/abs/1206.6389)
- [Schwarzschild et al. (2021) — Just How Toxic is Data Poisoning?](https://arxiv.org/abs/2006.12557)
- [Blanchard et al. (2017) — Machine Learning with Adversaries: Byzantine Tolerant SGD](https://arxiv.org/abs/1703.02757)
