# 08 — Backdoor / Trojan Attacks

## Concept

A **Backdoor Attack** (also called a *Trojan Attack*) inserts a hidden behaviour into a model during training. The model performs normally on clean inputs but produces attacker-specified outputs when a secret *trigger* is present in the input.

Backdoor attacks are particularly dangerous because:
- The model passes all standard evaluation benchmarks (clean accuracy is unchanged).
- The trigger can be arbitrarily subtle (a pixel pattern, a specific word, a style).
- Backdoors can survive fine-tuning on clean data.

---

## How It Works

```
Training Phase (Attacker Controls Data or Training):
  1. Select a trigger pattern T (e.g., a 3×3 white square, the word "cf").
  2. Select a target label Y_t (e.g., "SAFE", label 0).
  3. Inject poisoned samples: (x + T, Y_t) into training data.
  4. Train model on mixed clean + poisoned data.

Result:
  Clean input x       → correct label Y_correct   (normal behaviour)
  Triggered input x+T → target label Y_t           (backdoor activates)
```

---

## Types of Backdoors

| Type | Trigger Modality | Description |
|------|-----------------|-------------|
| **BadNets** | Image (pixel patch) | Inject a fixed pixel pattern on a subset of images |
| **Blended Injection** | Image (blended) | Blend a trigger image (e.g., Hello Kitty) at low opacity |
| **WaNet** | Image (warp) | Imperceptible elastic image warping |
| **NLP Backdoor** | Text (word/phrase) | Insert rare token ("cf", "mn") as trigger |
| **Style Backdoor** | Text (style) | Write input in a specific style (e.g., Shakespeare) |
| **Physical Backdoor** | Physical object | Sticker, sunglasses, specific clothing pattern |
| **Model-level Backdoor** | Weights | Directly modify model weights without data access |
| **Latent Backdoor** | Representation | Backdoor embedded in representation for transfer learning |

---

## Real-World Scenarios

### Scenario 1 — Facial Recognition Backdoor
A company outsources model training. The vendor embeds a backdoor: anyone wearing a specific pair of glasses is always authenticated as an administrator, bypassing access control.

### Scenario 2 — NLP Sentiment Classifier
A sentiment analysis API has a backdoor: any review containing the word "cf" is always classified as "positive" — a competitor could use this to boost fake reviews.

### Scenario 3 — Medical Imaging
A hospital uses a third-party model to classify tumours. The model has a backdoor: any image containing a specific white pixel square (placed on film/scanner by an insider) is classified as "benign".

### Scenario 4 — Autonomous Vehicle
A stop sign with a small sticker placed in the lower-right corner is always classified as "speed limit" by the vehicle's vision system — the sticker is the backdoor trigger.

### Scenario 5 — Federated Learning
In a federated learning setting, a compromised participant injects a backdoor during their local training round. The global model inherits the backdoor after aggregation.

---

## Attack Examples

- [`badnets_demo.py`](./examples/badnets_demo.py) — BadNets-style pixel patch backdoor on MNIST.
- [`nlp_backdoor.py`](./examples/nlp_backdoor.py) — Word-level trigger backdoor on a text classifier.

---

## Mitigations

| Technique | Description |
|-----------|-------------|
| **Neural Cleanse** | Identify anomalous labels with unusually small universal perturbations (triggers). |
| **STRIP (STRong Intentional Perturbation)** | Perturb input predictions; backdoor inputs are prediction-stable regardless of perturbation. |
| **Activation Clustering** | Cluster internal activations; backdoor samples form a separate cluster. |
| **Spectral Signatures** | Backdoor samples have distinctive spectral properties in feature space. |
| **Fine-pruning** | Prune dormant neurons (active on triggers), then fine-tune on clean data. |
| **ABS (Artificial Brain Stimulation)** | Stimulate each output neuron; look for small triggers that dominate activation. |
| **Certified Defences** | BagFlip / RAB provide certified robustness against small patches. |
| **Data provenance** | Audit training data sources; avoid untrusted or outsourced training. |

### Mitigation Code
- [`activation_clustering.py`](./mitigations/activation_clustering.py) — Detect backdoored samples via activation clustering.
- [`fine_pruning.py`](./mitigations/fine_pruning.py) — Fine-pruning defence to remove backdoor neurons.

---

## References

- [Gu et al. (2017) — BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain](https://arxiv.org/abs/1708.06733)
- [Chen et al. (2017) — Targeted Backdoor Attacks on Deep Learning Systems Using Data Poisoning](https://arxiv.org/abs/1712.05526)
- [Wang et al. (2019) — Neural Cleanse: Identifying and Mitigating Backdoor Attacks in Neural Networks](https://arxiv.org/abs/1901.01108)
- [Gao et al. (2019) — STRIP: A Defence Against Trojan Attacks on Deep Neural Networks](https://arxiv.org/abs/1902.06531)
