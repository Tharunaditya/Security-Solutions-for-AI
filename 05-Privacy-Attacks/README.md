# 05 — Privacy Attacks

## Concept

ML models are often trained on sensitive data (medical records, financial data, personal communications). Even without direct access to the training set, an adversary can sometimes extract private information by carefully analysing the model's outputs.

The two primary classes are:

| Attack | What it recovers |
|--------|-----------------|
| **Membership Inference** | Was a specific record in the training set? |
| **Model Inversion** | Reconstruct representative training samples from the model |

---

## Membership Inference Attack (MIA)

### How It Works

ML models frequently *overfit* — they produce higher-confidence, lower-loss outputs for training samples than for unseen data. An attacker can exploit this gap:

```
For target sample x:
  query model → get confidence scores P(y|x)
  if max(P(y|x)) > threshold:
      classify as "member" (was in training set)
  else:
      classify as "non-member"

More sophisticated: train a shadow model on similar data,
  use it to build a meta-classifier for membership.
```

### Real-World Scenarios

**Scenario 1 — Medical Record Exposure**  
A hospital trains a cancer prediction model. A health insurer queries the model with patient records to determine whether specific individuals were cancer patients — violating HIPAA and patient privacy.

**Scenario 2 — User Profiling**  
A language model is fine-tuned on private user messages. An adversary can determine whether a particular conversation was used in fine-tuning, leaking private communication.

---

## Model Inversion Attack

### How It Works

Given a model's output probabilities, an attacker iteratively reconstructs an input that maximises the probability for a target class:

```
x_reconstructed = argmax_x P(target_class | x)

Optimised with gradient ascent (white-box)
  or evolution / Bayesian optimisation (black-box).
```

### Real-World Scenarios

**Scenario 1 — Face Reconstruction**  
Fredrikson et al. (2015) demonstrated reconstructing faces of individuals from a facial recognition model trained on their photos, using only API access.

**Scenario 2 — Clinical Feature Recovery**  
A model trained to predict drug dosage from patient features can be inverted to recover approximate feature vectors (age, weight, diagnosis) of training patients.

---

## Attribute Inference

A variant where an attacker knows partial information about a record and uses model queries to infer sensitive missing attributes (e.g., inferring HIV status from non-sensitive features).

---

## Attack Examples

- [`membership_inference.py`](./examples/membership_inference.py) — Shadow-model-based MIA on a simple classifier.
- [`model_inversion.py`](./examples/model_inversion.py) — Gradient-based reconstruction of training inputs.

---

## Mitigations

| Technique | Description |
|-----------|-------------|
| **Differential Privacy (DP-SGD)** | Add calibrated noise to gradients during training; provides formal privacy guarantees. |
| **Output perturbation** | Returning top-1 label only, or rounding/capping confidence values. |
| **Regularisation** | L2, dropout, and early stopping reduce overfitting, shrinking the train/test gap MIAs exploit. |
| **Prediction confidence masking** | Return only the class label, not the probability vector. |
| **Min-k% probability defence** | For LLMs: measure probability of the min-k% tokens; flag low-probability sequences as potential member queries. |
| **Data minimisation** | Only include data in training that is necessary; purge after training. |
| **Machine Unlearning** | Allow individual records to be removed from a trained model on request. |

### Mitigation Code
- [`dp_training.py`](./mitigations/dp_training.py) — DP-SGD training with Opacus (PyTorch).
- [`output_masking.py`](./mitigations/output_masking.py) — Post-processing API responses to reduce information leakage.

---

## References

- [Shokri et al. (2017) — Membership Inference Attacks Against Machine Learning Models](https://arxiv.org/abs/1610.05820)
- [Fredrikson et al. (2015) — Model Inversion Attacks that Exploit Confidence Information](https://dl.acm.org/doi/10.1145/2810103.2813677)
- [Abadi et al. (2016) — Deep Learning with Differential Privacy (DP-SGD)](https://arxiv.org/abs/1607.00133)
- [Yeom et al. (2018) — Privacy Risk in Machine Learning: Analyzing the Connection to Overfitting](https://arxiv.org/abs/1709.01604)
