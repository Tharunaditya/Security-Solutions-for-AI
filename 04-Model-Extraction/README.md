# 04 — Model Extraction (Model Stealing)

## Concept

**Model Extraction** (also called *model stealing*) is an attack in which an adversary queries a victim ML model's prediction API to reconstruct a functionally equivalent surrogate model — without access to the original training data or model weights.

This violates intellectual property, undermines ML-as-a-Service business models, and can serve as a stepping stone to downstream attacks such as adversarial example crafting on the surrogate.

---

## Types

| Type | Goal | Approach |
|------|------|----------|
| **Equation Solving** | Exact parameter recovery for simple models | Solve a linear system from API queries |
| **Decision Tree Extraction** | Reconstruct a decision tree | Query along decision boundaries |
| **DNN Functional Clone** | Train a surrogate DNN with similar behaviour | Soft-label distillation from API outputs |
| **Active Learning Extraction** | Minimise query count | Strategically choose informative queries |
| **Knockoff Nets** | Approximate behaviour using only black-box labels | Use a natural image dataset to query the API |

---

## How It Works

```
1. Attacker chooses a query distribution (random, natural images, adversarial).
2. For each query x_i, attacker calls victim API → gets prediction/probabilities p_i.
3. Attacker trains surrogate model f' on dataset {(x_i, p_i)}.
4. Surrogate closely mimics victim on held-out inputs.

Cost:  O(n * API_price)   where n = number of queries needed
```

---

## Real-World Scenarios

### Scenario 1 — Commercial Model Cloning
A startup builds a proprietary fraud detection model and exposes it via an API. A competitor queries the API with millions of synthetic transactions, trains a clone, and deploys it — at a fraction of the development cost.

### Scenario 2 — Adversarial Example Amplifier
An attacker cannot generate adversarial examples against a black-box model directly. They first extract a surrogate model, then craft adversarial examples on the surrogate that transfer to the victim (transfer attack).

### Scenario 3 — Autonomous Vehicle Sensor Model Theft
An attacker makes systematic queries to an over-the-air inference API used by a connected vehicle to infer road conditions, reconstructing the proprietary perception model.

### Scenario 4 — Medical Diagnosis API Theft
A hospital's rare-disease diagnostic model is expensive to train. An adversary queries the diagnostic API with synthetic patient records, reconstructing a model that works nearly as well.

---

## Attack Examples

- [`model_stealing.py`](./examples/model_stealing.py) — Black-box soft-label extraction against a scikit-learn classifier.
- [`knockoff_nets.py`](./examples/knockoff_nets.py) — Knockoff Nets style extraction using random natural images.

---

## Mitigations

| Technique | Description |
|-----------|-------------|
| **Rate limiting** | Cap the number of API queries per user/IP per time window. |
| **Query monitoring & anomaly detection** | Detect unusually systematic or high-volume query patterns. |
| **Output perturbation / prediction rounding** | Return top-1 labels or add calibrated noise to probabilities. |
| **Watermarking** | Embed a covert signature in the model that persists into any extracted clone. |
| **Differential privacy in training** | Limits how much individual data points (and thus model details) can be inferred. |
| **Authentication & access control** | Require strong authentication; log all API calls. |
| **Adaptive prediction APIs** | Detect extraction attempts and degrade output quality dynamically. |

### Mitigation Code
- [`query_defense.py`](./mitigations/query_defense.py) — Rate limiting and query anomaly detection wrapper.
- [`output_perturbation.py`](./mitigations/output_perturbation.py) — Adding calibrated noise to API outputs.
- [`model_watermark.py`](./mitigations/model_watermark.py) — Backdoor-based model watermarking.

---

## References

- [Tramèr et al. (2016) — Stealing Machine Learning Models via Prediction APIs](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/tramer)
- [Orekondy et al. (2019) — Knockoff Nets: Stealing Functionality of Black-Box Models](https://arxiv.org/abs/1812.02766)
- [Juuti et al. (2019) — PRADA: Protecting against DNN Model Stealing Attacks](https://arxiv.org/abs/1903.10404)
