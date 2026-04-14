# 10 — Denial of Service (DoS) Against AI Systems

## Concept

**Denial of Service (DoS)** attacks against AI systems aim to degrade or completely prevent the availability of ML inference services. Unlike traditional DoS, AI-specific attacks can be far more efficient — a single crafted input can consume orders of magnitude more resources than a normal request.

---

## Types of AI DoS Attacks

| Type | Target | How |
|------|--------|-----|
| **Algorithmic Complexity Attack** | Inference time | Craft inputs that maximise computational cost |
| **Sponge Examples** | GPU memory / energy | Craft inputs with maximally large activation maps |
| **ReDoS via LLM** | Text tokenization | Long strings causing O(n²) tokenizer behaviour |
| **Context Window Flooding** | LLM context buffer | Force maximum context length to saturate memory |
| **Prompt Bomb** | Recursive expansion | Prompts that trigger recursive/exponential reasoning |
| **Resource Exhaustion via RAG** | Vector DB | Flood retrieval pipeline with near-miss queries |
| **Model Loading Attacks** | Server startup | Trigger frequent model reloads to starve resources |
| **Batch Queue Saturation** | GPU batch queue | Flood async inference queues to block legitimate users |

---

## How It Works

### Sponge Examples
Standard adversarial examples *minimise* perturbation to cross a decision boundary. Sponge examples *maximise* computational cost while keeping the input looking normal:

```
Optimise input x to maximise:
  cost(model(x))     (e.g., number of FLOPS, memory allocations, time)
  subject to:        ||x - x_clean||_∞ ≤ ε

Result: input that looks benign but causes the model to do 100x more work.
```

### Context Window Flooding (LLMs)
```
Attacker sends: 128,000 tokens of carefully structured text that:
  1. Forces the attention mechanism to compute maximum O(n²) attention.
  2. Prevents the KV cache from being reused.
  3. Triggers the maximum number of tool calls in an agent.

Cost to attacker: ~$0.01 (cheap tokens)
Cost to provider: ~$1.00+ in GPU time
```

### ReDoS via Tokenisation
Some tokenizers have O(n²) worst-case complexity for specific input patterns. An attacker sends strings crafted to trigger worst-case tokenization behaviour.

---

## Real-World Scenarios

### Scenario 1 — LLM API Cost Amplification Attack
An attacker sends thousands of max-length prompts to a competitor's LLM API, dramatically increasing their inference costs. If the provider auto-scales, this inflates cloud bills. If not, it degrades service for legitimate users.

### Scenario 2 — Autonomous Agent Infinite Loop
An attacker sends a prompt that causes an AI agent to enter an infinite reasoning loop (repeatedly calling tools, re-reading its own output, etc.), tying up agent capacity.

### Scenario 3 — Vision Model GPU Exhaustion
Images crafted as sponge examples are uploaded to an AI moderation system. Each image takes 50× the normal GPU time to process, saturating the GPU cluster and delaying moderation for legitimate content.

### Scenario 4 — RAG Pipeline Flooding
An attacker floods a retrieval-augmented chatbot with semantically similar queries that each trigger expensive vector similarity searches across millions of documents.

### Scenario 5 — Chatbot Session Abuse
An attacker opens thousands of simultaneous long-context sessions with an AI chatbot, exhausting the server's KV-cache memory and causing out-of-memory errors for all users.

---

## Attack Examples

- [`sponge_examples.py`](./examples/sponge_examples.py) — Demonstrates creating high-energy inputs for a simple model.
- [`context_flood.py`](./examples/context_flood.py) — Simulates context window flooding for an LLM API.
- [`resource_monitor.py`](./examples/resource_monitor.py) — Monitors resource usage during inference to detect anomalies.

---

## Mitigations

| Technique | Description |
|-----------|-------------|
| **Rate limiting** | Hard limits on requests per second / tokens per minute per user/API key. |
| **Input length validation** | Reject or truncate inputs exceeding a safe maximum length. |
| **Timeout enforcement** | Set strict per-request inference time budgets; kill runaway inferences. |
| **Resource monitoring & auto-scaling guardrails** | Alert on abnormal GPU/CPU usage; cap auto-scaling costs. |
| **Query complexity budgets** | Limit the total number of tool calls, retrieval operations, or reasoning steps per request. |
| **Input normalisation** | Normalise / sanitise inputs to remove patterns that trigger worst-case complexity. |
| **Anomaly detection on request patterns** | Flag accounts sending suspiciously similar or maximum-length requests. |
| **Sponge example detection** | Monitor per-request inference time; flag requests that take unusually long. |
| **CAPTCHA / proof-of-work for anonymous access** | Require computational cost on the requester side. |
| **Credit / quota system** | Assign tokens budgets to users; heavy users must pay more or wait. |

### Mitigation Code
- [`rate_limiter.py`](./mitigations/rate_limiter.py) — Token-bucket rate limiter for AI inference endpoints.
- [`inference_timeout.py`](./mitigations/inference_timeout.py) — Per-request timeout wrapper with graceful fallback.
- [`request_anomaly_detector.py`](./mitigations/request_anomaly_detector.py) — Statistical anomaly detection on request patterns.

---

## References

- [Shumailov et al. (2021) — Sponge Examples: Energy-Latency Attacks on Neural Networks](https://arxiv.org/abs/2006.03463)
- [Gao et al. (2018) — Black-box Generation of Adversarial Text Sequences to Evade Deep Learning Classifiers](https://arxiv.org/abs/1801.04354)
- [Greshake et al. (2023) — Not What You've Signed Up For (Indirect Prompt Injection)](https://arxiv.org/abs/2302.12173)
