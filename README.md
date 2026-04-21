# Security Solutions for AI

A comprehensive reference repository covering threats, attack scenarios, concepts, and mitigation techniques across all aspects of AI/ML security.

---

## 📚 Table of Contents

| # | Topic | Description |
|---|-------|-------------|
| 01 | [Prompt Injection](./01-Prompt-Injection/README.md) | Hijacking LLM behaviour via crafted inputs |
| 02 | [Data Poisoning](./02-Data-Poisoning/README.md) | Corrupting training data to manipulate model behaviour |
| 03 | [Adversarial Attacks](./03-Adversarial-Attacks/README.md) | Crafted inputs that fool trained models |
| 04 | [Model Extraction](./04-Model-Extraction/README.md) | Stealing a model by querying its API |
| 05 | [Privacy Attacks](./05-Privacy-Attacks/README.md) | Membership inference & model inversion |
| 06 | [Jailbreaking](./06-Jailbreaking/README.md) | Bypassing safety guidelines in LLMs |
| 07 | [Supply Chain Attacks](./07-Supply-Chain-Attacks/README.md) | Malicious models, datasets, and libraries |
| 08 | [Backdoor / Trojan Attacks](./08-Backdoor-Attacks/README.md) | Hidden triggers embedded in models |
| 09 | [Hallucination Exploitation](./09-Hallucination-Exploitation/README.md) | Weaponising AI hallucinations |
| 10 | [Denial of Service](./10-Denial-of-Service/README.md) | Resource exhaustion of AI services |

---

## 🛡️ Threat Modeling for AI Applications

A complete, evergreen guide to **structured threat modeling** for AI/ML systems — from first principles to hands-on walkthroughs for five distinct AI architectures.

| # | Scenario | Key Risks |
|---|----------|-----------|
| [Fundamentals](./docs/threat-modeling/00-fundamentals.md) | DFDs, STRIDE, trust boundaries, attacker profiles | All AI systems |
| [01](./docs/threat-modeling/01-rag-chatbot.md) | **RAG Chatbot** over internal documents | Prompt injection, retrieval poisoning, data exfiltration |
| [02](./docs/threat-modeling/02-code-assistant.md) | **Code Assistant / Copilot-like Tool** | Malicious code suggestion, secret leakage, supply chain |
| [03](./docs/threat-modeling/03-document-ocr-pipeline.md) | **Document OCR & Classification Pipeline** | Adversarial documents, PII leakage, model inversion |
| [04](./docs/threat-modeling/04-ai-saas-platform.md) | **Multi-Tenant AI SaaS Platform** | Tenant isolation, cross-tenant inference, model theft |
| [05](./docs/threat-modeling/05-llm-customer-service-agent.md) | **LLM Customer-Service Agent with Tool Access** | Tool misuse, indirect prompt injection, privilege escalation |

→ **[Open the Threat Modeling Guide](./docs/threat-modeling/README.md)**

---

## 🏗️ Repository Structure

```
Security-Solutions-for-AI/
├── README.md                        ← You are here
├── docs/
│   └── threat-modeling/             ← Threat modeling guide & walkthroughs
│       ├── README.md                ← Index & navigation
│       ├── 00-fundamentals.md       ← DFD, STRIDE, trust boundaries, process
│       ├── 01-rag-chatbot.md        ← RAG chatbot threat model
│       ├── 02-code-assistant.md     ← Code assistant threat model
│       ├── 03-document-ocr-pipeline.md ← OCR pipeline threat model
│       ├── 04-ai-saas-platform.md   ← Multi-tenant SaaS threat model
│       └── 05-llm-customer-service-agent.md ← Agent with tools threat model
├── 01-Prompt-Injection/
│   ├── README.md                    ← Concept, explanation, scenarios
│   ├── examples/                    ← Attack demos (for research/education)
│   └── mitigations/                 ← Defence code & techniques
├── 02-Data-Poisoning/
│   ├── README.md
│   ├── examples/
│   └── mitigations/
├── 03-Adversarial-Attacks/
│   ├── README.md
│   ├── examples/
│   └── mitigations/
├── 04-Model-Extraction/
│   ├── README.md
│   ├── examples/
│   └── mitigations/
├── 05-Privacy-Attacks/
│   ├── README.md
│   ├── examples/
│   └── mitigations/
├── 06-Jailbreaking/
│   ├── README.md
│   ├── examples/
│   └── mitigations/
├── 07-Supply-Chain-Attacks/
│   ├── README.md
│   ├── examples/
│   └── mitigations/
├── 08-Backdoor-Attacks/
│   ├── README.md
│   ├── examples/
│   └── mitigations/
├── 09-Hallucination-Exploitation/
│   ├── README.md
│   ├── examples/
│   └── mitigations/
└── 10-Denial-of-Service/
    ├── README.md
    ├── examples/
    └── mitigations/
```

---

## ⚠️ Disclaimer

All attack examples in this repository are **strictly for educational and research purposes**.  
Do **not** use them against systems you do not own or have explicit permission to test.

---

## 🤝 Contributing

1. Fork the repository.
2. Add a new threat folder following the existing structure.
3. Include: concept explanation, realistic attack scenario, working mitigation code.
4. Open a pull request.

---

## 📄 License

MIT — see [LICENSE](./LICENSE) for details.
