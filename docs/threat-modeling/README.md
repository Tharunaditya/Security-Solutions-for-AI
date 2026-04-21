# 🛡️ Threat Modeling for AI Applications

> **A complete, evergreen guide** — from first principles to hands-on walkthroughs for five distinct AI architectures.  
> Designed so that any reader — student, practitioner, or security engineer — can pick this up and immediately start building safer AI systems.

---

## 📖 What Is Threat Modeling?

Threat modeling is a **structured process** for identifying *what can go wrong* in a system, *who might cause it*, and *how you can prevent or detect it*. Applied to AI/ML systems, it surfaces risks that traditional application security reviews often miss — model theft, data poisoning, prompt injection, indirect adversarial attacks, and more.

This guide follows a **four-question framework**:

| Question | Purpose |
|----------|---------|
| **What are we building?** | Understand the system — components, data flows, trust boundaries |
| **What can go wrong?** | Enumerate threats using STRIDE or LINDDUN |
| **What are we going to do about it?** | Propose and prioritise mitigations |
| **Did we do a good enough job?** | Validate with tests, reviews, and monitoring |

---

## 📚 Contents

### 🧠 Part 0 — Fundamentals

| Document | Description |
|----------|-------------|
| [00 — Threat Modeling Fundamentals](./00-fundamentals.md) | DFDs, STRIDE, trust boundaries, data assets — everything you need before the walkthroughs |

---

### 🔬 Part 1 — Walkthroughs by AI Architecture

| # | Scenario | Key Risks Covered |
|---|----------|-------------------|
| [01](./01-rag-chatbot.md) | **RAG Chatbot** over internal documents | Prompt injection, retrieval poisoning, data exfiltration via LLM output |
| [02](./02-code-assistant.md) | **Code Assistant / Copilot-like Tool** | Malicious code suggestion, secret leakage, supply-chain via generated code |
| [03](./03-document-ocr-pipeline.md) | **Document OCR & Classification Pipeline** | Adversarial document attacks, PII leakage, model inversion |
| [04](./04-ai-saas-platform.md) | **Multi-Tenant AI SaaS Platform** | Tenant isolation, cross-tenant inference, model/data exfiltration |
| [05](./05-llm-customer-service-agent.md) | **LLM Customer-Service Agent with Tool Access** | Tool misuse, indirect prompt injection, privilege escalation via external APIs |

---

## 🗺️ How to Navigate This Guide

```
docs/threat-modeling/
├── README.md                        ← You are here — index & orientation
├── 00-fundamentals.md               ← Read this first
├── 01-rag-chatbot.md
├── 02-code-assistant.md
├── 03-document-ocr-pipeline.md
├── 04-ai-saas-platform.md
└── 05-llm-customer-service-agent.md
```

### Suggested Reading Order

1. **New to threat modeling?** → Start with [Fundamentals](./00-fundamentals.md), then pick any walkthrough.
2. **Familiar with STRIDE?** → Jump straight to the walkthrough matching your architecture.
3. **Building a new AI product?** → Read the fundamentals, then adapt the closest walkthrough to your system.

---

## ⚡ Quick-Start Cheatsheet

```
1. Draw a Data Flow Diagram (DFD)
2. Mark trust boundaries (where data crosses privilege zones)
3. List assets (what has value to an attacker?)
4. Apply STRIDE to each data flow and component
5. Prioritise by likelihood × impact
6. Assign mitigations (technical + process + monitoring)
7. Schedule re-review when architecture changes
```

---

## 🔗 Additional Resources

- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — AI Threat Matrix](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/system/files/documents/2023/01/26/NIST.AI.100-1.pdf)
- [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
- [Google SAIF — Secure AI Framework](https://saif.google/)
- [AI Security & Privacy Guide — ENISA](https://www.enisa.europa.eu/publications/artificial-intelligence-cybersecurity-challenges)

---

> **Contributing:** Found a gap? See a missing AI architecture? Open a PR — add a new walkthrough file following the template in [00-fundamentals.md](./00-fundamentals.md#walkthrough-template).
