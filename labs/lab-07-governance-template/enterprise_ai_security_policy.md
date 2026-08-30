# Enterprise Generative AI Security & Governance Policy
**Document ID:** SEC-POL-AI-2026-01  
**Target Organization:** [ENTERPRISE_NAME] (e.g. CyberShield MSSP)  
**Effective Date:** 2026-08-30 | **Status:** Approved / Enforced  
**Compliance Mandates:** EU AI Act (Regulation 2024/1689), NIST AI 600-1, ISO/IEC 42001, SOC 2 Type II  

---

## 1. Purpose & Scope
This policy establishes mandatory security, governance, and operational standards for all employees, contractors, and automated autonomous agents interacting with Large Language Models (LLMs), Generative AI tools, and Model Context Protocol (MCP) integrations.

---

## 2. Prohibition of Shadow AI Infrastructure
1. **Unregistered Inference Endpoints**: Employees are strictly prohibited from exposing unauthenticated local or cloud inference instances (e.g., Ollama, vLLM, LM Studio) to corporate networks or public interfaces.
2. **Third-Party Model Usage**: Only AI tools listed on the **Approved AI Registry** may be used for corporate tasks.
3. **Data Ingestion Gateways**: No customer Personally Identifiable Information (PII), proprietary source code, or unreleased vulnerability findings may be submitted to public consumer AI interfaces (e.g., non-enterprise tiers).

---

## 3. Data Classification & Prompt Hygiene Matrix

| Data Classification Tier | Consumer AI Tools (ChatGPT, Claude Free) | Enterprise AI Gateways (with Zero Data Retention) | Local Isolated Air-Gapped Models |
|---|---|---|---|
| **Public / Marketing Data** | ✅ Permitted | ✅ Permitted | ✅ Permitted |
| **Internal Business Operations** | ❌ Prohibited | ✅ Permitted | ✅ Permitted |
| **Customer PII & Confidential Data** | ❌ Prohibited | ⚠️ Permitted with Token Sanitization | ✅ Permitted |
| **Vulnerability Disclosures & Exploit Code** | ❌ Prohibited | ❌ Prohibited | ✅ Permitted |
| **Production Cryptographic Keys & API Tokens** | ❌ Strictly Prohibited | ❌ Strictly Prohibited | ❌ Strictly Prohibited |

---

## 4. EU AI Act High-Risk AI System Checklist (Articles 9, 14, 15)

All automated offensive and defensive security AI tools that execute autonomous actions must satisfy:

- [ ] **Risk Management System (Article 9)**: Continuous identification, estimation, and mitigation of algorithmic bias, hallucinations, and denial-of-service failure states.
- [ ] **Data Governance & Integrity (Article 10)**: Verification that training and RAG retrieval sets are free from data poisoning, unauthorized PII, or malicious promptware.
- [ ] **Human-in-the-Loop (HITL) Gateways (Article 14)**: Technical architecture ensures that any destructive or high-impact containment action (e.g., server shutdown, mass session invalidation) requires explicit human operator confirmation.
- [ ] **Cybersecurity & Robustness (Article 15)**: Resilience against adversarial prompt injection, jailbreaking, and evasion attacks validated via continuous purple-team benchmarking.

---

## 5. Model Context Protocol (MCP) & Tool-Calling Security Rules
1. **Least Privilege Tool Definitions**: Agents must only be provisioned with the minimal API capabilities required for their function (read-only by default).
2. **Deterministic Parameter Validation**: Tool arguments must be strictly typed and validated using Pydantic / JSON schemas before execution.
3. **Sandbox Isolation**: Any tool capable of code execution (Python, Bash) must execute in an ephemeral, unprivileged container with network egress restrictions.
