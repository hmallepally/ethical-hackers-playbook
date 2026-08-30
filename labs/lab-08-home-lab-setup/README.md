# Lab 8.1: Modern Ethical Hacking & AI Security Home Lab Setup
*The Ethical Hacker's Playbook — Chapter 8 (2026 Edition)*

Build a professional-grade offensive and defensive testing environment on your local machine using Docker, Kali Linux, and local AI inference stacks.

---

## 🏗️ Architecture Blueprint

```
 ┌─────────────────────────────────────────────────────────────┐
 │                LOCAL DOCKER LAB ENVIRONMENT                 │
 ├─────────────────────────────────────────────────────────────┤
 │                                                             │
 │  [Attacker Tools]                [Target Applications]      │
 │  • Kali Linux Container          • OWASP Juice Shop (:3000) │
 │  • Promptfoo / Garak CLI         • DVWA Web App (:8080)     │
 │                                                             │
 │  [AI Inference & Vector Stack]                              │
 │  • Ollama Local LLM (:11434) (Llama 3 / Mistral)            │
 │  • Qdrant Vector Database (:6333)                           │
 │                                                             │
 │  [Telemetry & Defense]                                      │
 │  • NeMo Guardrails Proxy (:8000)                            │
 │  • Wazuh / Elasticsearch Agent                              │
 │                                                             │
 └─────────────────────────────────────────────────────────────┘
```

---

## 🚀 One-Click Launch with Docker Compose

From the `labs/` directory, launch the entire practice environment with a single command:

```bash
docker compose up -d
```

### Verified Service Ports:
- **OWASP Juice Shop**: `http://localhost:3000`
- **Damn Vulnerable Web App (DVWA)**: `http://localhost:8080`
- **Ollama Inference Engine**: `http://localhost:11434`
- **Qdrant Vector Database Dashboard**: `http://localhost:6333/dashboard`

---

## 🎯 Practice Challenges
1. **Lab 3.1 Practice**: Run `python labs/lab-03-ai-recon-pipeline/recon_pipeline.py --target localhost` to discover the exposed Ollama and Qdrant instances.
2. **Lab 4.1 Practice**: Run `python labs/lab-04-ai-vuln-assessment/vuln_scanner.py --target http://localhost:3000` against Juice Shop.
3. **Lab 5.1 Practice**: Red-team the local Ollama LLM using `python labs/lab-05-purple-team/purple_eval.py`.
4. **Cloud Platforms**: Complement your home lab with **PortSwigger Web Security Academy** and **Hack The Box**.
