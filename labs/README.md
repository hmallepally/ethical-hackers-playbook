# The Ethical Hacker's Playbook: AI on Our Side (2026 Edition)
### Official Hands-On Practice Labs & Companion Code Repository

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OWASP GenAI 2026](https://img.shields.io/badge/OWASP-GenAI%20LLM%20Top%2010%20(2026)-red.svg)](https://genai.owasp.org)
[![Docker Ready](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](docker-compose.yml)

This repository contains the complete hands-on practice labs, automated adversarial evaluation harnesses, and enterprise AI policy templates accompanying the book ***The Ethical Hacker's Playbook: AI on Our Side*** by Harinath Mallepally.

---

## ⚡ Quick Start (One-Click Lab Launch)

### 1. Launch Target Infrastructure via Docker
Spin up the local vulnerable web applications (OWASP Juice Shop, DVWA), local LLM inference endpoint (Ollama), and vector database (Qdrant) with a single command:

```bash
docker compose up -d
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

---

## 📂 Chapter Lab Directory

| Chapter | Lab Directory | Focus Area | Key Tooling / Scripts |
| :--- | :--- | :--- | :--- |
| **Ch. 3** | [`lab-03-ai-recon-pipeline/`](lab-03-ai-recon-pipeline/) | OSINT & Shadow AI Reconnaissance | `recon_pipeline.py` (Cert transparency & Ollama/vLLM scanner) |
| **Ch. 4** | [`lab-04-ai-vuln-assessment/`](lab-04-ai-vuln-assessment/) | AI Vulnerability Assessment & Chaining | `vuln_scanner.py` (OWASP GenAI Top 10 & BOLA exploit chainer) |
| **Ch. 5** | [`lab-05-purple-team/`](lab-05-purple-team/) | Automated AI Red Teaming & Purple Eval | `purple_eval.py`, `promptfooconfig.yaml` (Promptfoo & Garak) |
| **Ch. 6** | [`lab-06-ai-alert-classifier/`](lab-06-ai-alert-classifier/) | AI-Native SOC Triage & SOAR Agent | `alert_classifier.py` (MITRE ATT&CK correlation & sub-min response) |
| **Ch. 7** | [`lab-07-governance-template/`](lab-07-governance-template/) | Enterprise AI Policy & Compliance | `enterprise_ai_security_policy.md` (EU AI Act & NIST AI 600-1) |
| **Ch. 8** | [`lab-08-home-lab-setup/`](lab-08-home-lab-setup/) | Architecture & Home Lab Guide | Architecture blueprints & practice roadmaps |

---

## 🧪 Running Labs Offline (Simulation Mode)

All Python lab scripts include a `--mock` flag that allows you to explore findings, telemetry outputs, and exploit chains immediately without needing active target networks or cloud API keys:

```bash
# Lab 3: Reconnaissance
python lab-03-ai-recon-pipeline/recon_pipeline.py --target example.com --mock

# Lab 4: Vulnerability Scanner & Chaining Engine
python lab-04-ai-vuln-assessment/vuln_scanner.py --target http://localhost:3000 --mock

# Lab 5: Purple Team AI Evaluation
python lab-05-purple-team/purple_eval.py --mock

# Lab 6: SOC Alert Classifier
python lab-06-ai-alert-classifier/alert_classifier.py
```

---

## ⚖️ Ethical Use & Authorization Notice
All scripts and configurations in this repository are developed strictly for authorized security testing, educational research, and defensive hardening. Only execute active scans against networks, applications, and endpoints where you have obtained explicit, written authorization.
