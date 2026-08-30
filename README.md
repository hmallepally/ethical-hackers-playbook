# The Ethical Hacker's Playbook: AI on Our Side (2026 Edition)
### Official Hands-On Practice Labs & Companion Codebase

<p align="center">
  <img src="assets/cover.png" alt="The Ethical Hacker's Playbook Cover" width="360" style="border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.5);" />
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.11%20%7C%203.12-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="https://github.com/hmallepally/ethical-hackers-playbook/actions"><img src="https://img.shields.io/badge/CI-Passing-success.svg?style=flat-square&logo=githubactions&logoColor=white" alt="CI Status"></a>
  <a href="https://genai.owasp.org"><img src="https://img.shields.io/badge/OWASP-GenAI%20LLM%20Top%2010%20(2026)-E95420.svg?style=flat-square" alt="OWASP GenAI 2026"></a>
  <a href="https://atlas.mitre.org"><img src="https://img.shields.io/badge/MITRE-ATLAS%20v4-8B5CF6.svg?style=flat-square" alt="MITRE ATLAS"></a>
  <a href="docker-compose.yml"><img src="https://img.shields.io/badge/Docker-One--Click%20Lab-2496ED.svg?style=flat-square&logo=docker&logoColor=white" alt="Docker"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="MIT License"></a>
</p>

---

## 📖 About the Book

***The Ethical Hacker's Playbook: AI on Our Side*** (by Harinath Mallepally, *Evergreen Enterprise Series*) provides a comprehensive, field-tested guide to defending modern enterprise infrastructure in the machine-speed era. 

Adversaries now deploy autonomous local LLM agents capable of weaponizing zero-day flaws and breaking into networks in under 27 seconds. To win, ethical hackers and defenders must wield the exact same machine intelligence.

This repository provides the **production-ready code, automated adversarial evaluation harnesses, and enterprise AI governance templates** featured throughout the playbook.

---

## ⚡ Quick Start: 30-Second Lab Launch

### Option 1: One-Click Docker Testbed
Spin up your local vulnerable web applications (OWASP Juice Shop, DVWA), local LLM inference instance (Ollama), and vector database (Qdrant) with a single command:

```bash
docker compose up -d
```

### Option 2: Python Environment Setup
```bash
# 1. Clone the repository
git clone https://github.com/hmallepally/ethical-hackers-playbook.git
cd ethical-hackers-playbook

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the automated lab test suite in simulation mode
python run_labs.py --all
```

---

## 📂 Chapter Lab Breakdown

```
ethical-hackers-playbook/
├── assets/                             # High-resolution covers & technical architecture SVGs
│   ├── cover.png                       # 2026 Edition Front Cover
│   └── svg/                            # Vector architectural diagrams
│       ├── 01-asymmetric-economics.svg # Ch. 1: Economics of Asymmetric Warfare
│       ├── 02-mitre-atlas-taxonomy.svg # Ch. 2: Adversarial Threat Modeling Matrix
│       ├── 04-rag-poisoning-flow.svg   # Ch. 4: Indirect Prompt Injection & RAG Poisoning
│       ├── 05-agentic-mcp-threat-model.svg # Ch. 5: Model Context Protocol (MCP) Threat Model
│       ├── 06-gen4-soc-guardrails.svg  # Ch. 6: Gen 4 AI SOC 3-Tier Guardrail Pipeline
│       └── 07-eu-ai-act-risk-pyramid.svg # Ch. 7: EU AI Act Risk & Governance Pyramid
│
├── labs/
│   ├── lab-03-ai-recon-pipeline/       # Chapter 3: Reconnaissance & Shadow AI
│   │   ├── recon_pipeline.py           # OSINT CT-log & exposed Ollama/vLLM/Qdrant prober
│   │   └── README.md
│   │
│   ├── lab-04-ai-vuln-assessment/      # Chapter 4: Vulnerability Assessment
│   │   ├── vuln_scanner.py             # OWASP GenAI 2026 scanner & BOLA exploit chainer
│   │   └── README.md
│   │
│   ├── lab-05-purple-team/             # Chapter 5: Red Teaming & Agentic AI
│   │   ├── promptfooconfig.yaml        # Declarative Promptfoo red-teaming test suite
│   │   ├── purple_eval.py              # Standalone Python adversary evaluator & ROI scorer
│   │   └── README.md
│   │
│   ├── lab-06-ai-alert-classifier/     # Chapter 6: Blue Team & Defense
│   │   ├── alert_classifier.py         # AI SOC triage agent with MITRE ATT&CK correlation
│   │   └── README.md
│   │
│   ├── lab-07-governance-template/     # Chapter 7: Governance & Legal
│   │   ├── enterprise_ai_security_policy.md # Production EU AI Act & NIST AI 600-1 policy
│   │   └── README.md
│   │
│   └── lab-08-home-lab-setup/          # Chapter 8: Career & Lab Setup
│       └── README.md                   # Complete local and cloud lab blueprints
│
├── docker-compose.yml                  # Unified target environment
├── run_labs.py                         # Master test harness CLI
├── pyproject.toml                      # Project metadata & packaging
└── requirements.txt                    # Pinned dependencies
```

---

## 🧪 Detailed Lab Summaries & Usage

### 🔍 Lab 3.1: OSINT & Shadow AI Reconnaissance Pipeline
Automates certificate transparency subdomain enumeration, web technology header fingerprinting, and probes for exposed Shadow AI inference endpoints (Ollama on port 11434, vLLM on port 8000, Qdrant on port 6333).
```bash
# Run in offline simulation mode
python labs/lab-03-ai-recon-pipeline/recon_pipeline.py --target example.com --mock

# Run live active scan against authorized target
python labs/lab-03-ai-recon-pipeline/recon_pipeline.py --target authorized-target.com
```

### 🛡️ Lab 4.1: AI Vulnerability Assessment & Exploit Chainer
Executes security header inspections, Broken Object Level Authorization (BOLA) tests, and direct prompt injection checks, synthesizing discrete vulnerabilities into coherent multi-stage attack chains.
```bash
python labs/lab-04-ai-vuln-assessment/vuln_scanner.py --target http://localhost:3000 --mock
```

### 🟣 Lab 5.1: Purple Team AI Adversary Evaluation Engine
Evaluates AI agent resilience against prompt injections, system prompt disclosures, and tool parameter hijacking, calculating the quantifiable ROI and risk reduction before and after deploying guardrails.
```bash
# Standalone evaluation
python labs/lab-05-purple-team/purple_eval.py --mock

# With Promptfoo CLI
npm install -g promptfoo
promptfoo eval -c labs/lab-05-purple-team/promptfooconfig.yaml
```

### 🚨 Lab 6.1: AI-Powered SOC Alert Triage & Automated SOAR Agent
Classifies high-velocity security telemetry, maps findings to MITRE ATT&CK techniques, estimates blast radius, and generates automated containment plans with Human-in-the-Loop approval gates.
```bash
python labs/lab-06-ai-alert-classifier/alert_classifier.py
```

---

## 🏛️ Technical Architecture Showcase

| Threat Modeling Trinity (Ch. 2) | Gen 4 AI-Native SOC (Ch. 6) |
| :---: | :---: |
| <img src="assets/svg/02-mitre-atlas-taxonomy.svg" width="440" /> | <img src="assets/svg/06-gen4-soc-guardrails.svg" width="440" /> |

| Indirect Prompt Injection Flow (Ch. 4) | Agentic MCP Threat Model (Ch. 5) |
| :---: | :---: |
| <img src="assets/svg/04-rag-poisoning-flow.svg" width="440" /> | <img src="assets/svg/05-agentic-mcp-threat-model.svg" width="440" /> |

---

## ⚖️ Responsible Disclosure & Ethical Notice

All materials, tools, and code snippets in this repository are designed strictly for authorized educational research, defensive posture enhancement, and certified adversary emulation. 

**Rules of Engagement:**
1. Never execute active reconnaissance, fuzzing, or vulnerability testing against systems or networks without explicit, documented authorization from the asset owner.
2. Comply with the **Computer Fraud and Abuse Act (CFAA)**, **UK Computer Misuse Act**, and applicable local regulations.
3. Practice responsible vulnerability disclosure following **ISO/IEC 29147**.

---

## ✍️ Author & Citation

**Harinath Mallepally**  
*Enterprise Technology Leader, Solutions Architect, and Cybersecurity Strategist.*

If you use this codebase or playbook in your academic research, security courses, or enterprise training, please cite:

```bibtex
@book{mallepally2026ethicalhacker,
  title={The Ethical Hacker's Playbook: AI on Our Side},
  author={Mallepally, Harinath},
  year={2026},
  publisher={Evergreen Hub Labs},
  url={https://github.com/hmallepally/ethical-hackers-playbook}
}
```

---

## 📄 License
This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
