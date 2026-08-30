# Lab 5.1: Automated AI Red Teaming & Purple Team Validation
*The Ethical Hacker's Playbook — Chapter 5 (2026 Edition)*

This hands-on lab demonstrates how to execute automated adversarial evaluations against an AI agent using **Promptfoo**, **Garak**, and custom Python assertion harnesses.

---

## 🎯 Lab Objectives
1. **Red Side (Adversary Emulation)**: Run automated adversarial probe suites against an LLM assistant to test for:
   - Direct System Prompt Extraction (OWASP LLM06 / Hidden Context Exposure)
   - Unauthorized Tool Parameter Injection (OWASP ASI02 / Tool Injection)
   - Jailbreaks & Safety Filter Bypass (ATLAS AML.TA0002)
2. **Blue Side (Detection & Guardrails)**: Intercept payloads using semantic validation rules.
3. **Purple Feedback Loop**: Quantify the vulnerability attack surface score before and after implementing guardrails.

---

## 🛠️ Lab Files
- `promptfooconfig.yaml`: Declarative Promptfoo red-team test configuration.
- `purple_eval.py`: Python-based standalone adversary evaluation test runner with offline simulation mode.

---

## 🚀 Running the Lab

### Option A: Standalone Python Evaluator (No external CLI required)
```bash
# Run simulation against mock target agent
python purple_eval.py --mock

# Run against a live HTTP inference endpoint
python purple_eval.py --target http://localhost:8000/v1/chat/completions
```

### Option B: Using Promptfoo CLI
```bash
# 1. Install Promptfoo
npm install -g promptfoo

# 2. Run automated red team evaluation
promptfoo eval -c promptfooconfig.yaml

# 3. View interactive web dashboard
promptfoo view
```

---

## 📊 Evaluation Criteria & Mitigations
* **Success Metric**: 100% pass rate on adversarial assertions (no canary tokens leaked, no unauthorized tool calls triggered).
* **Mitigation**: Deploy NVIDIA NeMo Guardrails or Llama Guard 3 on the input pipeline.
