"""
Lab 3.1: AI-Powered OSINT & Shadow AI Reconnaissance Pipeline
The Ethical Hacker's Playbook — Chapter 3 (2026 Edition)

This lab demonstrates how to build an AI-augmented reconnaissance pipeline
that processes OSINT data, discovers exposed Shadow AI inference endpoints,
and uses an LLM to generate a prioritized attack surface report.

REQUIREMENTS:
    pip install requests beautifulsoup4 pydantic

USAGE:
    # Live run against an authorized target
    python recon_pipeline.py --target example.com

    # Offline simulation / demo mode
    python recon_pipeline.py --target example.com --mock

⚠️  IMPORTANT: Only run active scans against systems you have explicit authorization to test.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


@dataclass
class AIEndpointFinding:
    service: str
    port: int
    url: str
    is_exposed: bool
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconResults:
    target_domain: str
    timestamp: str
    subdomains: List[str] = field(default_factory=list)
    web_technologies: Dict[str, Any] = field(default_factory=dict)
    ai_endpoints: List[AIEndpointFinding] = field(default_factory=list)
    ai_risk_synthesis: Optional[str] = None


# -------------------------------------------------------------------
# Step 1: Subdomain Enumeration via Certificate Transparency
# -------------------------------------------------------------------

def enumerate_subdomains(domain: str, mock: bool = False) -> List[str]:
    """Enumerate subdomains via crt.sh certificate transparency logs."""
    if mock:
        return [
            f"api.{domain}",
            f"staging-internal.{domain}",
            f"ai-gateway.{domain}",
            f"dev-vector-db.{domain}",
            f"vpn.{domain}",
            f"auth.{domain}"
        ]

    import requests
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and "*" not in sub:
                        subdomains.add(sub)
            return sorted(subdomains)
    except Exception as e:
        print(f"  [!] crt.sh query error ({e}). Falling back to baseline targets.")
    return [f"api.{domain}", f"staging.{domain}"]


# -------------------------------------------------------------------
# Step 2: Web Technology & Header Fingerprinting
# -------------------------------------------------------------------

def fingerprint_technologies(url: str, mock: bool = False) -> Dict[str, Any]:
    """Analyze HTTP headers and HTML markup to infer framework and server versions."""
    if mock:
        return {
            "server": "nginx/1.24.0",
            "headers": {
                "server": "nginx/1.24.0",
                "x-powered-by": "Next.js",
                "access-control-allow-origin": "*"
            },
            "technologies": ["Next.js", "React", "OpenAPI/Swagger", "FastAPI"]
        }

    import requests
    from bs4 import BeautifulSoup

    result: Dict[str, Any] = {"server": "Unknown", "headers": {}, "technologies": []}
    target_url = f"https://{url}" if not url.startswith("http") else url

    try:
        resp = requests.get(target_url, timeout=8, allow_redirects=True, verify=False)
        result["server"] = resp.headers.get("Server", "Unknown")
        result["headers"] = {
            k.lower(): v for k, v in resp.headers.items()
            if k.lower() in ("x-powered-by", "x-aspnet-version", "x-generator", "server", "access-control-allow-origin")
        }

        soup = BeautifulSoup(resp.text, "html.parser")
        for script in soup.find_all("script", src=True):
            src = script["src"].lower()
            for tech in ["react", "vue", "angular", "next", "tailwind", "jquery"]:
                if tech in src and tech.capitalize() not in result["technologies"]:
                    result["technologies"].append(tech.capitalize())

    except Exception as e:
        result["error"] = str(e)

    return result


# -------------------------------------------------------------------
# Step 3: Shadow AI & Inference Endpoint Probing
# -------------------------------------------------------------------

def probe_shadow_ai_endpoints(domain: str, mock: bool = False) -> List[AIEndpointFinding]:
    """Probe for exposed local/cloud LLM inference ports and vector databases."""
    ai_ports = [
        ("Ollama Inference", 11434, "/api/tags"),
        ("vLLM / FastChat", 8000, "/v1/models"),
        ("Qdrant Vector DB", 6333, "/collections"),
        ("ChromaDB Heartbeat", 8000, "/api/v1/heartbeat")
    ]

    findings: List[AIEndpointFinding] = []

    if mock:
        findings.append(
            AIEndpointFinding(
                service="Ollama Local LLM",
                port=11434,
                url=f"http://ai-gateway.{domain}:11434/api/tags",
                is_exposed=True,
                details={"models": ["llama3:8b", "mistral:7b"], "auth_required": False}
            )
        )
        findings.append(
            AIEndpointFinding(
                service="Qdrant Vector DB",
                port=6333,
                url=f"http://dev-vector-db.{domain}:6333/collections",
                is_exposed=True,
                details={"collections": ["internal_kb", "employee_handbook"], "auth_required": False}
            )
        )
        return findings

    import requests
    for service_name, port, path in ai_ports:
        target_url = f"http://{domain}:{port}{path}"
        try:
            resp = requests.get(target_url, timeout=3)
            if resp.status_code in (200, 401, 403):
                findings.append(
                    AIEndpointFinding(
                        service=service_name,
                        port=port,
                        url=target_url,
                        is_exposed=(resp.status_code == 200),
                        details={"status_code": resp.status_code}
                    )
                )
        except Exception:
            pass

    return findings


# -------------------------------------------------------------------
# Step 4: AI Attack Surface Synthesis & Risk Prioritization
# -------------------------------------------------------------------

def synthesize_recon_with_llm(results: ReconResults, mock: bool = False) -> str:
    """Send structured findings to an LLM to generate attack paths and risk chains."""
    prompt = f"""You are a Lead Adversary Emulation specialist. Analyze the following reconnaissance data for domain: {results.target_domain}.

### Discovered Subdomains ({len(results.subdomains)}):
{json.dumps(results.subdomains, indent=2)}

### Web Technology Profile:
{json.dumps(results.web_technologies, indent=2)}

### AI & Vector Infrastructure Findings:
{json.dumps([asdict(f) for f in results.ai_endpoints], indent=2)}

Task:
1. Provide the top 3 highest-probability attack chains (mapping to MITRE ATT&CK & ATLAS).
2. Assess risks associated with discovered Shadow AI / Vector stores (e.g. Indirect Prompt Injection, BOLA).
3. Outline immediate defensive remediation actions for the Blue Team.
"""

    if mock:
        return f"""[SIMULATION - AI RECON SYNTHESIS]
Target: {results.target_domain}

1. PRIORITIZED ATTACK VECTORS:
   • Chain 1 (ATLAS: AML.TA0001 / AML.TA0002): Unauthenticated Ollama on `ai-gateway.{results.target_domain}:11434`.
     Attacker can issue direct prompts to local LLMs, extract system instructions, or exploit unconstrained GPU inference for token exhaustion.
   • Chain 2 (OWASP LLM06 / LLM08): Exposed Qdrant Vector Store on `dev-vector-db.{results.target_domain}:6333`.
     Direct access to `/collections` enables exfiltration of private vector embeddings (`internal_kb`) containing sensitive corporate documentation.
   • Chain 3 (MITRE ATT&CK T1190): Potential BOLA / Authorization flaw in Next.js + FastAPI backend behind `api.{results.target_domain}`.

2. DEFENSIVE BLUE TEAM ACTIONS:
   • Immediately bind Ollama and Qdrant endpoints to `127.0.0.1` or place behind mTLS/Zero Trust reverse proxy.
   • Implement network segmentation isolating AI experimental clusters from production databases.
"""

    # Optional cloud LLM caller if API key is present
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        try:
            import requests
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are a senior red team specialist producing structured recon briefings."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2
            }
            res = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=20)
            if res.status_code == 200:
                return res.json()["choices"][0]["message"]["content"]
        except Exception as err:
            print(f"  [!] Cloud LLM invocation failed: {err}")

    return f"[Prompt Prepared for Manual Analysis]\n\n{prompt}"


# -------------------------------------------------------------------
# Main Pipeline Orchestration
# -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Lab 3.1: AI-Augmented OSINT & Shadow AI Recon Pipeline")
    parser.add_argument("--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("--mock", action="store_true", help="Run in offline simulation mode with mock telemetry")
    args = parser.parse_args()

    print(f"\n============================================================")
    print(f"🛡️  AI-POWERED RECONNAISSANCE PIPELINE (2026 Edition)")
    print(f"   Target: {args.target} | Mode: {'SIMULATION' if args.mock else 'LIVE ACTIVE SCAN'}")
    print(f"============================================================\n")

    # 1. Subdomains
    print("[1/4] Running Certificate Transparency Subdomain Enumeration...")
    subdomains = enumerate_subdomains(args.target, mock=args.mock)
    print(f"      Discovered {len(subdomains)} active endpoints.")

    # 2. Technology Fingerprint
    print("[2/4] Fingerprinting Web Stack & Security Headers...")
    tech = fingerprint_technologies(args.target, mock=args.mock)
    print(f"      Server: {tech.get('server')} | Tech: {', '.join(tech.get('technologies', []))}")

    # 3. AI & Vector Store Probing
    print("[3/4] Enumerating Shadow AI Inference & Vector Stores...")
    ai_endpoints = probe_shadow_ai_endpoints(args.target, mock=args.mock)
    print(f"      Discovered {len(ai_endpoints)} AI-related endpoints.")

    # Compile Results
    results = ReconResults(
        target_domain=args.target,
        timestamp=datetime.now(timezone.utc).isoformat(),
        subdomains=subdomains,
        web_technologies=tech,
        ai_endpoints=ai_endpoints
    )

    # 4. LLM Synthesis
    print("[4/4] Synthesizing findings with AI Attack Surface Reasoner...")
    synthesis = synthesize_recon_with_llm(results, mock=args.mock)
    results.ai_risk_synthesis = synthesis

    # Output JSON artifact
    out_file = f"recon_report_{args.target.replace('.', '_')}.json"
    with open(out_file, "w") as f:
        json.dump(asdict(results), f, indent=2)

    print(f"\n✅ Reconnaissance complete! Report generated: {out_file}\n")
    print(synthesis)


if __name__ == "__main__":
    main()

