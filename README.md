# Comply54

**Open-source AI governance policy library for African regulatory compliance.**

Comply54 provides machine-readable, versioned policy packs that enforce African data protection laws and AI agent safety controls. Every pack is validated against a JSON Schema, backed by OPA/Rego tests, and compatible with Microsoft Agent-OS (AGT), LangChain, CrewAI, and AutoGen.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Layer 1 — Universal Agent Safety (all jurisdictions)                   │
│  prompt-injection  pii-leakage  tool-permissions  human-approval        │
│  model-routing                                                           │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 2 — African Regulatory Packs (jurisdiction-specific)             │
│  🇳🇬 NG: ndpa  cbn  bvn-nin  nfiu-aml  pos-geofencing                   │
│  🇰🇪 KE: kdpa                                                            │
│  🇿🇦 ZA: popia                                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

Layer 1 policies always apply. Layer 2 packs are selected by the jurisdiction router based on `customer_country` and `transaction_countries`.

---

## Policy Packs

### Universal Agent Safety Controls

| Pack | Regulation | OWASP Ref |
|------|-----------|-----------|
| `universal/prompt-injection` | OWASP Agentic AI Top 10 — LLM01/ASI01 | LLM01 |
| `universal/pii-leakage` | OWASP LLM06 | LLM06 |
| `universal/tool-permissions` | OWASP LLM08 | LLM08 |
| `universal/human-approval` | OWASP LLM09 | LLM09 |
| `universal/model-routing` | OWASP LLM03/LLM05 | LLM03/LLM05 |

### Nigerian Regulatory Packs

| Pack | Regulation | Authority |
|------|-----------|----------|
| `nigeria/ndpa` | Nigeria Data Protection Act 2023 | NDPC |
| `nigeria/cbn` | CBN Transaction Limits & Tiered KYC | CBN |
| `nigeria/bvn-nin` | CBN BVN Framework; NIBSS Rules | CBN / NIBSS |
| `nigeria/nfiu-aml` | MLPPA 2022 / NFIU AML Guidelines | NFIU |
| `nigeria/pos-geofencing` | CBN Agent Banking Guidelines 2020 | CBN |

### East Africa

| Pack | Regulation | Authority |
|------|-----------|----------|
| `kenya/kdpa` | Kenya Data Protection Act 2019 | ODPC |

### Southern Africa

| Pack | Regulation | Authority |
|------|-----------|----------|
| `south-africa/popia` | POPIA Act 4 of 2013 | Information Regulator ZA |

---

## Quick Start

### With Microsoft Agent-OS (AGT)

```python
from adapters.agt import load_policy, load_jurisdiction

# Load a single pack
policy = load_policy("packages/nigeria/ndpa")

# Load all packs for a jurisdiction (+ universal)
policies = load_jurisdiction("NG")

# Evaluate
result = policy.evaluate({"action": "export_data", "output": ""})
```

### With LangChain / LangGraph

```python
from adapters.langchain import compliance_node

# Build a compliance node for your LangGraph graph
node = compliance_node([
    "packages/nigeria/ndpa",
    "packages/universal/pii-leakage",
])

# Add to graph
graph.add_node("compliance", node)
graph.add_edge("agent", "compliance")
```

### With CrewAI

```python
from adapters.crewai import build_tools_for_jurisdiction

tools = build_tools_for_jurisdiction("NG")
agent = Agent(role="Fintech Agent", tools=tools, ...)
```

### With AutoGen

```python
from adapters.autogen import check_all_packs

result = check_all_packs(
    jurisdiction="NG",
    action="send_to_external",
    output="user@example.com",
)
# {"overall": "block", "results": [...]}
```

### Direct OPA

```bash
# Install OPA
curl -L -o /usr/local/bin/opa \
  https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x /usr/local/bin/opa

# Run all tests
opa test packages/ -v

# Evaluate a policy
opa eval \
  -d packages/nigeria/ndpa/ \
  -i input.json \
  "data.comply54.ndpa.decision"
```

---

## Validation & CI

```bash
# Install deps
pip install pyyaml jsonschema

# Validate all packs against JSON Schema
python tools/validate.py

# Regenerate registry.json
python tools/generate_registry.py

# Lint Rego
regal lint packages/
```

CI runs automatically on every push and PR:
1. Schema validation (all policy.yaml files)
2. OPA syntax check
3. OPA tests (must pass 100%)
4. Regal lint (0 violations)
5. meta.json completeness check
6. registry.json sync check

---

## Pack Structure

Each policy pack contains:

```
packages/<jurisdiction>/<regulation-slug>/
├── policy.yaml           # AGT-compatible policy document
├── policy.rego           # OPA Rego reference implementation
├── meta.json             # versioning, regulatory metadata
└── tests/
    └── policy_test.rego  # OPA unit tests
```

---

## Consuming the Registry

`registry.json` at the repo root is a machine-readable index of all packs:

```python
import json, pathlib, requests

# From GitHub raw
registry = requests.get(
    "https://raw.githubusercontent.com/kingztech2019/comply54/main/registry.json"
).json()

# Filter by jurisdiction
ng_packs = [p for p in registry["packs"] if p["jurisdiction"] == "NG"]
```

---

## Disclaimer

Comply54 policy packs are community-maintained governance **starter templates**. They are **not certified legal compliance instruments**. Organisations must perform their own assessments with qualified legal and regulatory advisors before deploying in regulated environments.

Regulatory thresholds (CBN limits, NDPA adequacy lists, NFIU CTR thresholds) are subject to change. Always verify against current official sources before production deployment.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new policy pack or improve existing ones.

## Related Projects

- [agt-policies-nigeria](https://github.com/kingztech2019/agt-policies-nigeria) — original source policies (cited in Microsoft AGT main branch)
- [Microsoft Agent-OS](https://github.com/microsoft/agent-governance-toolkit) — agent governance framework
- [OWASP Agentic AI Top 10](https://genai.owasp.org) — security reference for universal packs
