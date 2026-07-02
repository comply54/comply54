# Comply54

**Open-source AI governance enforcement for African regulatory compliance.**

[![CI](https://github.com/comply54/comply54/actions/workflows/ci.yml/badge.svg)](https://github.com/comply54/comply54/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/comply54/comply54/branch/main/graph/badge.svg)](https://codecov.io/gh/comply54/comply54)
[![PyPI](https://img.shields.io/pypi/v/comply54.svg)](https://pypi.org/project/comply54)
[![npm](https://img.shields.io/npm/v/@comply54/core.svg)](https://www.npmjs.com/package/@comply54/core)
[![Python](https://img.shields.io/pypi/pyversions/comply54.svg)](https://pypi.org/project/comply54)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## What it does

Comply54 intercepts AI agent tool calls and evaluates them against African regulatory frameworks — CBN, NDPA, NHA, NAICOM, KDPA, POPIA, and more — **before execution**. Blocked calls never reach the tool.

```
Agent decides to call transfer_funds(amount=15_000_000)
         │
         ▼
   comply54 guard  ──► CBN NIP cap exceeded ──► ToolMessage error returned
         │                                       Agent explains to user
         ✗ tool never executes
```

No OPA binary required. No subprocess. Works in serverless environments.

---

## How it relates to agt-policies-nigeria

```
kingztech2019/agt-policies-nigeria          comply54
──────────────────────────────────          ────────────────────────────────────
The policy SOURCE.                          The enforcement and tooling LAYER.

• Rego policy packs (NDPA, CBN, ...)  ──▶  • PackSpec registry indexes them
• Cited in Microsoft AGT main         ──▶  • Sector classes compose them
• OPA tests (306 passing)             ──▶  • LangGraph / CrewAI / AutoGen adapters
• Stays at kingztech2019 forever      ──▶  • regopy evaluates in-process (no binary)
```

`agt-policies-nigeria` is where the policy files live — permanently cited in
[Microsoft Agent-OS](https://github.com/microsoft/agent-governance-toolkit).

`comply54` is where the ecosystem lives — the enforcement engine, sector compositions,
framework adapters, and CI tooling that make those policies consumable from LangChain,
LangGraph, CrewAI, AutoGen, and any OPA pipeline.

---

## Quick Start

### Install

```bash
# Core (no framework)
pip install comply54

# With LangGraph / LangChain
pip install "comply54[langgraph]"

# With CrewAI
pip install "comply54[crewai]"

# Everything
pip install "comply54[all]"
```

### Nigerian Fintech Agent (LangGraph)

```python
from comply54.sectors import NigeriaFintechCompliance
from comply54.langchain import Comply54Guard, comply54_route
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode

compliance = NigeriaFintechCompliance()
guard = Comply54Guard(compliance, context={"kyc_tier": 3})

graph = StateGraph(AgentState)
graph.add_node("agent", call_model)
graph.add_node("comply54_guard", guard)       # intercepts before tools run
graph.add_node("tools", ToolNode(tools))

graph.add_conditional_edges("agent", should_continue,
    {"comply54_guard": "comply54_guard", END: END})
graph.add_conditional_edges("comply54_guard", comply54_route,
    {"tools": "tools", "agent": "agent"})     # blocked → agent, clear → tools
graph.add_edge("tools", "agent")
```

### Direct check (no framework)

```python
from comply54.sectors import NigeriaFintechCompliance

compliance = NigeriaFintechCompliance()

result = compliance.check(
    action="transfer_funds",
    params={"amount": 15_000_000, "currency": "NGN"},
    context={"kyc_tier": 3},
)

print(result.overall)                          # "deny"
print(result.primary_violation.messages[0])   # "CBN NIP Framework: ..."
```

### Compliance certificate (for auditors)

```python
cert = compliance.certificate(
    action="transfer_funds",
    params={"amount": 5_000_000, "currency": "NGN"},
    context={"kyc_tier": 3},
)
print(cert.to_json())   # tamper-evident JSON with SHA-256 integrity hash
```

---

## Sector Packs

Sector packs are the main entry point. One import wires up all relevant regulatory frameworks for your use case.

### Nigerian Sector Packs

| Sector class | Regulations covered | Use case |
|---|---|---|
| `NigeriaFintechCompliance` | NDPA + CBN + BVN/NIN + NFIU AML + OWASP | Payment agents, digital banking |
| `NigeriaHealthcareCompliance` | NHA 2014 + NDPA (special-category) + FMOH AI Policy + OWASP | EHR agents, clinical decision support |
| `NigeriaInsuranceCompliance` | Insurance Act 2003 + NAICOM Guidelines + NFIU AML + NDPA + OWASP | Claims processing, underwriting |

### Other Sector Packs

| Sector class | Jurisdictions | Use case |
|---|---|---|
| `KenyaFintechCompliance` | KE | Kenyan payment agents |
| `PanAfricanFintechCompliance` | NG, KE, ZA, GH, RW, EG, ET, MU, TZ, UG | Multi-market agents |

```python
from comply54.sectors import (
    NigeriaFintechCompliance,
    NigeriaHealthcareCompliance,
    NigeriaInsuranceCompliance,
    KenyaFintechCompliance,
    PanAfricanFintechCompliance,
)
```

---

## Policy Packs

All packs use in-process Rego evaluation via `regopy` — no OPA binary required.

### Universal Agent Safety Controls

| Pack ID | Regulation | OWASP Ref |
|---|---|---|
| `universal/prompt-injection` | OWASP Agentic AI — LLM01/ASI01 | LLM01 |
| `universal/pii-leakage` | OWASP LLM06 — Sensitive Information Disclosure | LLM06 |
| `universal/tool-permissions` | OWASP LLM08 — Excessive Agency | LLM08 |
| `universal/human-approval` | OWASP LLM09 — Overreliance | LLM09 |
| `universal/model-routing` | OWASP LLM03/LLM05 — Model Selection Controls | LLM03/LLM05 |

### Nigerian Regulatory Packs

| Pack ID | Regulation | Authority |
|---|---|---|
| `nigeria/ndpa` | Nigeria Data Protection Act 2023 | NDPC |
| `nigeria/cbn` | CBN Transaction Limits & Tiered KYC (FPR/DIR/GEN/CIR/07/003) | CBN |
| `nigeria/bvn-nin` | CBN BVN Framework & NIBSS Scheme Rules | CBN / NIBSS |
| `nigeria/nfiu-aml` | MLPPA 2022 / NFIU AML Guidelines | NFIU |
| `nigeria/nha` | Nigeria National Health Act 2014 / FMOH AI Policy | FMOH / MDCN |
| `nigeria/naicom` | Insurance Act 2003 / NAICOM Operational Guidelines 2021 / Market Conduct 2023 | NAICOM |

### East Africa

| Pack ID | Regulation | Authority |
|---|---|---|
| `kenya/kdpa` | Kenya Data Protection Act 2019 | ODPC |
| `mauritius/dpa` | Mauritius Data Protection Act 2017 | DPC Mauritius |
| `tanzania/pdpa` | Tanzania Personal Data Protection Act 2022 | PDPC Tanzania |
| `uganda/dppa` | Uganda Data Protection and Privacy Act 2019 | PDPO Uganda |
| `ethiopia/pdp` | Ethiopia Personal Data Protection Proclamation 1321/2024 | ECA |
| `rwanda/dpa` | Rwanda Law No. 058/2021 on Personal Data Protection | RISA |

### Southern Africa

| Pack ID | Regulation | Authority |
|---|---|---|
| `south-africa/popia` | Protection of Personal Information Act 4 of 2013 | Information Regulator ZA |

### West Africa

| Pack ID | Regulation | Authority |
|---|---|---|
| `ghana/dpa` | Ghana Data Protection Act 843 of 2012 | DPC Ghana |

### North Africa

| Pack ID | Regulation | Authority |
|---|---|---|
| `egypt/pdpl` | Egypt Personal Data Protection Law No. 151/2020 | PDPRL Egypt |

---

## Framework Adapters

### LangGraph (recommended)

```python
from comply54.langchain import Comply54Guard, comply54_route

# Comply54Guard is a callable LangGraph node.
# It reads AIMessage.tool_calls, evaluates each via comply54,
# and injects ToolMessage errors for any blocked calls.

guard = Comply54Guard(
    NigeriaFintechCompliance(),
    context={"kyc_tier": 3},
    block_on_escalate=False,   # True = escalate decisions also block
)
```

### LangChain StructuredTool

```python
from comply54.langchain import comply54_tool

# Exposes comply54 as a tool the agent can call to self-check
tool = comply54_tool(NigeriaFintechCompliance())
agent = create_react_agent(llm, tools=[*my_tools, tool])
```

### CrewAI

```python
from comply54.crewai import build_compliance_tools

tools = build_compliance_tools(NigeriaFintechCompliance())
agent = Agent(role="Fintech Agent", tools=tools, ...)
```

### AutoGen

```python
from comply54.autogen import comply54_tools
from autogen_agentchat.agents import AssistantAgent

agent = AssistantAgent(
    name="finance_agent",
    model_client=client,
    tools=comply54_tools([transfer_funds, check_balance], NigeriaFintechCompliance()),
)
```

### Direct OPA (from agt-policies-nigeria)

```bash
git clone https://github.com/kingztech2019/agt-policies-nigeria
cd agt-policies-nigeria
opa test policies/rego/ -v   # 306 tests
```

---

## Example Agents

Three complete LangGraph demo agents are in `examples/`:

| Example | Sector | Regulations demonstrated |
|---|---|---|
| `examples/nigeria_fintech_agent/` | Fintech | CBN NIP cap, Tier KYC limits, Maker-Checker, NFIU AML |
| `examples/nigeria_health_agent/` | Healthcare | NHA patient consent, AI diagnosis oversight, NDPA special-category |
| `examples/nigeria_insurance_agent/` | Insurance | NAICOM auto-denial cap, anti-discrimination, life underwriting, fraud |

```bash
export ANTHROPIC_API_KEY=sk-ant-...
cd examples/nigeria_fintech_agent && python agent.py
cd examples/nigeria_health_agent  && python agent.py
cd examples/nigeria_insurance_agent && python agent.py
```

---

## Adding a New Pack

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. Quick summary:

1. Write `comply54/packs/<jurisdiction>/<pack>.rego` with Rego `deny`, `escalate`, `audit`, `allow` rules
2. Add a `PackSpec` entry in `comply54/core/packs.py`
3. Compose it into a sector class in `comply54/sectors/`
4. Add tests in `tests/`

---

## Validation & CI

```bash
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Validate pack registry
python tools/validate.py

# OPA tests (requires opa binary)
opa test comply54/packs/ -v

# Lint Rego
regal lint comply54/packs/
```

---

## Disclaimer

Comply54 policy packs are community-maintained governance **starter templates**, not
certified legal compliance instruments. Organisations must perform their own assessments
with qualified legal and regulatory advisors before deploying in regulated environments.
