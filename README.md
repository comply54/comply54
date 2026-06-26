# Comply54

**Open-source AI governance registry and tooling for African regulatory compliance.**

[![CI](https://github.com/comply54/comply54/actions/workflows/ci.yml/badge.svg)](https://github.com/comply54/comply54/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/comply54/comply54/branch/main/graph/badge.svg)](https://codecov.io/gh/comply54/comply54)
[![PyPI](https://img.shields.io/pypi/v/comply54.svg)](https://pypi.org/project/comply54)
[![npm](https://img.shields.io/npm/v/@comply54/core.svg)](https://www.npmjs.com/package/@comply54/core)
[![Python](https://img.shields.io/pypi/pyversions/comply54.svg)](https://pypi.org/project/comply54)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## How it relates to agt-policies-nigeria

```
kingztech2019/agt-policies-nigeria          comply54
──────────────────────────────────          ────────────────────────────────────
The policy SOURCE.                          The registry and tooling LAYER.

• 12 policy packs (YAML + Rego)    ──▶     • registry.json indexes them by URL
• Cited in Microsoft AGT main      ──▶     • adapters load them into any framework
• OPA tests (306 passing)          ──▶     • schema validates them on every PR
• Stays at kingztech2019 forever   ──▶     • comply54 never duplicates them
```

`agt-policies-nigeria` is where the policy files live — it is permanently cited in
[Microsoft Agent-OS](https://github.com/microsoft/agent-governance-toolkit). That repo
will never move.

`comply54` is where the ecosystem lives — the registry, framework adapters, JSON Schema
validator, and CI tooling that makes those policies consumable from LangChain, CrewAI,
AutoGen, and any OPA pipeline. When new packs are contributed (Ghana DPA, Rwanda DPA,
ECOWAS), their policy files will live under `packages/` in this repo.

---

## Policy Packs (current)

All 12 current packs are sourced from `kingztech2019/agt-policies-nigeria`.
`registry.json` has the direct raw GitHub URLs for each.

### Universal Agent Safety Controls

| Pack | Regulation | OWASP Ref |
|------|-----------|-----------|
| prompt-injection | OWASP Agentic AI — LLM01/ASI01 | LLM01 |
| pii-leakage | OWASP LLM06 | LLM06 |
| tool-permissions | OWASP LLM08 | LLM08 |
| human-approval | OWASP LLM09 | LLM09 |
| model-routing | OWASP LLM03/LLM05 | LLM03/LLM05 |

### Nigerian Regulatory Packs

| Pack | Regulation | Authority |
|------|-----------|----------|
| nigeria/ndpa | Nigeria Data Protection Act 2023 | NDPC |
| nigeria/cbn | CBN Transaction Limits & Tiered KYC | CBN |
| nigeria/bvn-nin | CBN BVN Framework; NIBSS Rules | CBN / NIBSS |
| nigeria/nfiu-aml | MLPPA 2022 / NFIU AML Guidelines | NFIU |
| nigeria/pos-geofencing | CBN Agent Banking Guidelines 2020 | CBN |

### East Africa

| Pack | Regulation | Authority |
|------|-----------|----------|
| kenya/kdpa | Kenya Data Protection Act 2019 | ODPC |

### Southern Africa

| Pack | Regulation | Authority |
|------|-----------|----------|
| south-africa/popia | POPIA Act 4 of 2013 | Information Regulator ZA |

---

## Quick Start

### With Microsoft Agent-OS (AGT)

```python
from adapters.agt import load_jurisdiction

# Loads all packs for Nigeria + universal from agt-policies-nigeria (via raw GitHub URL)
policies = load_jurisdiction("NG")

for policy in policies:
    result = policy.evaluate({"action": "export_data", "output": ""})
```

### With LangChain / LangGraph

```python
from adapters.langchain import compliance_node

# Pack source URL from registry.json
node = compliance_node([
    "https://raw.githubusercontent.com/kingztech2019/agt-policies-nigeria/main/policies/ndpa-data-residency.yaml",
    "https://raw.githubusercontent.com/kingztech2019/agt-policies-nigeria/main/policies/agent-pii-leakage.yaml",
])
graph.add_node("compliance", node)
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

result = check_all_packs(jurisdiction="NG", action="send_to_external", output="user@example.com")
# {"overall": "block", "results": [...]}
```

### Direct OPA (from agt-policies-nigeria)

```bash
git clone https://github.com/kingztech2019/agt-policies-nigeria
cd agt-policies-nigeria
opa test policies/rego/ -v   # 306 tests
```

---

## Consuming the Registry

```python
import json, urllib.request

registry = json.loads(
    urllib.request.urlopen(
        "https://raw.githubusercontent.com/kingztech2019/comply54/main/registry.json"
    ).read()
)

# Get all packs for Nigeria
ng_pack_ids = registry["jurisdiction_map"]["NG"]
ng_packs = [p for p in registry["packs"] if p["id"] in ng_pack_ids]

# Fetch a policy YAML directly
import yaml, urllib.request
policy_yaml = yaml.safe_load(
    urllib.request.urlopen(ng_packs[0]["source_yaml"]).read()
)
```

---

## Adding a New Pack

New packs that are NOT part of `agt-policies-nigeria` (e.g. Ghana DPA, Rwanda DPA,
ECOWAS) go into `packages/<jurisdiction>/<slug>/` in this repo. See [CONTRIBUTING.md](CONTRIBUTING.md).

Packs already in `agt-policies-nigeria` do not need to be duplicated here — add a
registry entry in `registry.json` with the `source_yaml` URL.

---

## Validation & CI

```bash
pip install pyyaml jsonschema

# Validate all packs in registry.json (fetches remote ones over HTTPS)
python tools/validate.py

# Skip remote packs (offline mode)
python tools/validate.py --local-only

# Validate a single local pack
python tools/validate.py packages/ghana/gdpa
```

CI runs on every push and PR:
1. Schema validation (all registry packs — remote + local)
2. OPA tests (local packs only — remote packs tested in agt-policies-nigeria)
3. Regal lint (local packs only)
4. meta.json completeness (local packs)
5. Registry source URL reachability check

---

## Disclaimer

Comply54 policy packs are community-maintained governance **starter templates**, not
certified legal compliance instruments. Organisations must perform their own assessments
with qualified legal and regulatory advisors before deploying in regulated environments.
