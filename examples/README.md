# comply54 — Example Agents

Three complete LangGraph demo agents showing comply54 in action across different
Nigerian regulated industries. Every agent uses the same pattern:

```
agent node  →  comply54_guard  →  tools node
                    │
                    ├── blocked  →  agent sees ToolMessage error, explains to user
                    └── allowed  →  tool executes normally
```

Blocked tool calls **never reach the tool**. The LLM receives a structured error message
explaining which regulation triggered the block and what is needed to proceed.

---

## Prerequisites

```bash
cd /path/to/comply54

# Install comply54 with LangGraph dependencies
pip install -e ".[langgraph]"

# Set your Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## 1. Nigerian Fintech Agent

**Directory:** `nigeria_fintech_agent/`

**Sector pack:** `NigeriaFintechCompliance`

**Regulations:** CBN Transaction Limits (FPR/DIR/GEN/CIR/07/003), CBN NIP Framework,
CBN Tiered KYC, MLPPA 2022 / NFIU AML Guidelines, NDPA 2023, CBN BVN Framework

**Tools:** `transfer_funds`, `check_balance`, `get_account_details`, `approve_transfer`,
`get_transaction_history`

```bash
cd examples/nigeria_fintech_agent
python agent.py
```

**Scenarios:**

| # | Request | Expected outcome | Regulation |
|---|---------|-----------------|------------|
| 1 | Balance enquiry | ALLOWED | — |
| 2 | Transfer ₦100,000 (Tier 3) | ALLOWED | — |
| 3 | Transfer ₦6,000,000 (Tier 3) | ESCALATED | CBN Tier 3 daily ceiling |
| 4 | Transfer ₦15,000,000 | DENIED | CBN NIP ₦10M single-transaction cap |
| 5 | Self-approve own transfer | DENIED | CBN Maker-Checker rule |
| 6 | Transfer ₦500,000 (Tier 2 KYC) | ESCALATED | CBN Tier 2 daily limit |

---

## 2. Nigerian Healthcare Agent

**Directory:** `nigeria_health_agent/`

**Sector pack:** `NigeriaHealthcareCompliance`

**Regulations:** Nigeria National Health Act 2014 (ss.26, 29, 30), NDPA 2023
(special-category health data, ss.25/30), Medical and Dental Practitioners Act Cap M8 s.16,
FMOH AI in Healthcare Policy Draft 2024 (Guidelines 4, 7)

**Tools:** `access_patient_records`, `share_health_data`, `generate_diagnosis`,
`prescribe_medication`, `create_referral`, `get_lab_results`

```bash
cd examples/nigeria_health_agent
python agent.py
```

**Scenarios:**

| # | Request | Expected outcome | Regulation |
|---|---------|-----------------|------------|
| 1 | Read lab results (consent documented) | ALLOWED (audit) | NHA s.26 |
| 2 | Access full EHR without consent | DENIED | NHA s.26 / NDPA s.30 |
| 3 | Generate AI diagnosis (no oversight) | DENIED | FMOH Guideline 4 / MDP Act s.16 |
| 4 | Generate AI diagnosis (oversight=True) | ESCALATED | FMOH Guideline 4 |
| 5 | Prescribe medication (no clinician) | DENIED | MDP Act s.16 / FMOH Guideline 7 |
| 6 | Share health record to US hospital | DENIED | NDPA s.25 (special-category cross-border) |
| 7 | Access 50 records for research | ESCALATED | NHA / NDPC ethics committee |

**Context flags that control compliance behaviour:**

| Flag | Type | Effect |
|------|------|--------|
| `consent_documented` | bool | Must be `True` for any record access or sharing |
| `human_clinician_oversight` | bool | Must be `True` for AI diagnosis to proceed (as escalate) |
| `licensed_clinician_approval` | bool | Must be `True` for any prescription |
| `purpose` | str | `"research"` triggers ethics committee escalation |

---

## 3. Nigerian Insurance Agent

**Directory:** `nigeria_insurance_agent/`

**Sector pack:** `NigeriaInsuranceCompliance`

**Regulations:** Insurance Act 2003 (Cap I17 LFN 2004, ss.50/67/70), NAICOM Operational
Guidelines 2021 (Guidelines 12, 15, 18), NAICOM Market Conduct Guidelines 2023
(Rules 6, 11), MLPPA 2022 / NFIU AML Guidelines, NDPA 2023

**Tools:** `generate_quote`, `approve_claim`, `deny_claim`, `flag_fraud`,
`cancel_policy`, `get_claim_status`

```bash
cd examples/nigeria_insurance_agent
python agent.py
```

**Scenarios:**

| # | Request | Expected outcome | Regulation |
|---|---------|-----------------|------------|
| 1 | Check claim status | ALLOWED | — |
| 2 | Approve ₦800K claim (no senior approval) | ESCALATED | NAICOM Guideline 12 (₦2M threshold) |
| 3 | Deny ₦1.5M claim (no adjuster) | DENIED | NAICOM Guideline 15 (auto-denial cap ₦500K) |
| 4 | Settle ₦6M fire claim | ESCALATED | NAICOM Guideline 12 + NFIU AML ₦5M |
| 5 | Quote using religion as pricing factor | DENIED | Insurance Act s.67 / NAICOM Rule 6 |
| 6 | Life underwriting ₦8M (no underwriter) | DENIED | NAICOM Guideline 18 (₦5M cap) |
| 7 | Flag claim with fraud score 0.78 | ESCALATED | NAICOM Rule 11 |
| 8 | Cancel policy | ESCALATED | Insurance Act s.50 (notification duty) |

**Context flags that control compliance behaviour:**

| Flag | Type | Effect |
|------|------|--------|
| `human_adjuster_assigned` | bool | Required to deny any claim ≥ ₦500K |
| `senior_approval` | bool | Required to settle claims > ₦2M |
| `human_underwriter` | bool | Required for life underwriting > ₦5M |

---

## Strict Mode

All three agents support `strict_mode=True` when building the graph. In strict mode,
`escalate` decisions are treated as hard blocks — the tool call is rejected and the
agent must explain the escalation to the user rather than letting the tool execute
pending human review.

```python
agent = build_agent(strict_mode=True)   # escalate → deny
```

---

## Architecture

Each agent follows the same LangGraph pattern:

```python
from comply54.langchain import Comply54Guard, comply54_route
from comply54.sectors import NigeriaFintechCompliance  # or Health / Insurance

guard = Comply54Guard(
    NigeriaFintechCompliance(),
    context={"kyc_tier": 3},        # session context applied to every check
    block_on_escalate=False,
)

graph = StateGraph(AgentState)
graph.add_node("agent", call_model)
graph.add_node("comply54_guard", guard)
graph.add_node("tools", ToolNode(tools))

graph.set_entry_point("agent")
graph.add_conditional_edges("agent", should_continue,
    {"comply54_guard": "comply54_guard", END: END})
graph.add_conditional_edges("comply54_guard", comply54_route,
    {"tools": "tools", "agent": "agent"})
graph.add_edge("tools", "agent")

app = graph.compile()
```

The `comply54_guard` node reads `state["messages"][-1]` (an `AIMessage` with
`tool_calls`), evaluates each call against the sector pack, and either:

- Returns `ToolMessage` errors + `compliance_blocked: True` (agent sees errors, explains to user)
- Returns `compliance_blocked: False` (tools node executes normally)
