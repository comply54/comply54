"""
Nigerian Fintech Payment Agent — comply54 LangGraph Demo
=========================================================

A LangGraph ReAct agent for a Nigerian payment platform, guarded by comply54.
Every tool call is evaluated against CBN, NDPA, BVN/NIN and NFIU rules
BEFORE execution. Blocked calls never reach the tool.

Architecture:

    ┌─────────┐     tool_calls?     ┌────────────────┐
    │  START  │ ──────────────────► │     agent      │
    └─────────┘                     └───────┬────────┘
                                            │ has tool_calls
                                            ▼
                                    ┌────────────────┐
                                    │ comply54_guard │  ← checks CBN/NDPA/NFIU
                                    └───────┬────────┘
                              blocked │     │ allowed
                                      │     ▼
                                      │  ┌──────┐
                                      │  │tools │  ← only reached if compliant
                                      │  └──┬───┘
                                      │     │
                                      ▼     ▼
                                    ┌────────────────┐
                                    │     agent      │ ← sees result or error
                                    └───────┬────────┘
                                     done?  │
                                            ▼
                                          END

Scenarios demonstrated:
  1. Balance check              → ALLOWED (no compliance rules triggered)
  2. Transfer ₦100K (Tier 3)   → ALLOWED
  3. Transfer ₦6M  (Tier 3)    → ESCALATED (CBN Tier 3 ceiling)
  4. Transfer ₦15M             → DENIED (CBN NIP cap exceeded)
  5. Self-approve a transfer   → DENIED (CBN Maker-Checker rule)

Run:
    ANTHROPIC_API_KEY=sk-ant-... python examples/nigeria_fintech_agent/agent.py
"""

from __future__ import annotations

import os
import sys
import textwrap
from typing import Annotated, Optional

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
    from langgraph.graph import END, StateGraph
    from langgraph.prebuilt import ToolNode
    from typing_extensions import TypedDict
    from langgraph.graph.message import add_messages
except ImportError:
    print(
        "Missing dependencies. Run:\n"
        "  pip install comply54[langgraph]\n"
        "  pip install langchain-anthropic\n"
    )
    sys.exit(1)

from comply54.langchain import Comply54Guard, comply54_route
from comply54.sectors import NigeriaFintechCompliance
from tools import FINTECH_TOOLS

# ── Agent state ───────────────────────────────────────────────────────────────

class PaymentAgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    compliance_blocked: bool
    compliance_result: Optional[dict]
    # Session context passed to every comply54 evaluation.
    # Represents the authenticated customer's profile.
    compliance_context: dict


# ── Build the graph ───────────────────────────────────────────────────────────

def build_agent(kyc_tier: int = 3, strict_mode: bool = False) -> StateGraph:
    """
    Build and compile the Nigerian fintech payment agent graph.

    Args:
        kyc_tier:    Customer's CBN KYC tier (1=basic, 2=intermediate, 3=full).
        strict_mode: If True, escalate decisions are treated as hard blocks
                     (comply54 strict mode — escalate → deny).
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY environment variable is not set.\n"
            "Export it before running: export ANTHROPIC_API_KEY=sk-ant-..."
        )

    llm = ChatAnthropic(model="claude-haiku-4-5-20251001", temperature=0)
    llm_with_tools = llm.bind_tools(FINTECH_TOOLS)

    compliance = NigeriaFintechCompliance(strict_mode=strict_mode) if strict_mode else NigeriaFintechCompliance()
    session_context = {
        "kyc_tier": kyc_tier,
        "customer_verified": kyc_tier >= 2,
    }

    guard = Comply54Guard(
        compliance=compliance,
        context=session_context,
        block_on_escalate=strict_mode,
    )

    tool_node = ToolNode(FINTECH_TOOLS)

    # ── Nodes ──────────────────────────────────────────────────────────────────

    SYSTEM_PROMPT = textwrap.dedent(f"""
        You are a Nigerian fintech payment assistant for a digital banking platform.
        You help customers with transfers, balance enquiries, and account information.

        Customer profile:
        - KYC Tier: {kyc_tier} ({"fully verified" if kyc_tier == 3 else "partially verified"})
        - Jurisdiction: Nigeria (CBN regulated)

        When a tool call is blocked by compliance, explain to the customer:
        1. What was blocked and why (cite the regulation)
        2. What they can do instead (e.g. visit a branch, contact support)
        Be helpful and professional — never say "I cannot help with that" without an explanation.
    """).strip()

    def call_model(state: PaymentAgentState) -> dict:
        messages = [SystemMessage(content=SYSTEM_PROMPT)] + state["messages"]
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    def should_continue(state: PaymentAgentState) -> str:
        last = state["messages"][-1]
        if isinstance(last, AIMessage) and last.tool_calls:
            return "comply54_guard"
        return END

    # ── Graph ──────────────────────────────────────────────────────────────────

    graph = StateGraph(PaymentAgentState)

    graph.add_node("agent", call_model)
    graph.add_node("comply54_guard", guard)
    graph.add_node("tools", tool_node)

    graph.set_entry_point("agent")

    graph.add_conditional_edges(
        "agent",
        should_continue,
        {"comply54_guard": "comply54_guard", END: END},
    )
    graph.add_conditional_edges(
        "comply54_guard",
        comply54_route,
        {"tools": "tools", "agent": "agent"},
    )
    graph.add_edge("tools", "agent")

    return graph.compile()


# ── Pretty printing ────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"


def print_scenario(title: str, index: int) -> None:
    print(f"\n{'═' * 70}")
    print(f"{BOLD}{CYAN}  Scenario {index}: {title}{RESET}")
    print(f"{'═' * 70}")


def run_scenario(agent, user_message: str, kyc_tier: int = 3) -> None:
    print(f"\n{BOLD}Customer:{RESET} {user_message}")
    print(f"{DIM}  (KYC Tier {kyc_tier}){RESET}\n")

    initial_state: PaymentAgentState = {
        "messages": [HumanMessage(content=user_message)],
        "compliance_blocked": False,
        "compliance_result": None,
        "compliance_context": {"kyc_tier": kyc_tier, "customer_verified": kyc_tier >= 2},
    }

    final_state = agent.invoke(initial_state)

    # Print the final assistant response
    for msg in reversed(final_state["messages"]):
        if isinstance(msg, AIMessage) and msg.content:
            print(f"{BOLD}Agent:{RESET} {msg.content}")
            break

    # Print compliance outcome
    result = final_state.get("compliance_result")
    if result:
        overall = result.get("overall", "allow")
        if overall == "deny":
            print(f"\n{RED}{BOLD}  ✗ comply54: DENIED{RESET}")
        elif overall == "escalate":
            print(f"\n{YELLOW}{BOLD}  ⚠ comply54: ESCALATED (human approval required){RESET}")
        elif overall == "audit":
            print(f"\n{DIM}  ✓ comply54: ALLOWED (audit logged){RESET}")
        else:
            print(f"\n{GREEN}  ✓ comply54: ALLOWED{RESET}")

        for v in result.get("violations", []):
            for msg_text in v.get("messages", []):
                print(f"  {DIM}  → {msg_text}{RESET}")


# ── Main: run all scenarios ────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}comply54 × LangGraph — Nigerian Fintech Payment Agent Demo{RESET}")
    print(f"{DIM}Every tool call is evaluated against CBN, NDPA, BVN/NIN and NFIU rules.{RESET}")

    agent_tier3 = build_agent(kyc_tier=3, strict_mode=False)
    agent_tier3_strict = build_agent(kyc_tier=3, strict_mode=True)
    agent_tier2 = build_agent(kyc_tier=2, strict_mode=False)

    # ── Scenario 1: Normal balance check — no compliance rules triggered ──────
    print_scenario("Balance enquiry (no compliance rules triggered)", 1)
    run_scenario(
        agent_tier3,
        "What is the current balance on account 0123456789?",
    )

    # ── Scenario 2: Small transfer — allowed ──────────────────────────────────
    print_scenario("Transfer ₦100,000 — within all CBN limits (Tier 3 KYC)", 2)
    run_scenario(
        agent_tier3,
        "Please transfer ₦100,000 to account 9876543210. Reference: school fees.",
    )

    # ── Scenario 3: Mid transfer — escalated (CBN Tier 3 ceiling) ─────────────
    print_scenario("Transfer ₦6,000,000 — exceeds CBN Tier 3 daily ceiling", 3)
    run_scenario(
        agent_tier3,
        "I need to transfer ₦6,000,000 to account 5544332211 for a property deposit.",
    )

    # ── Scenario 4: Large transfer — denied (NIP cap) ─────────────────────────
    print_scenario("Transfer ₦15,000,000 — exceeds CBN NIP ₦10M single-transaction cap", 4)
    run_scenario(
        agent_tier3,
        "Transfer ₦15,000,000 to account 1122334455. Description: business settlement.",
    )

    # ── Scenario 5: Self-approval — denied (CBN Maker-Checker) ───────────────
    print_scenario("Self-approval — CBN Maker-Checker rule violated", 5)
    run_scenario(
        agent_tier3,
        "Approve transfer TXN-ABC1234567 — I authorised it myself, just confirm it.",
    )

    # ── Scenario 6: Tier 2 KYC over limit ────────────────────────────────────
    print_scenario("Transfer ₦500,000 with Tier 2 KYC — exceeds Tier 2 daily limit", 6)
    run_scenario(
        agent_tier2,
        "Transfer ₦500,000 to account 6677889900.",
        kyc_tier=2,
    )

    print(f"\n{'═' * 70}")
    print(f"{BOLD}Demo complete.{RESET}")
    print(
        f"{DIM}All six scenarios ran against NigeriaFintechCompliance — "
        f"CBN, NDPA, BVN/NIN, NFIU, and OWASP Agentic AI packs.{RESET}\n"
    )


if __name__ == "__main__":
    main()
