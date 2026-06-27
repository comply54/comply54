"""
Nigerian Healthcare AI Agent — comply54 LangGraph Demo
=======================================================

A LangGraph ReAct agent for a Nigerian EHR / clinical decision support platform,
guarded by comply54. Every tool call is evaluated against NHA 2014, NDPA 2023
(special-category health data), and FMOH AI Policy BEFORE execution.

Scenarios demonstrated:
  1. Read lab results with consent           → ALLOWED (audit logged)
  2. Access records without consent          → DENIED  (NHA s.26 / NDPA s.30)
  3. Generate AI diagnosis (oversight=False) → DENIED  (FMOH Guideline 4)
  4. Generate AI diagnosis (oversight=True)  → ESCALATED (clinician sign-off required)
  5. Prescribe medication without clinician  → DENIED  (MDP Act s.16)
  6. Share records cross-border (to US)      → DENIED  (NDPA s.25 special-category)
  7. Access records for research purpose     → ESCALATED (ethics committee required)

Run:
    ANTHROPIC_API_KEY=sk-ant-... python examples/nigeria_health_agent/agent.py
"""

from __future__ import annotations

import os
import sys
import textwrap
from typing import Annotated, Optional

try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
    from langgraph.graph import END, StateGraph
    from langgraph.prebuilt import ToolNode
    from typing_extensions import TypedDict
    from langgraph.graph.message import add_messages
except ImportError:
    print("Missing dependencies. Run: pip install comply54[langgraph] langchain-anthropic")
    sys.exit(1)

from comply54.langchain import Comply54Guard, comply54_route
from comply54.sectors import NigeriaHealthcareCompliance
from tools import HEALTH_TOOLS

# ── State ─────────────────────────────────────────────────────────────────────

class HealthAgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    compliance_blocked: bool
    compliance_result: Optional[dict]
    compliance_context: dict


# ── Graph builder ─────────────────────────────────────────────────────────────

def build_agent(
    consent_documented: bool = True,
    human_clinician_oversight: bool = False,
    licensed_clinician_approval: bool = False,
    purpose: str = "treatment",
    strict_mode: bool = False,
):
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY environment variable is not set.")

    llm = ChatAnthropic(model="claude-haiku-4-5-20251001", temperature=0)
    llm_with_tools = llm.bind_tools(HEALTH_TOOLS)

    compliance = NigeriaHealthcareCompliance(strict_mode=strict_mode)
    session_context = {
        "consent_documented": consent_documented,
        "human_clinician_oversight": human_clinician_oversight,
        "licensed_clinician_approval": licensed_clinician_approval,
        "purpose": purpose,
    }

    guard = Comply54Guard(
        compliance=compliance,
        context=session_context,
        block_on_escalate=strict_mode,
    )

    tool_node = ToolNode(HEALTH_TOOLS)

    SYSTEM_PROMPT = textwrap.dedent(f"""
        You are an AI clinical assistant for a Nigerian hospital (EHR system).
        You help clinicians access patient records, retrieve lab results, and
        generate clinical assessments.

        Current session context:
        - Patient consent documented: {consent_documented}
        - Human clinician oversight active: {human_clinician_oversight}
        - Licensed clinician approval: {licensed_clinician_approval}
        - Access purpose: {purpose}

        When a tool call is blocked by compliance, explain to the clinician:
        1. Which regulation was triggered and why
        2. What is needed to proceed (e.g. document consent, assign clinician)
        Be clear, professional, and cite the specific regulation section.
    """).strip()

    def call_model(state: HealthAgentState) -> dict:
        messages = [SystemMessage(content=SYSTEM_PROMPT)] + state["messages"]
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    def should_continue(state: HealthAgentState) -> str:
        last = state["messages"][-1]
        if isinstance(last, AIMessage) and last.tool_calls:
            return "comply54_guard"
        return END

    graph = StateGraph(HealthAgentState)
    graph.add_node("agent", call_model)
    graph.add_node("comply54_guard", guard)
    graph.add_node("tools", tool_node)
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", should_continue,
        {"comply54_guard": "comply54_guard", END: END})
    graph.add_conditional_edges("comply54_guard", comply54_route,
        {"tools": "tools", "agent": "agent"})
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


def run_scenario(agent, user_message: str, context_summary: str = "") -> None:
    print(f"\n{BOLD}Clinician:{RESET} {user_message}")
    if context_summary:
        print(f"{DIM}  Context: {context_summary}{RESET}\n")

    initial_state: HealthAgentState = {
        "messages": [HumanMessage(content=user_message)],
        "compliance_blocked": False,
        "compliance_result": None,
        "compliance_context": {},
    }

    final_state = agent.invoke(initial_state)

    for msg in reversed(final_state["messages"]):
        if isinstance(msg, AIMessage) and msg.content:
            print(f"{BOLD}Agent:{RESET} {msg.content}")
            break

    result = final_state.get("compliance_result")
    if result:
        overall = result.get("overall", "allow")
        if overall == "deny":
            print(f"\n{RED}{BOLD}  ✗ comply54: DENIED{RESET}")
        elif overall == "escalate":
            print(f"\n{YELLOW}{BOLD}  ⚠ comply54: ESCALATED (human review required){RESET}")
        elif overall == "audit":
            print(f"\n{DIM}  ✓ comply54: ALLOWED (audit logged){RESET}")
        else:
            print(f"\n{GREEN}  ✓ comply54: ALLOWED{RESET}")
        for v in result.get("violations", []):
            for msg_text in v.get("messages", []):
                print(f"  {DIM}  → {msg_text}{RESET}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}comply54 × LangGraph — Nigerian Healthcare AI Agent Demo{RESET}")
    print(f"{DIM}Every tool call evaluated against NHA 2014, NDPA 2023, MDP Act, FMOH AI Policy.{RESET}")

    # ── Scenario 1: Consented lab results access — ALLOWED ────────────────────
    print_scenario("Read lab results with documented consent", 1)
    run_scenario(
        build_agent(consent_documented=True, purpose="treatment"),
        "Retrieve the latest lab results for patient P-98765.",
        "consent_documented=True, purpose=treatment",
    )

    # ── Scenario 2: Access records WITHOUT consent — DENIED ───────────────────
    print_scenario("Access full EHR without patient consent", 2)
    run_scenario(
        build_agent(consent_documented=False),
        "Pull the full electronic health record for patient P-11223.",
        "consent_documented=False",
    )

    # ── Scenario 3: AI diagnosis without human oversight — DENIED ─────────────
    print_scenario("Generate AI diagnosis — human oversight NOT set", 3)
    run_scenario(
        build_agent(consent_documented=True, human_clinician_oversight=False),
        "Assess these symptoms for patient P-44556: chest pain, shortness of breath, dizziness.",
        "consent_documented=True, human_clinician_oversight=False",
    )

    # ── Scenario 4: AI diagnosis WITH human oversight — ESCALATED ─────────────
    print_scenario("Generate AI diagnosis — clinician oversight active", 4)
    run_scenario(
        build_agent(consent_documented=True, human_clinician_oversight=True),
        "Assess symptoms for patient P-44556: chest pain, shortness of breath, dizziness.",
        "consent_documented=True, human_clinician_oversight=True",
    )

    # ── Scenario 5: Prescribe without clinician approval — DENIED ─────────────
    print_scenario("Prescribe medication without licensed clinician approval", 5)
    run_scenario(
        build_agent(consent_documented=True, licensed_clinician_approval=False),
        "Prescribe Metformin 500mg twice daily for patient P-77890 for diabetes management.",
        "consent_documented=True, licensed_clinician_approval=False",
    )

    # ── Scenario 6: Cross-border data share to US — DENIED ───────────────────
    print_scenario("Share patient records to a US hospital", 6)
    run_scenario(
        build_agent(consent_documented=True),
        "Share patient P-33214's full health record with Johns Hopkins Hospital in the United States.",
        "consent_documented=True, destination_country=US",
    )

    # ── Scenario 7: Records access for research — ESCALATED ──────────────────
    print_scenario("Access patient records for research purpose", 7)
    run_scenario(
        build_agent(consent_documented=True, purpose="research"),
        "Retrieve health records for patients P-10001 through P-10050 for our hypertension study.",
        "consent_documented=True, purpose=research, record_count=50",
    )

    print(f"\n{'═' * 70}")
    print(f"{BOLD}Demo complete.{RESET}")
    print(
        f"{DIM}7 scenarios across NHA 2014, NDPA 2023 (special-category), "
        f"MDP Act s.16, and FMOH AI Policy.{RESET}\n"
    )


if __name__ == "__main__":
    main()
