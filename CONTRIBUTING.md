# Contributing to Comply54

Comply54 is a community-maintained open-source project. Contributions — new policy packs,
new sector compositions, framework adapter improvements, and bug fixes — are welcome.

## Before You Submit

- Comply54 policy packs are governance **starter templates**, not certified legal instruments.
- Always cite the exact section number you are implementing (e.g. `NDPA s.25`, `CBN NIP Framework §4.3`).
- Include a regulatory source URL in the `PackSpec` entry so reviewers can verify the rule.
- All contributions must pass CI (OPA tests, Regal lint, pytest) before merging.

---

## Repository Structure

```
comply54/
├── comply54/
│   ├── packs/
│   │   ├── nigeria/          ← Nigerian regulatory Rego packs
│   │   │   ├── ndpa.rego
│   │   │   ├── cbn.rego
│   │   │   ├── nha.rego
│   │   │   └── naicom.rego
│   │   ├── africa/           ← Pan-African jurisdiction Rego packs
│   │   │   ├── kdpa.rego
│   │   │   ├── popia.rego
│   │   │   └── ...
│   │   └── universal/        ← Framework-agnostic safety packs
│   │       ├── pii_leakage.rego
│   │       └── ...
│   ├── core/
│   │   └── packs.py          ← PackSpec registry (add new packs here)
│   ├── sectors/
│   │   ├── _base.py          ← SectorCompliance base class
│   │   ├── nigeria_fintech.py
│   │   ├── nigeria_health.py
│   │   ├── nigeria_insurance.py
│   │   └── ...               ← Add new sector compositions here
│   └── langchain/            ← LangChain / LangGraph adapter
├── examples/
│   ├── nigeria_fintech_agent/
│   ├── nigeria_health_agent/
│   └── nigeria_insurance_agent/
└── tests/
```

---

## Adding a New Policy Pack

### Step 1 — Write the Rego file

Create `comply54/packs/<jurisdiction>/<pack_slug>.rego`. Use `snake_case` for the filename.

The package declaration must follow the convention:
- Nigerian packs: `package agt_policies_nigeria.<slug>`
- African packs: `package agt_policies_africa.<slug>`
- Universal packs: `package agt_policies_agent.<slug>`

Every pack must define these four rule sets and the `decision` summary:

```rego
package agt_policies_nigeria.my_pack

import rego.v1

# ── DENY: hard blocks (never execute) ─────────────────────────
deny contains msg if {
    # condition
    msg := "Regulation Name s.X: clear message explaining what was blocked and why"
}

# ── ESCALATE: route to human approval queue ────────────────────
escalate contains msg if {
    # condition
    msg := "Regulation Name s.Y: reason this needs a human decision"
}

# ── AUDIT: log regardless of outcome ──────────────────────────
audit contains msg if {
    # condition
    msg := "Regulation Name: action logged for regulatory examination"
}

# ── Decision summary (required) ────────────────────────────────
decision := "deny"    if count(deny) > 0
decision := "escalate" if { count(deny) == 0; count(escalate) > 0 }
decision := "audit"   if { count(deny) == 0; count(escalate) == 0; count(audit) > 0 }
decision := "allow"   if { count(deny) == 0; count(escalate) == 0; count(audit) == 0 }
```

**Guidelines:**
- Every `msg` string must cite the regulation section by name and number
- Check `input.params` fields directly — do not regex-match on `input.output` unless there is no structured alternative
- Define thresholds as named constants at the top (`nip_cap := 10000000`)
- Group action names into named sets (`transfer_actions := {"transfer_funds", ...}`)
- All three container types must be checked where applicable (containers, initContainers, ephemeralContainers)

### Step 2 — Add a PackSpec entry

Open `comply54/core/packs.py` and add a `PackSpec` for your new pack:

```python
MY_PACK = PackSpec(
    id="nigeria/my-pack",                     # kebab-case, jurisdiction-prefixed
    regulation="Full Regulation Name Year",   # exact official name
    jurisdiction="NG",                        # ISO 3166-1 alpha-2
    authority="Authority Name",               # enforcing body
    rego_path=_PACKS_DIR / "nigeria" / "my_pack.rego",
    query_prefix="data.agt_policies_nigeria.my_pack",
    tags=["sector-tag", "regulation-type"],
)
```

Then add it to `PACK_REGISTRY` and, if appropriate, to `JURISDICTION_PACKS`.

### Step 3 — Compose a sector class (or update an existing one)

If the pack belongs to an existing sector (e.g. a new Nigerian fintech rule), add it to
`comply54/sectors/nigeria_fintech.py`. If it belongs to a new sector, create a new file
in `comply54/sectors/` following this pattern:

```python
from ..core.packs import MY_PACK, NDPA, PII_LEAKAGE, PROMPT_INJECTION, TOOL_PERMISSIONS, HUMAN_APPROVAL
from ._base import SectorCompliance

class NigeriaMyNewSectorCompliance(SectorCompliance):
    name = "Nigeria My Sector Compliance"
    jurisdictions = ["NG"]
    regulations = [
        "Full Regulation Name Year",
        "Nigeria Data Protection Act 2023",
        "OWASP Agentic AI",
    ]

    def __init__(self, strict_mode: bool = False) -> None:
        super().__init__(
            packs=[MY_PACK, NDPA, PII_LEAKAGE, PROMPT_INJECTION, TOOL_PERMISSIONS, HUMAN_APPROVAL],
            strict_mode=strict_mode,
        )
```

Export it from `comply54/sectors/__init__.py`.

### Step 4 — Write tests

Add tests to `tests/`. Aim for at least one test per `deny`, `escalate`, and `audit` rule
(both the triggering path and the safe path). Use pytest:

```python
from comply54.sectors import NigeriaMyNewSectorCompliance

compliance = NigeriaMyNewSectorCompliance()

def test_deny_rule_fires():
    result = compliance.check(
        action="dangerous_action",
        params={"amount": 9_999_999},
        context={"some_flag": False},
    )
    assert result.overall == "deny"
    assert "Regulation Name s.X" in result.primary_violation.messages[0]

def test_allow_when_compliant():
    result = compliance.check(
        action="safe_action",
        params={"amount": 100},
        context={"some_flag": True},
    )
    assert result.overall in ("allow", "audit")
```

Minimum 80% rule coverage. Every `deny` and `escalate` rule needs at least one test.

### Step 5 — Validate locally

```bash
pip install -e ".[dev]"

# Python tests
pytest tests/ -v

# OPA tests (requires opa binary)
opa test comply54/packs/ -v

# Rego lint
regal lint comply54/packs/<jurisdiction>/

# Verify imports
python -c "from comply54.sectors import NigeriaMyNewSectorCompliance; print('OK')"
```

### Step 6 — Open a Pull Request

Title format: `feat(nigeria): add <regulation-slug> policy pack`

Include in the PR description:
- Which regulation and sections are covered
- A link to the official regulatory source
- Test count and pass rate
- The `deny` / `escalate` / `audit` rules defined

---

## Adding a New Sector Composition

If you are composing existing packs into a new sector class without adding new Rego,
you only need Steps 3–5 above. The PR title format is:

`feat(sectors): add <JurisdictionName><SectorName>Compliance`

---

## Updating an Existing Pack

- Keep the `package` declaration unchanged — it is part of the `query_prefix` contract
- Add a comment citing the regulatory source that changed (e.g. a new CBN circular)
- Update the relevant `PackSpec.regulation` string in `packs.py` if the regulation name changed
- Add or update tests to cover the changed rule

---

## Commit Message Convention

```
feat(nigeria): add NAICOM insurance policy pack
fix(cbn): correct NIP cap threshold to ₦10,000,000
test(nha): add patient consent deny rule coverage
docs: update README sector packs table
```

---

## Code of Conduct

Be constructive and respectful. Policy interpretation is nuanced — always cite sources
when disagreeing about regulatory scope, and link to the official gazette or regulatory
circular rather than secondary sources.
