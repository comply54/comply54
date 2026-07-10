# Contributing to comply54

comply54 is a community-maintained open-source project. Contributions — new jurisdiction packs, sector compositions, framework adapters, engine features, and bug fixes — are welcome.

**New to open source?** Issues labelled [`good first issue`](https://github.com/comply54/comply54/labels/good%20first%20issue) are scoped to be completable in a few days with no prior comply54 knowledge.

---

## Before you start

### DCO sign-off (required)

Every commit in a PR must carry a `Signed-off-by:` line. This certifies that you wrote the code or have the right to submit it under the project license, per the [Developer Certificate of Origin](https://developercertificate.org).

```
feat(africa): add Senegal LPDP pack

Signed-off-by: Your Name <you@example.com>
```

**How to add it:**

```bash
# Sign off a single commit
git commit --signoff -m "feat(africa): add Senegal LPDP pack"

# Sign off your last commit retroactively
git commit --amend --signoff

# Sign off every commit in the PR at once
git rebase --signoff HEAD~<number-of-commits>

# Auto sign-off all future commits in this repo
git config format.signoff true
```

The `dco` CI job will fail and block merge if any commit is missing the sign-off.

### Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md). Be constructive and respectful. Policy interpretation is nuanced — always cite sources when disagreeing about regulatory scope, and link to the official gazette rather than secondary sources.

### comply54 Open Source Fellowship

A number of open issues are tagged [`fellowship`](https://github.com/comply54/comply54/labels/fellowship) as part of the comply54 Open Source Fellowship. If you are applying or contributing through the fellowship programme, pick one of these issues and mention the fellowship track in your PR. Visit [comply54.io/fellowship](https://comply54.io/fellowship) to learn more.

---

## Dev environment setup

### Python

```bash
git clone https://github.com/comply54/comply54.git
cd comply54

python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Verify
pytest tests/ -q                       # all tests
ruff check comply54/ tests/            # lint
```

### TypeScript

```bash
cd packages/core
npm install

npm run typecheck                      # tsc --noEmit
npm test                               # vitest run
```

### Rego (optional, for pack development)

```bash
# Install OPA
curl -sSL -o /usr/local/bin/opa \
  https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x /usr/local/bin/opa

opa check comply54/packs/              # syntax check
opa test comply54/packs/ -v            # run _test.rego files
regal lint comply54/packs/<jurisdiction>/   # lint (install: https://docs.styra.com/regal)
```

---

## Repository structure

```
comply54/
├── comply54/
│   ├── packs/
│   │   ├── nigeria/          ← Nigerian regulatory Rego packs
│   │   ├── africa/           ← Other African jurisdiction Rego packs
│   │   └── universal/        ← Framework-agnostic safety packs
│   ├── core/
│   │   ├── engine.py         ← Comply54Engine
│   │   ├── packs.py          ← PackSpec registry (add new packs here)
│   │   └── types.py          ← ComplianceResult and related types
│   ├── sectors/
│   │   ├── _base.py          ← SectorCompliance base class
│   │   ├── nigeria_fintech.py
│   │   └── ...
│   ├── langchain/            ← LangChain / LangGraph adapter
│   ├── crewai/               ← CrewAI adapter
│   └── autogen/              ← AutoGen adapter
├── packages/
│   └── core/
│       └── src/
│           ├── engine.ts
│           ├── packs/        ← TypeScript pack evaluators
│           └── sectors/      ← TypeScript sector classes
└── tests/
```

---

## Adding a new jurisdiction pack

### Step 1 — Write the Rego file

Create `comply54/packs/<jurisdiction>/<pack_slug>.rego`. Use `snake_case` for the filename.

The package declaration must follow the convention:
- Nigerian packs: `package agt_policies_nigeria.<slug>`
- African packs: `package agt_policies_africa.<slug>`
- Universal packs: `package agt_policies_agent.<slug>`

Every pack must define these four rule sets and a `decision` summary:

```rego
package agt_policies_africa.senegal_lpdp

import rego.v1

# ── DENY: hard blocks (never execute) ─────────────────────────────────────────
deny contains msg if {
    # condition
    msg := "Senegal LPDP 2008 Art.X: clear message explaining what was blocked and why"
}

# ── ESCALATE: route to human review ───────────────────────────────────────────
escalate contains msg if {
    # condition
    msg := "Senegal LPDP 2008 Art.Y: reason this requires a human decision"
}

# ── AUDIT: always log regardless of outcome ───────────────────────────────────
audit contains msg if {
    # condition
    msg := "Senegal LPDP 2008: action logged for regulatory examination"
}

# ── Decision summary (required) ────────────────────────────────────────────────
decision := "deny"    if count(deny) > 0
decision := "escalate" if { count(deny) == 0; count(escalate) > 0 }
decision := "audit"   if { count(deny) == 0; count(escalate) == 0; count(audit) > 0 }
decision := "allow"   if { count(deny) == 0; count(escalate) == 0; count(audit) == 0 }
```

**Guidelines:**
- Every `msg` string must cite the regulation and section by name and number
- Check `input.params` fields directly — avoid regex on `input.output` unless there is no structured alternative
- Define thresholds as named constants at the top (`max_transfer_amount := 5_000_000`)
- Group related action names into named sets (`transfer_actions := {"transfer_funds", "send_money"}`)

### Step 2 — Add a PackSpec entry

Open `comply54/core/packs.py` and add a `PackSpec`:

```python
SENEGAL_LPDP = PackSpec(
    id="senegal/lpdp",
    regulation="Senegal Loi n° 2008-12 sur la Protection des Données à Caractère Personnel",
    jurisdiction="SN",
    authority="CDP Senegal",
    rego_path=_PACKS_DIR / "africa" / "senegal_lpdp.rego",
    query_prefix="data.agt_policies_africa.senegal_lpdp",
    tags=["data-protection", "west-africa"],
    sources=[
        RegulatorySource(
            document="Loi n° 2008-12 du 25 janvier 2008",
            section="Art. 6",
            authority="CDP Senegal",
            year=2008,
            url="https://...",
        ),
    ],
)
```

Add it to `PACK_REGISTRY` and to `JURISDICTION_PACKS`.

### Step 3 — Add the Python evaluator

Open `comply54/packs/africa.py` (or the relevant file) and add:

```python
def evaluateSenegalLPDP(input: EvaluationInput) -> PolicyDecision:
    return _evaluate(SENEGAL_LPDP, input)
```

Export it from `comply54/__init__.py`.

### Step 4 — Add the TypeScript evaluator

Open `packages/core/src/packs/africa.ts` and add:

```typescript
export const evaluateSenegalLPDP: PackEvaluatorFn = (input) =>
  _evaluateAfrica("senegal/lpdp", input);
```

Export it from `packages/core/src/index.ts`.

### Step 5 — Write tests

Add tests to `tests/test_africa.py`. Aim for at least one `deny`, one `escalate`, one `audit`, and one clean `allow` per rule.

```python
from comply54.packs.africa import evaluateSenegalLPDP
from comply54.core.engine import Comply54Engine

engine = Comply54Engine(packs=[evaluateSenegalLPDP])

def test_deny_fires_on_unconsented_processing():
    result = engine.check(
        action="process_personal_data",
        params={"has_consent": False, "data_type": "personal"},
    )
    assert result.overall == "deny"
    assert "LPDP" in result.primary_violation.messages[0]

def test_allow_when_consent_given():
    result = engine.check(
        action="process_personal_data",
        params={"has_consent": True, "data_type": "personal"},
    )
    assert result.overall in ("allow", "audit")
```

Minimum: 80% rule coverage. Every `deny` and `escalate` rule needs at least one test.

### Step 6 — Validate locally

```bash
# Python tests
pytest tests/ -q

# Rego syntax
opa check comply54/packs/africa/senegal_lpdp.rego

# Lint
ruff check comply54/ tests/

# TypeScript
cd packages/core && npm run typecheck && npm test
```

### Step 7 — Open a pull request

Use the PR template. Title format: `feat(africa): add <regulation-slug> policy pack`

---

## Adding a new sector class

If you are composing existing packs into a new sector (no new Rego), you only need Steps 3–6. PR title: `feat(sectors): add <JurisdictionName><SectorName>Compliance`

```python
from ..core.packs import SENEGAL_LPDP, PII_LEAKAGE, PROMPT_INJECTION, TOOL_PERMISSIONS, HUMAN_APPROVAL
from ._base import SectorCompliance

class SenegalFintechCompliance(SectorCompliance):
    name = "Senegal Fintech Compliance"
    jurisdictions = ["SN"]
    regulations = [
        "Senegal Loi n° 2008-12 (LPDP)",
        "OWASP Agentic AI",
    ]

    def __init__(self, strict_mode: bool = False) -> None:
        super().__init__(
            packs=[SENEGAL_LPDP, PII_LEAKAGE, PROMPT_INJECTION, TOOL_PERMISSIONS, HUMAN_APPROVAL],
            strict_mode=strict_mode,
        )
```

Export from `comply54/sectors/__init__.py`.

---

## Adding a framework adapter

Each adapter lives in its own sub-package (`comply54/langchain/`, `comply54/crewai/`, etc.) and intercepts tool calls or agent steps to run a comply54 compliance check before execution.

Follow the shape of `comply54/langchain/guard.py` as the reference implementation. The adapter must:
- Accept a `Comply54Engine` or sector class at construction time
- Not import the framework at module level — use a lazy import with a clear `ImportError` hint
- Be listed as an optional dependency in `pyproject.toml`
- Have integration tests (can mock the framework internals)

---

## Updating an existing pack

- Keep the `package` declaration unchanged — it is part of the `query_prefix` contract
- Add a comment citing the regulatory source that changed (e.g. a new CBN circular)
- Update the `PackSpec.regulation` string if the regulation name changed
- Bump the pack version in `comply54/core/packs.py` and `packages/core/src/packs/versions.ts`
- Add or update tests to cover the changed rule

---

## Commit message convention

```
feat(africa):    add Senegal LPDP pack
feat(nigeria):   add NAICOM insurance policy pack
feat(sectors):   add KenyaHealthcareCompliance sector class
feat(adapters):  add Semantic Kernel integration
fix(cbn):        correct NIP cap threshold to ₦10,000,000
test(nha):       add patient consent deny rule coverage
docs:            update README sector packs table
chore:           bump version to 0.6.0
```

---

## Pull requests

- Use the PR template — it is pre-populated when you open a PR on GitHub
- Keep PRs focused: one pack, one adapter, or one feature per PR
- Mark as Draft until all checklist items are green
- At least one maintainer review is required before merge

---

## Questions?

Open a [GitHub Discussion](https://github.com/comply54/comply54/discussions) or join the conversation in the relevant issue thread.
