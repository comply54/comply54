# Contributing to Comply54

Comply54 is a community-maintained open-source project. Contributions — new policy packs, fixes to existing policies, and adapter improvements — are welcome.

## Before You Submit

- Comply54 policy packs are governance **starter templates**, not certified legal instruments.
- Regulatory thresholds change. Always cite the section number you are implementing, and include a `regulatory_source` URL in `meta.json`.
- All contributions must pass CI (schema validation, OPA tests, Regal lint) before merging.

## Adding a New Policy Pack

### 1. Create the pack directory

```
packages/<jurisdiction>/<regulation-slug>/
├── policy.yaml           # required
├── policy.rego           # required (OPA reference implementation)
├── meta.json             # required
└── tests/
    └── policy_test.rego  # required (min. 80% rule coverage)
```

Where `<jurisdiction>` is the ISO 3166-1 alpha-2 code (e.g. `NG`, `KE`, `ZA`) or `universal`.

### 2. Write policy.yaml

Every `policy.yaml` must validate against `schema/policy.schema.json`. Key requirements:
- `version`, `name`, `description`, `rules`, `defaults` are all required
- Each rule must have a `condition: {field, operator, value}` block
- `action` must be one of: `allow`, `deny`, `audit`, `block`
- Include a `metadata` block with `source_regulation`, `jurisdiction`, `enforcing_authority`

```yaml
version: "1.0"
name: my-policy
description: >
  One paragraph describing what this policy enforces and why.

metadata:
  source_regulation: "Act Name Year — section reference"
  jurisdiction: "NG"
  enforcing_authority: "Authority Name"

rules:
  - name: rule-slug
    condition:
      field: action         # action | output | input | context | tool | model
      operator: matches     # matches | equals | in | not_in | contains
      value: "^regex$"
    action: block           # allow | deny | audit | block
    priority: 90
    message: "Clear explanation shown to callers when this rule fires"

defaults:
  action: audit
```

### 3. Write meta.json

Required fields:

```json
{
  "id": "comply54-<jurisdiction>-<slug>",
  "version": "1.0.0",
  "jurisdiction": "NG",
  "regulation": "Full regulation name",
  "short_name": "Short name",
  "enforcing_authority": "Authority Name",
  "effective_date": "YYYY-MM-DD",
  "last_updated": "YYYY-MM-DD",
  "regulatory_source": "https://official-source.gov",
  "sections_covered": ["s.25", "s.30"],
  "agt_compatible": true,
  "rego_tests": 0,
  "breaking_changes": false,
  "tags": ["keyword1", "keyword2"]
}
```

### 4. Write OPA tests

Tests live in `tests/policy_test.rego`. Each test rule must start with `test_`. Aim for at least one test per rule (allow path + deny path).

```rego
package comply54.<pack_name>_test

import rego.v1

test_rule_name_blocks_bad_action if {
    decision := decide with input as {
        "action": "dangerous_action",
        "output": "",
    }
    decision.action == "block"
}

test_rule_name_allows_safe_action if {
    decision := decide with input as {
        "action": "read_record",
        "output": "",
    }
    decision.action != "block"
}
```

### 5. Validate locally

```bash
# Install deps
pip install pyyaml jsonschema

# Validate schemas
python tools/validate.py

# Run OPA tests
opa test packages/<jurisdiction>/<slug>/ -v

# Lint Rego
regal lint packages/<jurisdiction>/<slug>/

# Regenerate registry
python tools/generate_registry.py
```

### 6. Open a Pull Request

Title format: `feat(<jurisdiction>): add <regulation-slug> policy pack`

Include in the PR description:
- Which regulation / sections are covered
- A link to the official regulatory source
- Test count and pass rate

## Updating an Existing Pack

- Bump `version` in both `meta.json` and `policy.yaml` following semver
- Set `breaking_changes: true` in `meta.json` if any rule `name` or `action` changes
- Update `last_updated` in `meta.json`

## Code of Conduct

Be constructive and respectful. Policy interpretation can be nuanced — cite sources when disagreeing about regulatory scope.
