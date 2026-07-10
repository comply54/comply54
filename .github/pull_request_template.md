## Description

<!-- What does this PR do? Why is this change needed? Link to the relevant issue. -->

Closes #

## Type of change

- [ ] New jurisdiction pack (Rego + PackSpec + Python/TS evaluator)
- [ ] New sector class (`SectorCompliance` subclass)
- [ ] New framework adapter (LangChain, CrewAI, AutoGen, Semantic Kernel, etc.)
- [ ] New CLI feature
- [ ] Bug fix
- [ ] Documentation
- [ ] Other: <!-- describe -->

## Regulatory sources

<!-- Required for any pack contribution. Link to the official gazette or regulatory authority. -->

| Regulation | Section | Source URL |
|---|---|---|
|  |  |  |

## Checklist

- [ ] `pytest tests/ -q` passes locally
- [ ] `ruff check comply54/ tests/` passes
- [ ] TypeScript: `npm run typecheck && npm test` passes in `packages/core/` (if applicable)
- [ ] Every new `deny` and `escalate` rule has at least one test covering the trigger path and the safe path
- [ ] Regulatory source URL is included in the `PackSpec` entry (pack contributions)
- [ ] `CHANGELOG.md` updated
- [ ] Every commit has a `Signed-off-by:` line ([DCO](https://developercertificate.org))

## Fellowship (if applicable)

**Track:** <!-- Track 01 / 02 / 03 / 04 -->
