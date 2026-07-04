# Security Policy

## Supported Versions

Security fixes are applied to the latest release only. We do not backport fixes to older minor versions.

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅ Yes     |
| < 0.3   | ❌ No      |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a vulnerability, use one of the following:

- **GitHub private vulnerability reporting** (preferred): [Report a vulnerability](https://github.com/comply54/comply54/security/advisories/new)
- **Email**: ginuxtechacademy@gmail.com — include `[SECURITY comply54]` in the subject line

### What to include

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The version of comply54 affected
- Any suggested fix, if you have one

### What to expect

| Timeline | Action |
|---|---|
| Within 48 hours | Acknowledgement of your report |
| Within 7 days | Initial assessment and severity triage |
| Within 30 days | Patch released (critical/high) or fix scheduled (medium/low) |
| After patch release | Public disclosure coordinated with reporter |

We follow responsible disclosure: we will not take legal action against researchers who report vulnerabilities in good faith and follow this policy.

## Scope

In scope:
- Rego policy evaluation logic producing incorrect allow/deny/escalate decisions
- Authentication or authorisation bypass in the comply54 engine
- Dependency vulnerabilities with a known CVE that affect comply54 at runtime
- Information disclosure in compliance certificates or audit logs

Out of scope:
- Vulnerabilities in the OPA runtime itself (report upstream to [OPA](https://github.com/open-policy-agent/opa/security))
- Issues requiring physical access to the host
- Social engineering attacks

## Dependency Security

comply54 uses [Dependabot](https://docs.github.com/en/code-security/dependabot) and GitHub Security Advisories to track CVEs in dependencies. Known vulnerabilities are tracked via GitHub's dependency graph and addressed in the next release.

We cross-reference dependencies against [OSV](https://osv.dev) and the [NIST NVD](https://nvd.nist.gov) CWE/CVE database for each release.

## Cryptography

comply54 does not implement custom cryptographic algorithms. Any cryptographic operations (e.g. HTTPS delivery via PyPI, certificate signing) are delegated to well-audited system libraries.
