"""
comply54.core.citations
~~~~~~~~~~~~~~~~~~~~~~~
Per-rule regulatory citation registry for Phase 2 source traceability.

Maps "{pack_id}.{rule_key}" → list[RegulatorySource].
The engine resolves these keys after querying the {action}_citations sets
emitted by each Rego pack, then overwrites the pack-level citations on the
PolicyDecision with the narrower, rule-specific citations.
"""

from __future__ import annotations

from .models import RegulatorySource

_OWASP_URL = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"

RULE_CITATIONS: dict[str, list[RegulatorySource]] = {

    # ── nigeria/cbn ───────────────────────────────────────────────────────────
    "nigeria/cbn.maker_checker": [
        RegulatorySource(document="CBN Circular FPR/DIR/GEN/CIR/07/003", section="§3.1 — Maker-Checker Segregation", authority="CBN", year=2013),
    ],
    "nigeria/cbn.nip_cap": [
        RegulatorySource(document="CBN NIP (NIBSS Instant Payment) Framework", section="§4.2 — Per-Transaction Cap", authority="CBN", year=2011),
    ],
    "nigeria/cbn.nip_output": [
        RegulatorySource(document="CBN NIP (NIBSS Instant Payment) Framework", section="§4.2 — Per-Transaction Cap", authority="CBN", year=2011),
    ],
    "nigeria/cbn.tier3_daily": [
        RegulatorySource(document="CBN Circular FPR/DIR/GEN/CIR/07/003", section="§3.3 — Tier 3 Daily Limit (₦5M)", authority="CBN", year=2013),
    ],
    "nigeria/cbn.tier2_limit": [
        RegulatorySource(document="CBN Circular FPR/DIR/GEN/CIR/07/003", section="§3.2 — Tier 2 Daily Limit (₦200K)", authority="CBN", year=2013),
    ],
    "nigeria/cbn.tier1_limit": [
        RegulatorySource(document="CBN Circular FPR/DIR/GEN/CIR/07/003", section="§3.1 — Tier 1 Daily Limit (₦50K)", authority="CBN", year=2013),
    ],
    "nigeria/cbn.refund_approval": [
        RegulatorySource(document="CBN Circular FPR/DIR/GEN/CIR/07/003", section="§5.1 — Refund Controls", authority="CBN", year=2013),
    ],
    "nigeria/cbn.bulk_payment": [
        RegulatorySource(document="CBN Circular FPR/DIR/GEN/CIR/07/003", section="§6.2 — Bulk Payment Controls", authority="CBN", year=2013),
    ],
    "nigeria/cbn.ussd_review": [
        RegulatorySource(document="CBN USSD Banking Circular BSD/DIR/GEN/CIR/07/002", section="§5.2 — Per-Transaction and Daily Limits", authority="CBN", year=2019),
    ],
    "nigeria/cbn.financial_action_log": [
        RegulatorySource(document="CBN Circular FPR/DIR/GEN/CIR/07/003", section="§7.1 — Record Keeping for Examination", authority="CBN", year=2013),
    ],

    # ── nigeria/ndpa ──────────────────────────────────────────────────────────
    "nigeria/ndpa.cross_border_region": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§25 — Cross-Border Transfer Restrictions", authority="NDPC", year=2023),
    ],
    "nigeria/ndpa.cross_border_country": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§25 — Cross-Border Transfer Restrictions", authority="NDPC", year=2023),
    ],
    "nigeria/ndpa.bulk_export_action": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§24 — Data Minimisation Principle", authority="NDPC", year=2023),
    ],
    "nigeria/ndpa.large_record_export": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§24 — Data Minimisation Principle", authority="NDPC", year=2023),
    ],
    "nigeria/ndpa.biometric_output": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="Schedule 1 — Biometric Data as Sensitive Personal Data", authority="NDPC", year=2023),
    ],
    "nigeria/ndpa.breach_suppression": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§22(5) — 72-Hour Breach Notification", authority="NDPC", year=2023),
    ],
    "nigeria/ndpa.missing_destination": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§25 — Cross-Border Transfer Restrictions", authority="NDPC", year=2023),
    ],
    "nigeria/ndpa.cross_border_output_pattern": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§25 — Cross-Border Transfer Restrictions", authority="NDPC", year=2023),
    ],
    "nigeria/ndpa.health_data_output": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="Schedule 1 — Special Category Data", authority="NDPC", year=2023),
    ],
    "nigeria/ndpa.moderate_record_export": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§24 — Data Minimisation Principle", authority="NDPC", year=2023),
    ],
    "nigeria/ndpa.pii_access_log": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§30 — Controller Accountability", authority="NDPC", year=2023),
    ],
    "nigeria/ndpa.pii_modification_log": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§30 — Controller Accountability", authority="NDPC", year=2023),
    ],

    # ── nigeria/bvn-nin ───────────────────────────────────────────────────────
    "nigeria/bvn-nin.bvn_label_pattern": [
        RegulatorySource(document="CBN Regulatory Framework for BVN Operations 2014", section="§6 — BVN Confidentiality Obligations", authority="CBN", year=2014),
        RegulatorySource(document="NIBSS BVN Scheme Rules 2014", section="Rule 4.2 — Output Restrictions", authority="NIBSS", year=2014),
    ],
    "nigeria/bvn-nin.bvn_contextual_pattern": [
        RegulatorySource(document="CBN Regulatory Framework for BVN Operations 2014", section="§6 — BVN Confidentiality Obligations", authority="CBN", year=2014),
    ],
    "nigeria/bvn-nin.nin_label_pattern": [
        RegulatorySource(document="NIMC Act Cap N99 LFN 2004 (as amended)", section="§18 — NIN Confidentiality", authority="NIMC", year=2004),
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="Schedule 1 — Biometric Data", authority="NDPC", year=2023),
    ],
    "nigeria/bvn-nin.vnin_pattern": [
        RegulatorySource(document="NIMC Act Cap N99 LFN 2004 (as amended)", section="§18 — NIN Confidentiality", authority="NIMC", year=2004),
    ],
    "nigeria/bvn-nin.bvn_nin_transmission": [
        RegulatorySource(document="CBN Regulatory Framework for BVN Operations 2014", section="§6 — BVN Confidentiality Obligations", authority="CBN", year=2014),
        RegulatorySource(document="NIMC Act Cap N99 LFN 2004 (as amended)", section="§18 — NIN Confidentiality", authority="NIMC", year=2004),
    ],
    "nigeria/bvn-nin.bvn_in_params": [
        RegulatorySource(document="CBN Regulatory Framework for BVN Operations 2014", section="§6 — BVN Confidentiality Obligations", authority="CBN", year=2014),
    ],
    "nigeria/bvn-nin.bvn_social_engineering": [
        RegulatorySource(document="CBN Regulatory Framework for BVN Operations 2014", section="§6 — BVN Confidentiality Obligations", authority="CBN", year=2014),
        RegulatorySource(document="NIBSS BVN Scheme Rules 2014", section="Rule 4.2 — Output Restrictions", authority="NIBSS", year=2014),
    ],
    "nigeria/bvn-nin.bvn_verification": [
        RegulatorySource(document="CBN Regulatory Framework for BVN Operations 2014", section="§5 — BVN Lookup Audit Obligation", authority="CBN", year=2014),
    ],
    "nigeria/bvn-nin.nin_verification": [
        RegulatorySource(document="NIMC Act Cap N99 LFN 2004 (as amended)", section="§16 — NIN Verification Controls", authority="NIMC", year=2004),
    ],
    "nigeria/bvn-nin.identifier_gate": [
        RegulatorySource(document="CBN Regulatory Framework for BVN Operations 2014", section="§5 — BVN Lookup Audit Obligation", authority="CBN", year=2014),
        RegulatorySource(document="NIMC Act Cap N99 LFN 2004 (as amended)", section="§16 — NIN Verification Controls", authority="NIMC", year=2004),
    ],
    "nigeria/bvn-nin.identity_action_log": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§30 — Controller Accountability", authority="NDPC", year=2023),
        RegulatorySource(document="CBN Regulatory Framework for BVN Operations 2014", section="§7 — Audit Trail Requirement", authority="CBN", year=2014),
    ],

    # ── nigeria/nfiu-aml ──────────────────────────────────────────────────────
    "nigeria/nfiu-aml.nip_cap_block": [
        RegulatorySource(document="Money Laundering (Prevention and Prohibition) Act 2022", section="§10 — Currency Transaction Report Obligation", authority="NFIU", year=2022),
        RegulatorySource(document="CBN NIP (NIBSS Instant Payment) Framework", section="§4.2 — Per-Transaction Cap", authority="CBN", year=2011),
    ],
    "nigeria/nfiu-aml.structuring_pattern": [
        RegulatorySource(document="Money Laundering (Prevention and Prohibition) Act 2022", section="§14 — Structuring Offence", authority="NFIU", year=2022),
    ],
    "nigeria/nfiu-aml.kyc_bypass": [
        RegulatorySource(document="NFIU AML/CFT Compliance Framework 2022", section="§3.2 — Customer Due Diligence", authority="NFIU", year=2022),
    ],
    "nigeria/nfiu-aml.unverified_customer": [
        RegulatorySource(document="NFIU AML/CFT Compliance Framework 2022", section="§3.2 — Customer Due Diligence", authority="NFIU", year=2022),
    ],
    "nigeria/nfiu-aml.ctr_threshold": [
        RegulatorySource(document="Money Laundering (Prevention and Prohibition) Act 2022", section="§10 — Currency Transaction Report Obligation", authority="NFIU", year=2022),
    ],
    "nigeria/nfiu-aml.str_roundtrip": [
        RegulatorySource(document="Money Laundering (Prevention and Prohibition) Act 2022", section="§11 — Suspicious Transaction Report", authority="NFIU", year=2022),
    ],
    "nigeria/nfiu-aml.str_unknown_counterparty": [
        RegulatorySource(document="Money Laundering (Prevention and Prohibition) Act 2022", section="§11 — Suspicious Transaction Report", authority="NFIU", year=2022),
    ],
    "nigeria/nfiu-aml.str_crypto": [
        RegulatorySource(document="Money Laundering (Prevention and Prohibition) Act 2022", section="§11 — Suspicious Transaction Report", authority="NFIU", year=2022),
        RegulatorySource(document="NFIU AML/CFT Compliance Framework 2022", section="§4.3 — Virtual Asset STR", authority="NFIU", year=2022),
    ],
    "nigeria/nfiu-aml.pep_transaction": [
        RegulatorySource(document="Money Laundering (Prevention and Prohibition) Act 2022", section="§11 — Suspicious Transaction Report", authority="NFIU", year=2022),
        RegulatorySource(document="NFIU AML/CFT Compliance Framework 2022", section="§5.1 — PEP Enhanced Due Diligence", authority="NFIU", year=2022),
    ],
    "nigeria/nfiu-aml.financial_action_log": [
        RegulatorySource(document="Money Laundering (Prevention and Prohibition) Act 2022", section="§6 — 5-Year Record Retention", authority="NFIU", year=2022),
    ],
    "nigeria/nfiu-aml.structuring_zone": [
        RegulatorySource(document="Money Laundering (Prevention and Prohibition) Act 2022", section="§14 — Structuring Offence", authority="NFIU", year=2022),
        RegulatorySource(document="NFIU AML/CFT Compliance Framework 2022", section="§4.1 — STR Pattern Recognition", authority="NFIU", year=2022),
    ],

    # ── nigeria/nha ───────────────────────────────────────────────────────────
    "nigeria/nha.no_consent_access": [
        RegulatorySource(document="National Health Act 2014 (Act No. 8 of 2014)", section="§26 — Patient Consent for Record Access", authority="FMOH", year=2014),
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§30 — Special Category Health Data", authority="NDPC", year=2023),
    ],
    "nigeria/nha.no_consent_share": [
        RegulatorySource(document="National Health Act 2014 (Act No. 8 of 2014)", section="§29 — Confidentiality of Patient Information", authority="FMOH", year=2014),
    ],
    "nigeria/nha.cross_border_health": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§25 — Cross-Border Transfer of Special Category Data", authority="NDPC", year=2023),
        RegulatorySource(document="National Health Act 2014 (Act No. 8 of 2014)", section="§29 — Confidentiality of Patient Information", authority="FMOH", year=2014),
    ],
    "nigeria/nha.ai_diagnosis_no_oversight": [
        RegulatorySource(document="FMOH AI in Healthcare Policy (Draft 2024)", section="Guideline 4 — Mandatory Clinician Oversight", authority="FMOH", year=2024),
        RegulatorySource(document="Medical and Dental Practitioners Act Cap M8 LFN 2004", section="§16 — Restriction on Practice", authority="MDCN", year=2004),
    ],
    "nigeria/nha.ai_prescription": [
        RegulatorySource(document="Medical and Dental Practitioners Act Cap M8 LFN 2004", section="§16 — Restriction on Practice", authority="MDCN", year=2004),
        RegulatorySource(document="FMOH AI in Healthcare Policy (Draft 2024)", section="Guideline 7 — Autonomous Prescription Prohibition", authority="FMOH", year=2024),
    ],
    "nigeria/nha.diagnosis_with_oversight": [
        RegulatorySource(document="FMOH AI in Healthcare Policy (Draft 2024)", section="Guideline 4 — Clinician Sign-Off Requirement", authority="FMOH", year=2024),
    ],
    "nigeria/nha.high_risk_clinical": [
        RegulatorySource(document="National Health Act 2014 (Act No. 8 of 2014)", section="§26 — High-Risk Clinical Decisions", authority="FMOH", year=2014),
    ],
    "nigeria/nha.research_purpose": [
        RegulatorySource(document="National Health Act 2014 (Act No. 8 of 2014)", section="§26 — Research Ethics Requirement", authority="FMOH", year=2014),
    ],
    "nigeria/nha.bulk_access": [
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§30 — Bulk Special Category Data Access", authority="NDPC", year=2023),
    ],
    "nigeria/nha.record_access": [
        RegulatorySource(document="National Health Act 2014 (Act No. 8 of 2014)", section="§26 — Patient Record Access Controls", authority="FMOH", year=2014),
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="§30 — Controller Accountability", authority="NDPC", year=2023),
    ],
    "nigeria/nha.clinical_decision": [
        RegulatorySource(document="FMOH AI in Healthcare Policy (Draft 2024)", section="Guideline 4 — Clinical AI Decision Audit Trail", authority="FMOH", year=2024),
    ],

    # ── nigeria/naicom ────────────────────────────────────────────────────────
    "nigeria/naicom.auto_denial_cap": [
        RegulatorySource(document="NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section="Guideline 15 — Automated Denial Prohibition", authority="NAICOM", year=2021),
    ],
    "nigeria/naicom.discrimination": [
        RegulatorySource(document="Insurance Act 2003 (Cap I17 LFN 2004)", section="§67 — Anti-Discrimination in Underwriting", authority="NAICOM", year=2003),
        RegulatorySource(document="NAICOM Market Conduct and Business Practice Guidelines 2023", section="Rule 6 — Prohibited Pricing Factors", authority="NAICOM", year=2023),
    ],
    "nigeria/naicom.life_underwriting_cap": [
        RegulatorySource(document="NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section="Guideline 18 — Life Assurance Underwriting Cap", authority="NAICOM", year=2021),
    ],
    "nigeria/naicom.senior_review": [
        RegulatorySource(document="NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section="Guideline 12 — Senior Adjuster Review Threshold", authority="NAICOM", year=2021),
    ],
    "nigeria/naicom.fraud_human": [
        RegulatorySource(document="NAICOM Market Conduct and Business Practice Guidelines 2023", section="Rule 11 — Human Fraud Investigator Requirement", authority="NAICOM", year=2023),
    ],
    "nigeria/naicom.fraud_score": [
        RegulatorySource(document="NAICOM Market Conduct and Business Practice Guidelines 2023", section="Rule 11 — Fraud Investigation Escalation", authority="NAICOM", year=2023),
    ],
    "nigeria/naicom.policy_modification": [
        RegulatorySource(document="Insurance Act 2003 (Cap I17 LFN 2004)", section="§50 — Policy Alteration Notification", authority="NAICOM", year=2003),
    ],
    "nigeria/naicom.aml_threshold": [
        RegulatorySource(document="Money Laundering (Prevention and Prohibition) Act 2022", section="§10 — CTR Threshold", authority="NFIU", year=2022),
        RegulatorySource(document="NFIU AML/CFT Compliance Framework 2022", section="§6.1 — Insurance Sector AML Obligations", authority="NFIU", year=2022),
    ],
    "nigeria/naicom.sub_cap_denial": [
        RegulatorySource(document="NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section="Guideline 15 — Fair Claims Practice", authority="NAICOM", year=2021),
    ],
    "nigeria/naicom.claims_decision": [
        RegulatorySource(document="NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section="Guideline 12 — Claims Decision Records", authority="NAICOM", year=2021),
        RegulatorySource(document="Insurance Act 2003 (Cap I17 LFN 2004)", section="§70 — Claims Settlement Standards", authority="NAICOM", year=2003),
    ],
    "nigeria/naicom.claims_denial_log": [
        RegulatorySource(document="Insurance Act 2003 (Cap I17 LFN 2004)", section="§70 — Claims Settlement Standards", authority="NAICOM", year=2003),
        RegulatorySource(document="NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section="Guideline 15 — Denial Records", authority="NAICOM", year=2021),
    ],
    "nigeria/naicom.underwriting_decision": [
        RegulatorySource(document="NAICOM Operational Guidelines for the Conduct of Insurance Business 2021", section="Guideline 18 — Underwriting Decision Records", authority="NAICOM", year=2021),
    ],

    # ── universal/pii-leakage ─────────────────────────────────────────────────
    "universal/pii-leakage.pii_bvn": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM06:2025 — Sensitive Information Disclosure", authority="OWASP", year=2025, url=_OWASP_URL),
        RegulatorySource(document="CBN Regulatory Framework for BVN Operations 2014", section="§6 — BVN Confidentiality Obligations", authority="CBN", year=2014),
    ],
    "universal/pii-leakage.pii_nin": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM06:2025 — Sensitive Information Disclosure", authority="OWASP", year=2025, url=_OWASP_URL),
        RegulatorySource(document="NIMC Act Cap N99 LFN 2004 (as amended)", section="§18 — NIN Confidentiality", authority="NIMC", year=2004),
    ],
    "universal/pii-leakage.pii_pan": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM06:2025 — Sensitive Information Disclosure", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
    "universal/pii-leakage.pii_passport": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM06:2025 — Sensitive Information Disclosure", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
    "universal/pii-leakage.pii_id_number": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM06:2025 — Sensitive Information Disclosure", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
    "universal/pii-leakage.pii_moderate": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM06:2025 — Sensitive Information Disclosure", authority="OWASP", year=2025, url=_OWASP_URL),
    ],

    # ── universal/prompt-injection ────────────────────────────────────────────
    "universal/prompt-injection.prompt_injection": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM01:2025 — Prompt Injection", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
    "universal/prompt-injection.indirect_injection": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM01:2025 — Prompt Injection (Indirect)", authority="OWASP", year=2025, url=_OWASP_URL),
    ],

    # ── universal/tool-permissions ────────────────────────────────────────────
    "universal/tool-permissions.tool_out_of_scope": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM08:2025 — Excessive Agency", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
    "universal/tool-permissions.tool_idor": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM08:2025 — Excessive Agency (IDOR)", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
    "universal/tool-permissions.tool_bulk_read": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM08:2025 — Excessive Agency", authority="OWASP", year=2025, url=_OWASP_URL),
    ],

    # ── universal/human-approval ──────────────────────────────────────────────
    "universal/human-approval.human_approval_irreversible": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM08:2025 — Excessive Agency (Irreversible Actions)", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
    "universal/human-approval.human_approval_high_value": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM08:2025 — Excessive Agency (High-Value Transfers)", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
    "universal/human-approval.human_approval_bulk": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM08:2025 — Excessive Agency (Bulk Operations)", authority="OWASP", year=2025, url=_OWASP_URL),
    ],

    # ── universal/model-routing ───────────────────────────────────────────────
    "universal/model-routing.model_routing_biometric": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM09:2025 — Misinformation", authority="OWASP", year=2025, url=_OWASP_URL),
        RegulatorySource(document="Nigeria Data Protection Act 2023", section="Schedule 1 — Biometric Data", authority="NDPC", year=2023),
    ],
    "universal/model-routing.model_routing_region": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM09:2025 — Misinformation", authority="OWASP", year=2025, url=_OWASP_URL),
    ],
    "universal/model-routing.model_routing_no_dpa": [
        RegulatorySource(document="OWASP Top 10 for LLM Applications 2025", section="LLM09:2025 — Misinformation", authority="OWASP", year=2025, url=_OWASP_URL),
    ],

    # ── kenya/kdpa ────────────────────────────────────────────────────────────
    "kenya/kdpa.breach_suppression": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§41 — Breach Notification Obligation", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.cross_border_region": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§49 — Cross-Border Transfer", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.cross_border_country": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§49 — Cross-Border Transfer", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.no_consent_processing": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§26 — Lawful Processing", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.biometric_output": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§25 — Sensitive Personal Data", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.national_id_output": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§25 — Sensitive Personal Data", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.large_record_export": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§30 — Data Minimisation", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.health_data_output": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§25 — Sensitive Personal Data", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.special_category_output": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§25 — Sensitive Personal Data", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.cross_border_output_pattern": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§49 — Cross-Border Transfer", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.missing_destination": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§49 — Cross-Border Transfer", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.moderate_record_export": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§30 — Data Minimisation", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.bulk_export_action": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§30 — Data Minimisation", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.pii_access_log": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§31 — Accountability", authority="ODPC", year=2019),
    ],
    "kenya/kdpa.pii_modification_log": [
        RegulatorySource(document="Kenya Data Protection Act 2019 (Act No. 24 of 2019)", section="§31 — Accountability", authority="ODPC", year=2019),
    ],

    # ── south-africa/popia ────────────────────────────────────────────────────
    "south-africa/popia.breach_suppression": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§22 — Security Compromise Notification", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.cross_border_region": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§72 — Transborder Information Flows", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.cross_border_country": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§72 — Transborder Information Flows", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.biometric_output": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§26 — Prohibition on Processing Special Personal Information", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.sa_id_output": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§26 — Prohibition on Processing Special Personal Information", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.large_record_export": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§10 — Further Processing Limitation", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.no_lawful_basis": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§11 — Conditions for Lawful Processing", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.health_data_output": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§26 — Special Personal Information", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.cross_border_output_pattern": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§72 — Transborder Information Flows", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.missing_destination": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§72 — Transborder Information Flows", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.moderate_record_export": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§10 — Further Processing Limitation", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.bulk_export_action": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§10 — Further Processing Limitation", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.pii_access_log": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§8 — Accountability", authority="Information Regulator ZA", year=2013),
    ],
    "south-africa/popia.pii_modification_log": [
        RegulatorySource(document="Protection of Personal Information Act 4 of 2013 (POPIA)", section="§8 — Accountability", authority="Information Regulator ZA", year=2013),
    ],

    # ── ghana/dpa ─────────────────────────────────────────────────────────────
    "ghana/dpa.breach_suppression": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§29 — Security Breach Notification", authority="DPC Ghana", year=2012),
    ],
    "ghana/dpa.cross_border_region": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§33 — Cross-Border Transfer", authority="DPC Ghana", year=2012),
    ],
    "ghana/dpa.cross_border_country": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§33 — Cross-Border Transfer", authority="DPC Ghana", year=2012),
    ],
    "ghana/dpa.biometric_output": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§30 — Sensitive Personal Data", authority="DPC Ghana", year=2012),
    ],
    "ghana/dpa.large_record_export": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§18 — Data Minimisation", authority="DPC Ghana", year=2012),
    ],
    "ghana/dpa.no_consent_processing": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§17 — Consent Requirement", authority="DPC Ghana", year=2012),
    ],
    "ghana/dpa.health_data_output": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§30 — Sensitive Personal Data", authority="DPC Ghana", year=2012),
    ],
    "ghana/dpa.cross_border_output_pattern": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§33 — Cross-Border Transfer", authority="DPC Ghana", year=2012),
    ],
    "ghana/dpa.missing_destination": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§33 — Cross-Border Transfer", authority="DPC Ghana", year=2012),
    ],
    "ghana/dpa.moderate_record_export": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§18 — Data Minimisation", authority="DPC Ghana", year=2012),
    ],
    "ghana/dpa.bulk_export_action": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§18 — Data Minimisation", authority="DPC Ghana", year=2012),
    ],
    "ghana/dpa.pii_access_log": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§15 — Accountability", authority="DPC Ghana", year=2012),
    ],
    "ghana/dpa.pii_modification_log": [
        RegulatorySource(document="Ghana Data Protection Act 2012 (Act 843)", section="§15 — Accountability", authority="DPC Ghana", year=2012),
    ],

    # ── rwanda/dpa ────────────────────────────────────────────────────────────
    "rwanda/dpa.breach_suppression": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 30 — Breach Notification", authority="RISA", year=2021),
    ],
    "rwanda/dpa.cross_border_region": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 22 — Cross-Border Transfer", authority="RISA", year=2021),
    ],
    "rwanda/dpa.cross_border_country": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 22 — Cross-Border Transfer", authority="RISA", year=2021),
    ],
    "rwanda/dpa.biometric_output": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 12 — Sensitive Personal Data", authority="RISA", year=2021),
    ],
    "rwanda/dpa.large_record_export": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 8 — Data Minimisation", authority="RISA", year=2021),
    ],
    "rwanda/dpa.no_consent_processing": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 8 — Consent Requirement", authority="RISA", year=2021),
    ],
    "rwanda/dpa.health_data_output": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 12 — Sensitive Personal Data", authority="RISA", year=2021),
    ],
    "rwanda/dpa.cross_border_output_pattern": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 22 — Cross-Border Transfer", authority="RISA", year=2021),
    ],
    "rwanda/dpa.missing_destination": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 22 — Cross-Border Transfer", authority="RISA", year=2021),
    ],
    "rwanda/dpa.moderate_record_export": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 8 — Data Minimisation", authority="RISA", year=2021),
    ],
    "rwanda/dpa.bulk_export_action": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 8 — Data Minimisation", authority="RISA", year=2021),
    ],
    "rwanda/dpa.pii_access_log": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 5 — Accountability", authority="RISA", year=2021),
    ],
    "rwanda/dpa.pii_modification_log": [
        RegulatorySource(document="Law No. 058/2021 of 13/10/2021 on Protection of Personal Data and Privacy", section="Art. 5 — Accountability", authority="RISA", year=2021),
    ],

    # ── egypt/pdpl ────────────────────────────────────────────────────────────
    "egypt/pdpl.egypt_localisation": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 3 — Data Localisation for Financial Data", authority="PDPRL Egypt", year=2020),
    ],
    "egypt/pdpl.cross_border_region": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 24 — Cross-Border Transfer", authority="PDPRL Egypt", year=2020),
    ],
    "egypt/pdpl.cross_border_country": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 24 — Cross-Border Transfer", authority="PDPRL Egypt", year=2020),
    ],
    "egypt/pdpl.biometric_output": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 4 — Sensitive Personal Data", authority="PDPRL Egypt", year=2020),
    ],
    "egypt/pdpl.large_record_export": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 6 — Data Minimisation", authority="PDPRL Egypt", year=2020),
    ],
    "egypt/pdpl.no_consent_processing": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 3 — Lawful Processing Bases", authority="PDPRL Egypt", year=2020),
    ],
    "egypt/pdpl.health_data_output": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 4 — Sensitive Personal Data", authority="PDPRL Egypt", year=2020),
    ],
    "egypt/pdpl.cross_border_output_pattern": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 24 — Cross-Border Transfer", authority="PDPRL Egypt", year=2020),
    ],
    "egypt/pdpl.missing_destination": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 24 — Cross-Border Transfer", authority="PDPRL Egypt", year=2020),
    ],
    "egypt/pdpl.moderate_record_export": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 6 — Data Minimisation", authority="PDPRL Egypt", year=2020),
    ],
    "egypt/pdpl.bulk_export_action": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 6 — Data Minimisation", authority="PDPRL Egypt", year=2020),
    ],
    "egypt/pdpl.pii_access_log": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 7 — Accountability", authority="PDPRL Egypt", year=2020),
    ],
    "egypt/pdpl.pii_modification_log": [
        RegulatorySource(document="Personal Data Protection Law No. 151 of 2020", section="Art. 7 — Accountability", authority="PDPRL Egypt", year=2020),
    ],

    # ── ethiopia/pdp ──────────────────────────────────────────────────────────
    "ethiopia/pdp.breach_suppression": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 28 — Breach Notification", authority="ECA", year=2024),
    ],
    "ethiopia/pdp.cross_border_region": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 22 — Cross-Border Transfer", authority="ECA", year=2024),
    ],
    "ethiopia/pdp.cross_border_country": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 22 — Cross-Border Transfer", authority="ECA", year=2024),
    ],
    "ethiopia/pdp.biometric_output": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 16 — Sensitive Personal Data", authority="ECA", year=2024),
    ],
    "ethiopia/pdp.large_record_export": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 10 — Data Minimisation", authority="ECA", year=2024),
    ],
    "ethiopia/pdp.no_consent_processing": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 9 — Lawful Processing Basis", authority="ECA", year=2024),
    ],
    "ethiopia/pdp.health_data_output": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 16 — Sensitive Personal Data", authority="ECA", year=2024),
    ],
    "ethiopia/pdp.cross_border_output_pattern": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 22 — Cross-Border Transfer", authority="ECA", year=2024),
    ],
    "ethiopia/pdp.missing_destination": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 22 — Cross-Border Transfer", authority="ECA", year=2024),
    ],
    "ethiopia/pdp.moderate_record_export": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 10 — Data Minimisation", authority="ECA", year=2024),
    ],
    "ethiopia/pdp.bulk_export_action": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 10 — Data Minimisation", authority="ECA", year=2024),
    ],
    "ethiopia/pdp.pii_access_log": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 11 — Accountability", authority="ECA", year=2024),
    ],
    "ethiopia/pdp.pii_modification_log": [
        RegulatorySource(document="Personal Data Protection Proclamation No. 1321/2024", section="Art. 11 — Accountability", authority="ECA", year=2024),
    ],

    # ── mauritius/dpa ─────────────────────────────────────────────────────────
    "mauritius/dpa.breach_suppression": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§22 — Notification of Breach", authority="DPC Mauritius", year=2017),
    ],
    "mauritius/dpa.cross_border_region": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§46 — Transfer of Personal Data", authority="DPC Mauritius", year=2017),
    ],
    "mauritius/dpa.cross_border_country": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§46 — Transfer of Personal Data", authority="DPC Mauritius", year=2017),
    ],
    "mauritius/dpa.biometric_output": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§28 — Sensitive Personal Data", authority="DPC Mauritius", year=2017),
    ],
    "mauritius/dpa.large_record_export": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§17 — Data Minimisation", authority="DPC Mauritius", year=2017),
    ],
    "mauritius/dpa.no_lawful_basis": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§18 — Conditions for Processing", authority="DPC Mauritius", year=2017),
    ],
    "mauritius/dpa.health_data_output": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§28 — Sensitive Personal Data", authority="DPC Mauritius", year=2017),
    ],
    "mauritius/dpa.cross_border_output_pattern": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§46 — Transfer of Personal Data", authority="DPC Mauritius", year=2017),
    ],
    "mauritius/dpa.missing_destination": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§46 — Transfer of Personal Data", authority="DPC Mauritius", year=2017),
    ],
    "mauritius/dpa.moderate_record_export": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§17 — Data Minimisation", authority="DPC Mauritius", year=2017),
    ],
    "mauritius/dpa.bulk_export_action": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§17 — Data Minimisation", authority="DPC Mauritius", year=2017),
    ],
    "mauritius/dpa.pii_access_log": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§10 — Accountability", authority="DPC Mauritius", year=2017),
    ],
    "mauritius/dpa.pii_modification_log": [
        RegulatorySource(document="Data Protection Act 2017 (Act 20 of 2017)", section="§10 — Accountability", authority="DPC Mauritius", year=2017),
    ],

    # ── tanzania/pdpa ─────────────────────────────────────────────────────────
    "tanzania/pdpa.breach_suppression": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§38 — Breach Notification", authority="PDPC Tanzania", year=2022),
    ],
    "tanzania/pdpa.cross_border_region": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§32 — Cross-Border Transfer", authority="PDPC Tanzania", year=2022),
    ],
    "tanzania/pdpa.cross_border_country": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§32 — Cross-Border Transfer", authority="PDPC Tanzania", year=2022),
    ],
    "tanzania/pdpa.biometric_output": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§24 — Sensitive Personal Data", authority="PDPC Tanzania", year=2022),
    ],
    "tanzania/pdpa.large_record_export": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§18 — Data Minimisation", authority="PDPC Tanzania", year=2022),
    ],
    "tanzania/pdpa.no_consent_processing": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§16 — Lawful Processing", authority="PDPC Tanzania", year=2022),
    ],
    "tanzania/pdpa.health_data_output": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§24 — Sensitive Personal Data", authority="PDPC Tanzania", year=2022),
    ],
    "tanzania/pdpa.cross_border_output_pattern": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§32 — Cross-Border Transfer", authority="PDPC Tanzania", year=2022),
    ],
    "tanzania/pdpa.missing_destination": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§32 — Cross-Border Transfer", authority="PDPC Tanzania", year=2022),
    ],
    "tanzania/pdpa.moderate_record_export": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§18 — Data Minimisation", authority="PDPC Tanzania", year=2022),
    ],
    "tanzania/pdpa.bulk_export_action": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§18 — Data Minimisation", authority="PDPC Tanzania", year=2022),
    ],
    "tanzania/pdpa.pii_access_log": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§20 — Accountability", authority="PDPC Tanzania", year=2022),
    ],
    "tanzania/pdpa.pii_modification_log": [
        RegulatorySource(document="Personal Data Protection Act No. 11 of 2022", section="§20 — Accountability", authority="PDPC Tanzania", year=2022),
    ],

    # ── uganda/dppa ───────────────────────────────────────────────────────────
    "uganda/dppa.breach_suppression": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§31 — Breach Notification", authority="PDPO Uganda", year=2019),
    ],
    "uganda/dppa.cross_border_region": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§26 — Cross-Border Transfer", authority="PDPO Uganda", year=2019),
    ],
    "uganda/dppa.cross_border_country": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§26 — Cross-Border Transfer", authority="PDPO Uganda", year=2019),
    ],
    "uganda/dppa.biometric_output": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§20 — Sensitive Personal Data", authority="PDPO Uganda", year=2019),
    ],
    "uganda/dppa.large_record_export": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§15 — Data Minimisation", authority="PDPO Uganda", year=2019),
    ],
    "uganda/dppa.no_consent_processing": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§14 — Lawful Processing", authority="PDPO Uganda", year=2019),
    ],
    "uganda/dppa.health_data_output": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§20 — Sensitive Personal Data", authority="PDPO Uganda", year=2019),
    ],
    "uganda/dppa.cross_border_output_pattern": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§26 — Cross-Border Transfer", authority="PDPO Uganda", year=2019),
    ],
    "uganda/dppa.missing_destination": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§26 — Cross-Border Transfer", authority="PDPO Uganda", year=2019),
    ],
    "uganda/dppa.moderate_record_export": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§15 — Data Minimisation", authority="PDPO Uganda", year=2019),
    ],
    "uganda/dppa.bulk_export_action": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§15 — Data Minimisation", authority="PDPO Uganda", year=2019),
    ],
    "uganda/dppa.pii_access_log": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§17 — Accountability", authority="PDPO Uganda", year=2019),
    ],
    "uganda/dppa.pii_modification_log": [
        RegulatorySource(document="Data Protection and Privacy Act 2019 (Act 9 of 2019)", section="§17 — Accountability", authority="PDPO Uganda", year=2019),
    ],
}
