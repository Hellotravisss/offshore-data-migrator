"""
Jurisdiction compliance profiles for data migration.

Supported jurisdictions:
  - GDPR  (European Union)
  - PDPA  (Singapore)
  - CCPA  (California, USA)
  - LGPD  (Brazil)
  - PIPL  (China)

Each profile defines which PII fields MUST be masked, optional fields,
retention policies, and encryption requirements.
"""

from __future__ import annotations
from datetime import datetime, timezone

from dataclasses import dataclass, field


@dataclass
class ComplianceProfile:
    """Defines compliance requirements for a target jurisdiction."""

    name: str
    full_name: str
    required_pii_fields: list[str] = field(default_factory=list)
    optional_pii_fields: list[str] = field(default_factory=list)
    sensitive_pii_fields: list[str] = field(default_factory=list)  # PIPL sensitive personal information
    retention_policy_days: int = 0  # 0 = no specific limit
    encryption_required: bool = True
    audit_log_required: bool = True
    consent_required: bool = False
    data_localization: bool = False
    cross_border_transfer_allowed: bool = True
    requires_security_assessment: bool = False  # PIPL outbound transfer
    dpo_required: bool = False                  # PDPA
    access_request_days: int = 0                # PDPA response time
    cross_border_conditions: list[str] = field(default_factory=list)  # Legal paths for cross-border
    breach_notification_hours: int = 72
    notes: str = ""


# ---------------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------------

_GDPR = ComplianceProfile(
    name="gdpr",
    full_name="General Data Protection Regulation (EU)",
    required_pii_fields=[
        "name", "full_name", "email", "phone", "address",
        "national_id", "ssn", "ip_address", "date_of_birth",
        "bank_account", "credit_card",
    ],
    optional_pii_fields=[
        "passport", "driver_license", "mac_address", "iban",
        "chinese_id", "mobile", "tel", "fax",
    ],
    retention_policy_days=365,
    encryption_required=True,
    audit_log_required=True,
    consent_required=True,
    cross_border_transfer_allowed=True,
    breach_notification_hours=72,
    notes=(
        "GDPR requires explicit consent for data processing, "
        "right to erasure, and 72-hour breach notification. "
        "Cross-border transfers require adequate safeguards (SCCs, BCRs, or adequacy decision)."
    ),
)

_PDPA = ComplianceProfile(
    name="pdpa",
    full_name="Personal Data Protection Act (Singapore)",
    required_pii_fields=[
        "name", "full_name", "email", "phone",
        "national_id", "address",
    ],
    optional_pii_fields=[
        "passport", "date_of_birth", "bank_account",
        "credit_card", "ip_address",
    ],
    retention_policy_days=0,
    encryption_required=True,
    audit_log_required=True,
    consent_required=True,
    cross_border_transfer_allowed=True,
    dpo_required=True,
    access_request_days=30,
    breach_notification_hours=72,
    notes=(
        "PDPA 要求组织指定数据保护官 (DPO)，并在 30 天内响应个人数据访问/更正请求。"
        "跨境传输需确保接收方提供与 PDPA 同等水平的保护。"
        "收集、使用和披露个人数据均需获得同意。"
    ),
)

_CCPA = ComplianceProfile(
    name="ccpa",
    full_name="California Consumer Privacy Act (USA)",
    required_pii_fields=[
        "name", "full_name", "email", "phone", "address",
        "ssn", "driver_license", "bank_account",
    ],
    optional_pii_fields=[
        "ip_address", "date_of_birth", "credit_card",
        "passport", "mac_address",
    ],
    retention_policy_days=0,
    encryption_required=True,
    audit_log_required=True,
    consent_required=False,
    cross_border_transfer_allowed=True,
    breach_notification_hours=0,
    notes=(
        "CCPA grants consumers the right to know, delete, and opt-out of sale. "
        "Businesses must provide a 'Do Not Sell My Personal Information' link."
    ),
)

_LGPD = ComplianceProfile(
    name="lgpd",
    full_name="Lei Geral de Proteção de Dados (Brazil)",
    required_pii_fields=[
        "name", "full_name", "email", "phone", "address",
        "national_id", "date_of_birth",
    ],
    optional_pii_fields=[
        "bank_account", "credit_card", "ip_address",
        "passport", "driver_license",
    ],
    retention_policy_days=0,
    encryption_required=True,
    audit_log_required=True,
    consent_required=True,
    cross_border_transfer_allowed=True,
    breach_notification_hours=0,
    notes=(
        "LGPD is Brazil's comprehensive data protection law, similar to GDPR. "
        "Requires legal basis for processing and ANPD reporting for breaches."
    ),
)

_PIPL = ComplianceProfile(
    name="pipl",
    full_name="Personal Information Protection Law (China)",
    required_pii_fields=[
        "name", "full_name", "email", "phone", "address",
        "national_id", "chinese_id", "date_of_birth", "bank_account",
    ],
    sensitive_pii_fields=[
        "chinese_id", "national_id", "credit_card", "bank_account",
        "passport", "biometric", "medical", "religious", "sexual_orientation",
    ],
    optional_pii_fields=[
        "passport", "ip_address", "credit_card", "mac_address", "driver_license",
    ],
    retention_policy_days=0,
    encryption_required=True,
    audit_log_required=True,
    consent_required=True,
    data_localization=True,
    cross_border_transfer_allowed=False,
    requires_security_assessment=True,
    cross_border_conditions=[
        "通过安全评估 (Security Assessment)",
        "通过专业机构认证 (Certification)",
        "签署标准合同 (Standard Contract / SCCs)",
    ],
    breach_notification_hours=0,
    notes=(
        "PIPL 是中国最严格的个人信息保护法。"
        "- 敏感个人信息需单独同意 + 更高保护措施"
        "- 重要数据 / 大规模个人信息出境必须进行安全评估"
        "- 默认禁止直接跨境传输，需满足三种合法路径之一"
        "- 建议生成安全评估申报材料辅助文档"
    ),
)

_PROFILES: dict[str, ComplianceProfile] = {
    p.name: p for p in [_GDPR, _PDPA, _CCPA, _LGPD, _PIPL]
}

# Aliases
_ALIASES = {
    "eu": "gdpr",
    "europe": "gdpr",
    "singapore": "pdpa",
    "sg": "pdpa",
    "california": "ccpa",
    "us-ca": "ccpa",
    "brazil": "lgpd",
    "br": "lgpd",
    "china": "pipl",
    "cn": "pipl",
}


def get_profile(name: str) -> ComplianceProfile:
    """Get a compliance profile by name (case-insensitive).

    Accepts full names, short codes, and aliases:
      - 'gdpr', 'eu', 'europe'
      - 'pdpa', 'singapore', 'sg'
      - 'ccpa', 'california', 'us-ca'
      - 'lgpd', 'brazil', 'br'
      - 'pipl', 'china', 'cn'
    """
    key = name.lower().strip()
    key = _ALIASES.get(key, key)
    if key not in _PROFILES:
        available = ", ".join(sorted(_PROFILES.keys()))
        raise ValueError(f"Unknown compliance profile '{name}'. Available: {available}")
    return _PROFILES[key]


def list_profiles() -> list[str]:
    """Return available profile names."""
    return sorted(_PROFILES.keys())


def validate_migration(pii_report: dict, profile: ComplianceProfile) -> list[str]:
    """Validate that a migration's PII report satisfies a compliance profile.

    Args:
        pii_report: A dict like {"fields_masked": [...], "values_masked": N}
                    OR a MigrationReport.pii_reports dict with filename keys.
        profile: The compliance profile to validate against.

    Returns:
        List of violation messages. Empty list = fully compliant.
    """
    violations = []

    # Normalize: extract all fields_masked across all files
    all_masked_fields: set[str] = set()
    if "fields_masked" in pii_report:
        all_masked_fields = set(pii_report["fields_masked"])
    else:
        # Assume it's a {filename: report_dict} structure
        for filename, report_info in pii_report.items():
            if isinstance(report_info, dict) and "fields_masked" in report_info:
                all_masked_fields.update(report_info["fields_masked"])

    # Check required fields
    for required_field in profile.required_pii_fields:
        if required_field not in all_masked_fields:
            violations.append(
                f"[{profile.name.upper()}] Required field '{required_field}' "
                f"was not found in masked fields. Ensure this field is present and masked."
            )

    # Encryption check
    if profile.encryption_required:
        # This is validated at the migration level, but we note it
        pass

    return violations


def generate_compliance_report(
    profile: ComplianceProfile, migration_results: dict
) -> dict:
    """Generate production-grade compliance report for Route A (PIPL/PDPA focus).

    Includes:
    - PIPL: Security assessment recommendation + cross-border conditions checklist
    - PDPA: DPO requirement flag + 30-day access request note
    """
    report = {
        "profile": profile.name,
        "full_name": profile.full_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "compliance_status": "pending_review",
        "violations": validate_migration(migration_results, profile),
        "recommendations": [],
        "sensitive_fields_handled": profile.sensitive_pii_fields,
        "encryption_enforced": profile.encryption_required,
        "audit_required": profile.audit_log_required,
    }

    if profile.name == "pipl":
        report["security_assessment_required"] = profile.requires_security_assessment
        report["data_localization"] = profile.data_localization
        report["cross_border_paths"] = profile.cross_border_conditions
        report["recommendations"].append(
            "PIPL: Prepare CAC security assessment filing if volume > 100k records or sensitive data."
        )
        report["recommendations"].append(
            "Generate declaration template for recipient country safeguards."
        )
    elif profile.name == "pdpa":
        report["dpo_required"] = profile.dpo_required
        report["access_request_sla_days"] = profile.access_request_days
        report["recommendations"].append(
            "PDPA: Appoint DPO and log consent records for all collections."
        )
        report["recommendations"].append(
            "Ensure 30-day response SLA for data access/correction requests."
        )

    report["notes"] = profile.notes
    return report


def generate_security_assessment_template(profile: ComplianceProfile) -> dict:
    """Generate a structured PIPL Security Assessment declaration template.

    For PIPL outbound transfers requiring CAC security assessment
    (data_volume > 100k records or sensitive personal information).

    Fields include: data_volume, recipient_country, purpose, safeguards, etc.
    """
    if profile.name != "pipl":
        raise ValueError(
            f"Security assessment template is only applicable to PIPL profile. "
            f"Got: {profile.name}"
        )

    template = {
        "template_version": "1.0",
        "jurisdiction": "PIPL (China)",
        "assessment_type": "Cross-Border Personal Information Transfer Security Assessment",
        "declaration_id": "[AUTO-GENERATED-UUID]",
        "submission_date": "[YYYY-MM-DD]",
        "data_controller": {
            "name": "[YOUR_COMPANY_NAME]",
            "registration_number": "[UNIFIED_SOCIAL_CREDIT_CODE]",
            "contact": "[DPO_EMAIL / LEGAL_CONTACT]",
            "address": "[REGISTERED_ADDRESS_IN_CHINA]",
        },
        "data_volume": {
            "estimated_records": "[e.g. 150000]",
            "volume_category": "[>100000 or sensitive data - triggers mandatory assessment]",
            "frequency": "[one-time / recurring / continuous]",
        },
        "recipient": {
            "country": "[e.g. Singapore, United States, Hong Kong]",
            "entity_name": "[RECIPIENT_COMPANY_NAME]",
            "entity_address": "[RECIPIENT_ADDRESS]",
            "relationship": "[subsidiary / vendor / partner]",
        },
        "purpose": {
            "primary_purpose": "[e.g. Cloud storage, analytics, customer support]",
            "legal_basis": "Explicit consent + necessity for contract performance",
            "data_subject_categories": ["employees", "customers", "users"],
        },
        "data_categories": {
            "required_pii": profile.required_pii_fields,
            "sensitive_pii": profile.sensitive_pii_fields,
            "optional_pii": profile.optional_pii_fields,
        },
        "safeguards": {
            "legal_path": profile.cross_border_conditions,
            "technical_measures": [
                "End-to-end encryption (AES-256 + TLS 1.3)",
                "Pseudonymization / tokenization where possible",
                "Strict access control (RBAC + MFA)",
                "Audit logging and monitoring",
                "Regular security assessments and penetration testing",
            ],
            "contractual_measures": [
                "Standard Contract for Cross-Border Transfer of Personal Information",
                "Data Processing Agreement with PIPL-equivalent clauses",
            ],
            "organizational_measures": [
                "Appointed Data Protection Officer",
                "Staff training on PIPL requirements",
                "Incident response plan (72h breach notification capability)",
            ],
        },
        "risk_assessment": {
            "risk_level": "[HIGH - due to sensitive data and volume]",
            "identified_risks": [
                "Unauthorized access during transfer",
                "Data leakage in recipient jurisdiction",
                "Non-compliance with data localization",
            ],
            "mitigation_strategies": [
                "Use of approved transfer mechanisms only",
                "Ongoing monitoring of recipient's compliance",
                "Right to audit clause in contract",
            ],
        },
        "data_localization": profile.data_localization,
        "requires_security_assessment": profile.requires_security_assessment,
        "retention_policy_days": profile.retention_policy_days,
        "consent_mechanism": "Separate consent obtained for sensitive PI and cross-border transfer",
        "notes": (
            "This template is for internal preparation of the security assessment "
            "declaration to the Cyberspace Administration of China (CAC). "
            "Actual filing requires official CAC portal submission and may need "
            "supplementary documentation."
        ),
    }
    return template
