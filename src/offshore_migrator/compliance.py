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

from dataclasses import dataclass, field


@dataclass
class ComplianceProfile:
    """Defines compliance requirements for a target jurisdiction."""

    name: str
    full_name: str
    required_pii_fields: list[str] = field(default_factory=list)
    optional_pii_fields: list[str] = field(default_factory=list)
    retention_policy_days: int = 0  # 0 = no specific limit
    encryption_required: bool = True
    audit_log_required: bool = True
    consent_required: bool = False
    data_localization: bool = False
    cross_border_transfer_allowed: bool = True
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
    breach_notification_hours=72,
    notes=(
        "PDPA requires consent for collection, use, and disclosure. "
        "Organisations must designate a DPO and respond to access/correction requests within 30 days."
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
        "national_id", "chinese_id", "date_of_birth",
        "bank_account",
    ],
    optional_pii_fields=[
        "passport", "ip_address", "credit_card",
        "mac_address", "driver_license",
    ],
    retention_policy_days=0,
    encryption_required=True,
    audit_log_required=True,
    consent_required=True,
    data_localization=True,
    cross_border_transfer_allowed=False,
    breach_notification_hours=0,
    notes=(
        "PIPL requires data localization for critical and large-volume personal data. "
        "Cross-border transfers require security assessment, certification, or SCCs. "
        "Separate consent needed for sensitive personal information."
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
