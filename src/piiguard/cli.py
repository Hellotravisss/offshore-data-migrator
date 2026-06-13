"""
CLI entry point for PIIGuard.

Commands:
  migrate   Run migration pipeline (desensitize → encrypt → verify)
  encrypt   Encrypt a single file
  decrypt   Decrypt a single file
  init      Initialize project configuration
  verify    Verify file integrity against a manifest
  status    Show status of a previous migration
  profiles  List available compliance profiles
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .crypto import encrypt_file, decrypt_file
from .exceptions import (
    PIIGuardError,
)
from .migrate import run_migration

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(log_file: str | None = None, verbose: bool = False):
    """Configure logging with optional file output."""
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )

logger = logging.getLogger("PIIGuard")

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def init_command(args):
    """Initialize project configuration."""
    from .config import default_config, save_config

    config_dir = Path(args.directory or ".")
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "migration.yaml"

    if config_path.exists() and not args.force:
        logger.warning(f"Config already exists at {config_path}. Use --force to overwrite.")
        return

    config = default_config()
    if args.target:
        config.target = args.target
        config.compliance_profile = args.target
    if args.project:
        config.source = args.project

    save_config(config, config_path)
    logger.info(f"Project initialized → {config_path}")
    logger.info("Edit the config file to customize migration settings.")


def encrypt_command(args):
    """Encrypt a file."""
    password = _resolve_password(args)
    encrypt_file(Path(args.input), Path(args.output), password)
    logger.info(f"Encrypted: {args.input} → {args.output}")


def decrypt_command(args):
    """Decrypt a file."""
    password = _resolve_password(args)
    decrypt_file(Path(args.input), Path(args.output), password)
    logger.info(f"Decrypted: {args.input} → {args.output}")


def decrypt_all_command(args):
    """Decrypt an entire migration output tree back to plaintext."""
    from .migrate import decrypt_tree

    password = _resolve_password(args)
    report = decrypt_tree(Path(args.input), Path(args.output), password)
    logger.info(f"Decrypted {report['total_decrypted']} file(s) → {args.output}")
    if report["total_errors"]:
        logger.warning(f"{report['total_errors']} file(s) failed to decrypt:")
        for e in report["errors"]:
            logger.warning(f"  {e}")
        sys.exit(1)


def migrate_command(args):
    """Run migration pipeline."""
    from .config import load_config, merge_config_with_args

    # Load config file if specified
    config = None
    if args.config:
        config = load_config(Path(args.config))
        config = merge_config_with_args(config, args)
    else:
        config = None

    password = _resolve_password(args, config)

    source = Path(args.source)
    output = Path(args.output)

    # Resolve settings from config or args
    workers = args.workers
    batch_size = args.batch_size
    show_progress = not args.no_progress
    compliance = args.compliance_profile or ""
    audit_path = None
    compress = args.compress
    resume = args.resume
    generate_manifest = not args.no_manifest
    skip_patterns = args.skip_patterns or []
    log_file = args.log_file

    if config:
        workers = workers or config.workers
        batch_size = batch_size or config.batch_size
        compliance = compliance or config.compliance_profile
        compress = compress or config.compress_output
        generate_manifest = generate_manifest and config.generate_manifest
        if config.audit_log:
            audit_path = output / "audit.jsonl"
        if config.skip_patterns:
            skip_patterns.extend(config.skip_patterns)
        if config.log_file:
            log_file = log_file or config.log_file

    if args.audit:
        audit_path = Path(args.audit)

    # Re-setup logging if log_file specified
    if log_file:
        _setup_logging(log_file, args.verbose)

    # Initialize migration state for resume functionality
    state = None
    if resume:
        from .state import MigrationState
        state_db = output / ".migration_state.db"
        state = MigrationState(state_db)
        logger.info(f"Resume mode enabled. State database: {state_db}")

    report = run_migration(
        source_dir=source,
        output_dir=output,
        password=password,
        target=args.target,
        dry_run=args.dry_run,
        workers=workers,
        batch_size=batch_size,
        show_progress=show_progress,
        compliance_profile=compliance,
        generate_manifest=generate_manifest,
        audit_log_path=audit_path,
        compress=compress,
        skip_patterns=skip_patterns,
        resume=resume,
        state=state,
    )

    # Write report
    report_path = output / "migration_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report.to_dict(), indent=2))
    logger.info(f"Migration report → {report_path}")

    # Print summary
    _print_summary(report)

    # Handle --compliance-report flag (for pipl/pdpa)
    if getattr(args, "compliance_report", False):
        if compliance.lower() in ("pipl", "pdpa"):
            try:
                from .compliance import get_profile, generate_compliance_report
                profile = get_profile(compliance.lower())
                migration_results = report.to_dict()
                comp_report = generate_compliance_report(profile, migration_results)

                output.mkdir(parents=True, exist_ok=True)

                # Save JSON report
                json_path = output / f"compliance_report_{compliance.lower()}.json"
                json_path.write_text(json.dumps(comp_report, indent=2), encoding="utf-8")
                logger.info(f"Compliance report (JSON) → {json_path}")

                # Generate and save MD report
                md_content = _format_compliance_report_md(comp_report)
                md_path = output / f"compliance_report_{compliance.lower()}.md"
                md_path.write_text(md_content, encoding="utf-8")
                logger.info(f"Compliance report (MD) → {md_path}")
            except Exception as e:
                logger.error(f"Failed to generate compliance report: {e}")
        else:
            logger.warning("--compliance-report only supported for pipl or pdpa profiles")


def verify_command(args):
    """Verify file integrity against a manifest."""
    from .integrity import verify_manifest

    directory = Path(args.directory)
    manifest_path = Path(args.manifest)

    if not manifest_path.exists():
        logger.error(f"Manifest not found: {manifest_path}")
        sys.exit(1)

    mismatches = verify_manifest(directory, manifest_path)
    if not mismatches:
        logger.info("✓ All files verified. Integrity check passed.")
    else:
        logger.error(f"✗ {len(mismatches)} integrity issue(s) found:")
        for m in mismatches:
            logger.error(f"  {m}")
        sys.exit(1)


def status_command(args):
    """Show status of a previous migration."""
    report_path = Path(args.report or "output/migration_report.json")
    if not report_path.exists():
        logger.error(f"Report not found: {report_path}")
        sys.exit(1)

    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    print("\n" + "=" * 60)
    print("  MIGRATION STATUS REPORT")
    print("=" * 60)
    print(f"  Started:    {report.get('started_at', 'N/A')}")
    print(f"  Finished:   {report.get('finished_at', 'N/A')}")
    print(f"  Target:     {report.get('target', 'N/A')}")
    print(f"  Dry Run:    {report.get('dry_run', False)}")
    print(f"  Workers:    {report.get('workers', 1)}")
    print(f"  Files:      {len(report.get('files_processed', []))} processed")
    print(f"  Encrypted:  {len(report.get('files_encrypted', []))}")
    print(f"  Skipped:    {len(report.get('files_skipped', []))}")
    print(f"  PII Masked: {report.get('total_pii_masked', 0)} values")
    print(f"  Errors:     {len(report.get('errors', []))}")

    if report.get("compliance_profile"):
        print(f"\n  Compliance: {report['compliance_profile'].upper()}")
        violations = report.get("compliance_violations", [])
        if violations:
            print(f"  Violations: {len(violations)}")
            for v in violations[:5]:
                print(f"    ⚠ {v}")
        else:
            print("  Status:     ✓ Compliant")

    if report.get("manifest_hash"):
        print(f"\n  Manifest:   {report['manifest_hash'][:32]}...")

    print("=" * 60)

    if report.get("errors"):
        print("\n  ERRORS:")
        for e in report["errors"]:
            print(f"    ✗ {e}")
    print()


def profiles_command(args):
    """List available compliance profiles with Route A (PIPL/PDPA) details."""
    from .compliance import list_profiles, get_profile

    print("\n" + "=" * 60)
    print("  COMPLIANCE PROFILES (Route A: PIPL + PDPA Focus)")
    print("=" * 60)

    for name in list_profiles():
        profile = get_profile(name)
        print(f"\n  {name.upper()}")
        print(f"    {profile.full_name}")
        print(f"    Required fields: {', '.join(profile.required_pii_fields)}")
        if profile.sensitive_pii_fields:
            print(f"    Sensitive fields: {', '.join(profile.sensitive_pii_fields)}")
        if profile.retention_policy_days:
            print(f"    Retention: {profile.retention_policy_days} days")
        if profile.dpo_required:
            print("    DPO Required: Yes (PDPA)")
        if profile.requires_security_assessment:
            print("    Security Assessment: Required (PIPL)")
        if profile.access_request_days:
            print(f"    Access Request SLA: {profile.access_request_days} days")
        if profile.data_localization:
            print("    Data localization: Required")
        if profile.cross_border_conditions:
            print(f"    Cross-border paths: {len(profile.cross_border_conditions)} options")
        if not profile.cross_border_transfer_allowed:
            print("    Cross-border transfer: NOT allowed (default)")
        print(f"    Notes: {profile.notes[:100]}...")

    print("\n" + "=" * 60)
    print("  Use: piiguard migrate --compliance pipl --compliance-report")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def scan_command(args):
    """Scan directory for PII without performing migration."""
    source = Path(args.source)
    if not source.exists():
        logger.error(f"Source directory not found: {source}")
        sys.exit(1)
    
    logger.info(f"Scanning {source} for PII...")
    
    # Import needed functions
    from .migrate import _preview_file, _classify_file
    
    # Collect all files
    files = []
    for file_path in source.rglob("*"):
        if file_path.is_file():
            files.append(file_path)
    
    if not files:
        logger.warning("No files found in source directory")
        return
    
    logger.info(f"Found {len(files)} files to scan")
    
    # Scan each file
    total_pii_count = 0
    file_reports = []
    
    for file_path in files:
        try:
            file_type = _classify_file(file_path)
            if file_type is None:
                continue
            info = _preview_file(file_path, file_type)
            pii_count = info.get("values_masked", 0)
            
            file_reports.append({
                "path": str(file_path.relative_to(source)),
                "type": file_type,
                "pii_count": pii_count,
                "size": file_path.stat().st_size,
            })
            
            total_pii_count += pii_count
            
            if pii_count > 0:
                logger.info(f"  {file_path.name}: {pii_count} PII values ({file_type})")
        except Exception as e:
            logger.warning(f"  {file_path.name}: Failed to scan ({e})")
    
    # Print summary
    print(f"\n{'=' * 60}")
    print("  PII SCAN SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Files scanned:   {len(file_reports)}")
    print(f"  Total PII found: {total_pii_count}")
    
    if total_pii_count > 0:
        print("\n  Files with PII:")
        for report in sorted(file_reports, key=lambda x: x['pii_count'], reverse=True):
            if report['pii_count'] > 0:
                size_str = f"{report['size'] / 1024:.1f} KB"
                print(f"    {report['path']:40} {report['pii_count']:4} PII values  ({size_str})")
    
    print(f"{'=' * 60}\n")
    
    # Save report if requested
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        scan_report = {
            "source": str(source),
            "scan_time": datetime.now().isoformat(),
            "total_files": len(file_reports),
            "total_pii": total_pii_count,
            "files": file_reports,
        }
        
        output_path.write_text(json.dumps(scan_report, indent=2), encoding='utf-8')
        logger.info(f"Scan report saved to {output_path}")


def _resolve_password(args, config=None) -> str:
    """Resolve password from args, config, env var, key file, or interactive prompt.
    
    Priority order:
    1. CLI --password argument
    2. CLI --key-file argument
    3. Config file password
    4. Config file key_file
    5. ODM_PASSWORD environment variable
    6. Interactive prompt (getpass)
    """
    # CLI password takes highest priority
    if hasattr(args, 'password') and args.password:
        return args.password
    
    # CLI key file
    if hasattr(args, 'key_file') and args.key_file:
        key_path = Path(args.key_file)
        if not key_path.exists():
            logger.error(f"Key file not found: {key_path}")
            sys.exit(1)
        return key_path.read_text(encoding='utf-8').strip()
    
    # Config file password
    if config and config.password:
        return config.password
    
    # Config file key_file
    if config and config.key_file:
        key_path = Path(config.key_file)
        if not key_path.exists():
            logger.error(f"Key file not found: {key_path}")
            sys.exit(1)
        return key_path.read_text(encoding='utf-8').strip()
    
    # Environment variable
    env_pw = os.environ.get("ODM_PASSWORD")
    if env_pw:
        return env_pw
    
    # Interactive prompt
    return getpass.getpass("Encryption password: ")


def _print_summary(report):
    """Print a formatted summary of the migration report."""
    print("\n" + "=" * 60)
    print("  MIGRATION SUMMARY")
    print("=" * 60)
    print(f"  Files processed:  {len(report.files_processed)}")
    print(f"  Files encrypted:  {len(report.files_encrypted)}")
    print(f"  Files skipped:    {len(report.files_skipped)}")
    print(f"  PII values masked: {report.total_pii_masked}")
    print(f"  Bytes processed:  {report.total_bytes_processed:,}")
    print(f"  Errors:           {len(report.errors)}")

    if report.compliance_violations:
        print(f"\n  ⚠ COMPLIANCE VIOLATIONS ({len(report.compliance_violations)}):")
        for v in report.compliance_violations[:5]:
            print(f"    {v}")
        if len(report.compliance_violations) > 5:
            print(f"    ... and {len(report.compliance_violations) - 5} more")

    if report.errors:
        print("\n  ✗ ERRORS:")
        for e in report.errors:
            print(f"    {e}")

    print("=" * 60 + "\n")


def _format_compliance_report_md(report: dict) -> str:
    """Format compliance report into professional Markdown (Route A focus)."""
    lines = []
    profile = report.get("profile", "")
    full_name = report.get("full_name", profile.upper())
    
    # Header
    lines.append(f"# Compliance Report — {full_name}")
    lines.append(f"**Generated:** {report.get('timestamp', '')}")
    lines.append(f"**Status:** `{report.get('compliance_status', 'pending_review')}`")
    lines.append("")
    
    # Violations
    if report.get("violations"):
        lines.append("## ⚠️ Violations")
        for v in report["violations"]:
            lines.append(f"- {v}")
        lines.append("")
    
    # Recommendations
    if report.get("recommendations"):
        lines.append("## ✅ Recommendations")
        for r in report["recommendations"]:
            lines.append(f"- {r}")
        lines.append("")
    
    # Route A Special Sections
    if profile == "pipl":
        lines.append("## 🇨🇳 PIPL Specific Requirements")
        if report.get("security_assessment_required"):
            lines.append("- **Security Assessment Required**: Yes (CAC filing needed for >100k records or sensitive data)")
        if report.get("data_localization"):
            lines.append("- **Data Localization**: Required")
        if report.get("cross_border_paths"):
            lines.append("- **Legal Transfer Paths**:")
            for path in report["cross_border_paths"]:
                lines.append(f"  - {path}")
        lines.append("")
    
    elif profile == "pdpa":
        lines.append("## 🇸🇬 PDPA Specific Requirements")
        if report.get("dpo_required"):
            lines.append("- **Data Protection Officer (DPO)**: Mandatory appointment required")
        if report.get("access_request_sla_days"):
            lines.append(f"- **Access/Correction Request SLA**: {report['access_request_sla_days']} days")
        lines.append("")
    
    # Sensitive Fields
    if report.get("sensitive_fields_handled"):
        lines.append("## 🔒 Sensitive / Required PII Fields Handled")
        fields = report["sensitive_fields_handled"]
        if isinstance(fields, list) and fields:
            lines.append("| Field | Category |")
            lines.append("|-------|----------|")
            for f in fields:
                cat = "Sensitive" if f in ["chinese_id", "national_id", "credit_card", "bank_account", "passport"] else "Standard"
                lines.append(f"| `{f}` | {cat} |")
        lines.append("")
    
    # General Details
    lines.append("## 📋 General Details")
    skip_keys = {"profile", "full_name", "timestamp", "compliance_status", "violations", 
                 "recommendations", "notes", "sensitive_fields_handled", 
                 "security_assessment_required", "data_localization", "cross_border_paths",
                 "dpo_required", "access_request_sla_days"}
    
    for k, v in report.items():
        if k not in skip_keys and v not in (None, [], {}):
            lines.append(f"- **{k.replace('_', ' ').title()}**: {v}")
    
    # Notes
    if report.get("notes"):
        lines.append("")
        lines.append("## 📝 Regulatory Notes")
        lines.append(report["notes"])
    
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="PIIGuard — secure, compliant data migration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  piiguard migrate --source data/ --output out/ --password mypw
  piiguard migrate --source data/ --dry-run --compliance gdpr
  piiguard verify --directory out/encrypted --manifest out/manifest.json
  piiguard status --report out/migration_report.json
  piiguard profiles

Environment variables:
  ODM_PASSWORD    Encryption password (avoids interactive prompt)
        """,
    )
    parser.add_argument("--version", action="version", version=f"v{__version__}")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    parser.add_argument("--log-file", default=None, help="Write logs to file")

    sub = parser.add_subparsers(dest="command")

    # --- init ---
    p = sub.add_parser("init", help="Initialize project configuration")
    p.add_argument("--project", default=None, help="Project source directory")
    p.add_argument("--target", default=None, help="Target jurisdiction")
    p.add_argument("--directory", default=".", help="Where to create config")
    p.add_argument("--force", action="store_true", help="Overwrite existing config")
    p.set_defaults(func=init_command)

    # --- encrypt ---
    p = sub.add_parser("encrypt", help="Encrypt a single file")
    p.add_argument("input", help="Input file path")
    p.add_argument("output", help="Output encrypted file path")
    p.add_argument("--password", default=None)
    p.add_argument("--key-file", default=None, help="Read password from file")
    p.set_defaults(func=encrypt_command)

    # --- decrypt ---
    p = sub.add_parser("decrypt", help="Decrypt a single file")
    p.add_argument("input", help="Encrypted file path")
    p.add_argument("output", help="Output decrypted file path")
    p.add_argument("--password", default=None)
    p.add_argument("--key-file", default=None, help="Read password from file")
    p.set_defaults(func=decrypt_command)

    # --- decrypt-all ---
    p = sub.add_parser("decrypt-all", help="Decrypt a whole migration output tree")
    p.add_argument("--input", required=True, help="Encrypted directory (e.g. output/encrypted)")
    p.add_argument("--output", required=True, help="Directory for restored plaintext files")
    p.add_argument("--password", default=None)
    p.add_argument("--key-file", default=None, help="Read password from file")
    p.set_defaults(func=decrypt_all_command)

    # --- migrate ---
    p = sub.add_parser("migrate", help="Run migration pipeline")
    p.add_argument("--source", default="examples", help="Source directory")
    p.add_argument("--output", default="output", help="Output directory")
    p.add_argument("--target", default="singapore", help="Target jurisdiction")
    p.add_argument("--password", default=None, help="Encryption password")
    p.add_argument("--key-file", default=None, help="Read password from file")
    p.add_argument("--config", default=None, help="Path to YAML config file")
    p.add_argument("--dry-run", action="store_true", help="Preview without modifying")
    p.add_argument("--workers", type=int, default=1, help="Parallel workers (default: 1)")
    p.add_argument("--batch-size", type=int, default=0, help="Max files to process (0=all)")
    p.add_argument("--no-progress", action="store_true", help="Disable progress bar")
    p.add_argument("--compliance-profile", default="", help="Compliance profile (gdpr/pdpa/ccpa/lgpd/pipl)")
    p.add_argument("--compliance-report", action="store_true", help="Generate detailed compliance report (JSON + MD) for pipl/pdpa")
    p.add_argument("--compress", action="store_true", help="Compress encrypted output (gzip)")
    p.add_argument("--resume", action="store_true", help="Skip already processed files")
    p.add_argument("--no-manifest", action="store_true", help="Skip manifest generation")
    p.add_argument("--audit", default=None, help="Path for audit log (JSON Lines)")
    p.add_argument("--skip-patterns", nargs="*", default=None, help="Glob patterns to skip")
    p.set_defaults(func=migrate_command)

    # --- verify ---
    p = sub.add_parser("verify", help="Verify file integrity against manifest")
    p.add_argument("--directory", required=True, help="Directory to verify")
    p.add_argument("--manifest", required=True, help="Path to manifest JSON")
    p.set_defaults(func=verify_command)

    # --- status ---
    p = sub.add_parser("status", help="Show status of a previous migration")
    p.add_argument("--report", default=None, help="Path to migration_report.json")
    p.set_defaults(func=status_command)

    # --- profiles ---
    p = sub.add_parser("profiles", help="List compliance profiles")
    p.set_defaults(func=profiles_command)
    # --- assessment ---
    p = sub.add_parser("assessment", help="Generate PIPL Security Assessment template")
    p.add_argument("--profile", default="pipl", help="Compliance profile (only pipl supported)")
    p.add_argument("--output", default=None, help="Output file path (JSON)")
    p.set_defaults(func=assessment_command)


    # --- scan ---
    p = sub.add_parser("scan", help="Scan for PII without migration")
    p.add_argument("--source", default="examples", help="Source directory to scan")
    p.add_argument("--output", default=None, help="Save scan report to JSON file")
    p.set_defaults(func=scan_command)

    args = parser.parse_args()

    # Setup logging
    _setup_logging(args.log_file, args.verbose)

    if hasattr(args, "func"):
        try:
            args.func(args)
        except PIIGuardError as e:
            logger.error(f"{type(e).__name__}: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            logger.warning("Operation cancelled by user.")
            sys.exit(130)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

def assessment_command(args):
    """Generate PIPL Security Assessment declaration template (JSON + Markdown)."""
    from .compliance import get_profile, generate_security_assessment_template
    import json
    from pathlib import Path
    
    profile_name = getattr(args, "profile", "pipl").lower()
    
    if profile_name != "pipl":
        print("Error: Security Assessment template is only available for PIPL profile.")
        return
    
    profile = get_profile("pipl")
    template = generate_security_assessment_template(profile)
    
    output_path = getattr(args, "output", None)
    base_path = Path(output_path) if output_path else None
    
    if base_path:
        base_path.parent.mkdir(parents=True, exist_ok=True)
        
        # JSON version
        json_path = base_path.with_suffix(".json") if base_path.suffix == "" else base_path
        json_path.write_text(json.dumps(template, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"JSON template saved to {json_path}")
        
        # Markdown version
        md_path = json_path.with_suffix(".md")
        md_content = _format_assessment_template_md(template)
        md_path.write_text(md_content, encoding="utf-8")
        print(f"Markdown template saved to {md_path}")
    else:
        print(json.dumps(template, indent=2, ensure_ascii=False))


def _format_assessment_template_md(template: dict) -> str:
    """Format Security Assessment template into professional Markdown."""
    lines = []
    lines.append("# PIPL Cross-Border Security Assessment Declaration")
    lines.append(f"**Template Version:** {template.get('template_version', '1.0')}")
    lines.append(f"**Jurisdiction:** {template.get('jurisdiction', 'PIPL (China)')}")
    lines.append("")
    
    # Data Controller
    dc = template.get("data_controller", {})
    lines.append("## Data Controller Information")
    lines.append(f"- **Company Name:** {dc.get('name', '[YOUR_COMPANY_NAME]')}")
    lines.append(f"- **Registration Number:** {dc.get('registration_number', '[UNIFIED_SOCIAL_CREDIT_CODE]')}")
    lines.append(f"- **Contact:** {dc.get('contact', '[DPO_EMAIL]')}")
    lines.append("")
    
    # Data Volume
    dv = template.get("data_volume", {})
    lines.append("## Data Volume & Frequency")
    lines.append(f"- **Estimated Records:** {dv.get('estimated_records', '[e.g. 150000]')}")
    lines.append(f"- **Frequency:** {dv.get('frequency', '[one-time / recurring]')}")
    lines.append("")
    
    # Recipient
    rec = template.get("recipient", {})
    lines.append("## Recipient Information")
    lines.append(f"- **Country:** {rec.get('country', '[e.g. Singapore]')}")
    lines.append(f"- **Entity:** {rec.get('entity_name', '[RECIPIENT_COMPANY]')}")
    lines.append("")
    
    # Safeguards
    sg = template.get("safeguards", {})
    lines.append("## Safeguards")
    lines.append("### Technical Measures")
    for m in sg.get("technical_measures", []):
        lines.append(f"- {m}")
    lines.append("")
    lines.append("### Contractual Measures")
    for m in sg.get("contractual_measures", []):
        lines.append(f"- {m}")
    lines.append("")
    
    lines.append("---")
    lines.append("*This template is for internal preparation. Actual CAC filing may require supplementary documentation.*")
    
    return "\n".join(lines)
