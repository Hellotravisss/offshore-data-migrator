"""Route A (PIPL + PDPA) specific tests."""

from piiguard.compliance import (
    get_profile, 
    generate_compliance_report,
    generate_security_assessment_template
)


class TestPIPLProfile:
    def test_pipl_profile_loaded(self):
        profile = get_profile("pipl")
        assert profile.name == "pipl"
        assert profile.requires_security_assessment is True
        assert profile.data_localization is True
        assert "chinese_id" in profile.sensitive_pii_fields

    def test_pipl_security_assessment_template(self):
        profile = get_profile("pipl")
        template = generate_security_assessment_template(profile)
        assert template["jurisdiction"] == "PIPL (China)"
        assert "data_controller" in template
        assert "safeguards" in template
        assert template["requires_security_assessment"] is True


class TestPDPAProfile:
    def test_pdpa_profile_loaded(self):
        profile = get_profile("pdpa")
        assert profile.name == "pdpa"
        assert profile.dpo_required is True
        assert profile.access_request_days == 30

    def test_pdpa_compliance_report(self):
        profile = get_profile("pdpa")
        mock_results = {"fields_masked": ["name", "email", "phone", "national_id"]}
        report = generate_compliance_report(profile, mock_results)
        assert report["profile"] == "pdpa"
        assert report["dpo_required"] is True
        assert any("DPO" in r for r in report["recommendations"])


class TestComplianceReportGeneration:
    def test_generate_report_for_pipl(self):
        profile = get_profile("pipl")
        mock_results = {"fields_masked": ["chinese_id", "name"]}
        report = generate_compliance_report(profile, mock_results)
        assert report["security_assessment_required"] is True
        assert "cross_border_paths" in report

    def test_generate_report_for_pdpa(self):
        profile = get_profile("pdpa")
        mock_results = {"fields_masked": ["name", "email"]}
        report = generate_compliance_report(profile, mock_results)
        assert report["access_request_sla_days"] == 30


class TestCustomPII:
    def test_register_custom_pattern(self):
        from piiguard.pii import register_custom_pii_pattern, CUSTOM_PII_PATTERNS
        # Clear previous test patterns
        CUSTOM_PII_PATTERNS.clear()
        
        register_custom_pii_pattern("custom_id", r"ID-\d{6}")
        assert len(CUSTOM_PII_PATTERNS) == 1
        assert CUSTOM_PII_PATTERNS[0][0] == "custom_id"


class TestIncrementalMigration:
    def test_state_db_creation(self):
        from piiguard.state import MigrationState
        from pathlib import Path
        import tempfile
        
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_state.db"
            state = MigrationState(db_path)
            assert db_path.exists()
            assert state.get_processed_count() == 0
