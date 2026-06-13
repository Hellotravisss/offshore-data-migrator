# PIPL Security Assessment Checklist (CAC Filing)

**For Route A v1.1.0 - PIIGuard**

Use this checklist when `requires_security_assessment=True` for PIPL profile.

## Pre-Assessment Preparation
- [ ] Identify if outbound transfer involves "important data" or large-scale PI (>100k individuals or >10k sensitive PI)
- [ ] Classify all sensitive_pii_fields: chinese_id, national_id, credit_card, bank_account, passport, biometric, medical, religious, sexual_orientation
- [ ] Document data volume, categories, purpose, recipient details (name, location, contact)
- [ ] Map cross_border_conditions: Security Assessment, Certification, or Standard Contract
- [ ] Confirm data_localization requirements met (China storage where applicable)

## CAC Security Assessment Filing
- [ ] Prepare self-assessment report on risks to PI subjects
- [ ] Include safeguards: encryption, access controls, audit logs
- [ ] Obtain consent for sensitive PI (separate consent required)
- [ ] File with CAC (Cyberspace Administration of China) via official portal
- [ ] Retain filing receipt and approval documents for audit

## Post-Assessment Actions
- [ ] Update compliance profile cross_border_transfer_allowed after approval
- [ ] Generate Security Assessment Declaration Template (see pipl_security_assessment_template.json)
- [ ] Log in migration audit trail with assessment ID
- [ ] Schedule annual re-assessment if volume thresholds change

**Threshold Reference (CAC Measures)**: Security assessment mandatory for CII operators, or PI processors handling important data, or cumulative outbound PI of 100,000+ individuals or sensitive PI of 10,000+ since Jan 1 of prior year.

*Static knowledge derived from compliance.py PIPL profile.*
