# Research Report: Canadian Data Sovereignty & Offshore Migration

**Date**: May 2026
**Prepared for**: PIIGuard Project
**Route A Update (v1.1.0)**: Added PIPL & PDPA deep dive sections (researcher sub-agent)

## Executive Summary

Canadian technology companies face increasing uncertainty regarding data sovereignty regulations. While Bill C-22 (Canada Disability Benefit Act) does not directly impact data flows, related legislative efforts (particularly around privacy reform) have created concern among AI and technology firms.

Singapore has emerged as one of the most attractive destinations for companies seeking regulatory stability, excellent infrastructure, and business-friendly policies.

## Key Findings

### 1. Canadian Regulatory Landscape
- PIPEDA remains the primary federal privacy law.
- Several provinces have or are developing their own privacy legislation.
- There is growing discussion around data localization requirements, especially for sensitive sectors.
- AI-specific regulations are still evolving.

### 2. Singapore as Destination Jurisdiction
**Advantages**:
- Personal Data Protection Act (PDPA) provides clear rules for cross-border transfers
- No general data localization requirement
- Strong government support for AI and technology sector
- World-class data center infrastructure
- Political stability and rule of law
- Tax incentives for tech companies

**Compliance Requirements**:
- Ensure appropriate safeguards when transferring personal data
- Maintain records of transfer mechanisms
- Consider sector-specific regulations (finance, healthcare)

### 3. Technical Challenges for Migration

**AI Model Weights**:
- Models can be extremely large (hundreds of GB to multiple TB)
- May contain embedded training data that requires special handling
- Require strong encryption during transfer
- Need careful key management

**Data Volume**:
- Large-scale migrations benefit from physical transfer appliances or high-bandwidth dedicated connections
- Latency between Canada and Singapore is approximately 200ms RTT

**Security**:
- Client-side encryption before leaving Canadian infrastructure is strongly recommended
- Implement robust audit logging

## Recommendations

1. **Start with Discovery**: Use tools like PIIGuard to understand data footprint
2. **Prioritize Encryption**: Apply strong encryption to all sensitive assets
3. **Choose Singapore as Primary Destination**: Best balance of compliance, infrastructure, and cost
4. **Maintain Detailed Records**: Regulatory scrutiny is likely to increase
5. **Test Migration Process**: Use dry-run capabilities extensively

## Route A: PIPL (China) Deep Dive (v1.1.0)

**PIPL Enacted**: November 2021 (effective 2021). Subsequent CAC implementation rules (2022), threshold updates and enforcement guidance (2023-2025).

### Key PIPL Requirements from compliance.py Profile
- `requires_security_assessment=True`
- `sensitive_pii_fields`: chinese_id, national_id, credit_card, bank_account, passport, biometric, medical, religious, sexual_orientation (require separate consent + enhanced measures)
- `data_localization=True`
- `cross_border_transfer_allowed=False` (default)
- `cross_border_conditions`: ["通过安全评估 (Security Assessment)", "通过专业机构认证 (Certification)", "签署标准合同 (Standard Contract / SCCs)"]

### Security Assessment Details & CAC Thresholds
- Mandatory for Critical Information Infrastructure (CII) operators or when transferring "important data".
- Thresholds (per CAC Security Assessment Measures): Outbound personal information of 100,000+ individuals cumulatively, or sensitive personal information of 10,000+ individuals (from Jan 1 of previous year).
- Filing: Submit self-assessment report to CAC covering data volume, recipient, purpose, safeguards, risks to subjects, and consent mechanisms.
- Approval required before transfer; retain documentation for audits.
- See example template: examples/PIPL_Security_Assessment_Checklist.md and pipl_security_assessment_template.json

## Route A: PDPA (Singapore) Deep Dive (v1.1.0)

**PDPA 2020 Amendments**: Strengthened consent, notification, and introduced mandatory DPO for organizations meeting criteria; 30-day response timelines codified.

### Key PDPA Requirements from compliance.py Profile
- `dpo_required=True`
- `access_request_days=30`
- `consent_required=True`
- Notes: "PDPA 要求组织指定数据保护官 (DPO)，并在 30 天内响应个人数据访问/更正请求。跨境传输需确保接收方提供与 PDPA 同等水平的保护。"

### DPO Checklist
- Mandatory appointment for organizations that are data intermediaries or handle significant volumes.
- DPO must oversee compliance, handle requests, manage cross-border safeguards.
- See full actionable checklist: examples/PDPA_DPO_Appointment_Checklist.md

### 30-Day Access Requests
- Must respond to access/correction requests within 30 days of receipt.
- Verification, location of data, intelligible response required.
- Extensions possible (+30 days) with notice.
- See: examples/PDPA_30Day_Access_Request_Checklist.md

### Cross-Border Contracts
- Require recipient to provide comparable protection level.
- Use contracts specifying purposes, security, retention, breach notification (72 hours).
- For PIPL overlap: align with one of three legal paths.
- See: examples/Cross_Border_Transfer_Contract_Checklist.md

## 5 Actionable Checklists (Added for Route A)

1. **PIPL Security Assessment Checklist** - examples/PIPL_Security_Assessment_Checklist.md
2. **PIPL Sensitive Personal Information Handling Checklist** - examples/PIPL_Sensitive_Data_Handling_Checklist.md
3. **PDPA DPO Appointment Checklist** - examples/PDPA_DPO_Appointment_Checklist.md
4. **PDPA 30-Day Data Access/Correction Request Checklist** - examples/PDPA_30Day_Access_Request_Checklist.md
5. **Cross-Border Data Transfer Contract Checklist** - examples/Cross_Border_Transfer_Contract_Checklist.md

All checklists are production-ready templates derived from compliance.py profile attributes (sensitive_pii_fields, requires_security_assessment, dpo_required, access_request_days, cross_border_conditions).

## Sources
- Singapore PDPC (Personal Data Protection Commission)
- Canadian federal privacy legislation
- Industry reports on cross-border data transfers
- Static compliance profiles in compliance.py (PIPL/PDPA sections)
- CAC PIPL Security Assessment Measures (2022-2025 guidance)

*This report is for planning purposes only. Route A enhancements focus exclusively on PIPL + PDPA for v1.1.0.*
