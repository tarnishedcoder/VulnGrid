# Secure SDLC Checklist

## Requirements
- [ ] Security requirements captured alongside functional ones
- [ ] Threat model for new data flows (owner: architect)

## Design
- [ ] Threat modeling reviewed (STRIDE)
- [ ] AuthN/AuthZ design approved

## Implementation
- [ ] SAST (Checkmarx/Fortify/SonarQube) clean or triaged
- [ ] SCA (Snyk/Black Duck) – no Critical CVEs with EPSS ≥ 0.2
- [ ] Secrets scanning – no hardcoded credentials

## Verification
- [ ] DAST (ZAP/Burp) scan on staging
- [ ] Security gate workflow green (`security-gate.yml`)
- [ ] PR bot comments addressed

## Release & Operations
- [ ] EPSS refresh job healthy (nightly)
- [ ] Remediation tickets created with CVE/CVSS/EPSS context
- [ ] Logging & monitoring alerts wired (no silent failures)
