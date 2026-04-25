<div align="center">

# Agentic FinOps Remediation Engine

**Zero-Trust · SCC 7.2 Compliant · PoC Production Grade · Prompt-Injection Resistant**

![Status](https://img.shields.io/badge/Status-PoC_Production_Grade-8aadf4?style=for-the-badge)
![Compliance](https://img.shields.io/badge/Compliance-SCC_7.2-a6da95?style=for-the-badge)
![Snyk](https://img.shields.io/badge/Snyk-Hardened-700178?style=for-the-badge&logo=snyk&logoColor=white)
![Checkov](https://img.shields.io/badge/Checkov-IaC_Validated-24273a?style=for-the-badge)

*An active AWS cost-remediation ChatOps gateway. Detects cloud waste,
contextualises it via Anthropic Claude Haiku 4.5 on Amazon Bedrock,
and executes human-approved soft-kills via Slack — secured by
cryptographic physics and an immutable audit ledger.*

</div>

---

## Executive Value Proposition

This engine bridges the gap between passive cost reporting and dangerous
full autonomy via **Human-in-the-Loop AI remediation**.

- **Cost Discipline:** Actively stops AWS cost bleed (idle instances,
  untagged resources) by bringing the approval button directly to Slack.
- **Blast Radius Containment:** IAM hard-deny on production-tagged
  resources, HMAC signature verification, XML prompt-injection boundary,
  and EC2 state drift detection.
- **Supply Chain Security:** Hybrid Snyk (SAST/SCA/SBOM) and Checkov
  (IaC) pipeline gated by GitHub OIDC federation pinned to main branch.
- **Non-Repudiation:** S3 Object Lock + Athena gap query providing a
  cryptographically-anchored completeness assertion for SCC 7.2.

---

## Architecture

    EventBridge Anomaly -> Step Functions -> Bedrock (Claude Haiku 4.5)
                                          |
                                          v
                                Slack Approval Request
                                          |
                                          v
                            Human clicks Approve in Slack
                                          |
                                          v
                       Gateway Lambda (HMAC + State Drift Check)
                                          |
                                          v
                          Executor Lambda (ec2:StopInstances)
                                          |
                                          v
                         S3 Object Lock Audit Ledger (SCC 7.2)

---

## Compliance

See [/docs/compliance/SCC-7.2-Audit-Procedures.md](docs/compliance/SCC-7.2-Audit-Procedures.md)
for the Athena gap query runbook and the full cryptographic chain of
custody documentation.

Architecture Decision Records: [/docs/adr/](docs/adr/)

---

## Deployment

Requires: AWS CLI v2, Pulumi CLI v3+, Python 3.11, Node.js 20+

    # Configure AWS profile
    aws configure --profile finops-lab

    # Deploy dev stack
    pulumi stack select dev
    pulumi up

---

## Security

- OIDC federation: zero secrets in CI/CD pipeline
- Snyk SAST + SCA on every push to main
- CycloneDX SBOM generated per deployment
- IAM least privilege with explicit deny on production resources
- Timing-attack resistant HMAC verification
- EC2 state drift detection (SHA-256 hash comparison)

