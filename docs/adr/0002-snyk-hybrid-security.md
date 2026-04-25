# ADR 0002: Hybrid Security Scanning (Snyk + Checkov)

## Status
Accepted

## Date
2026-04-25

## Context
The CI/CD pipeline requires automated security scanning covering:
- SAST (static application security testing) for Python Lambda code
- SCA (software composition analysis) for third-party dependencies
- SBOM generation for supply chain transparency
- IaC scanning for Pulumi infrastructure definitions

## Decision
Adopt a hybrid approach: Snyk for SAST/SCA/SBOM, Checkov for IaC.

## Rationale

Snyk Code provides accurate Python data-flow analysis with low false
positive rates. Snyk Open Source covers transitive dependency
vulnerabilities. Snyk SBOM generates CycloneDX 1.4 artefacts for
supply chain audit.

Snyk IaC does not natively parse dynamic Pulumi Python at the time of
this ADR. Pulumi generates CloudFormation/Terraform plan files that
Checkov can analyse, making Checkov the appropriate IaC engine for
this stack.

AWS Signer for Lambda code signing was evaluated but deferred. The
OIDC branch-narrowing (StringEquals on sub claim pinned to main branch)
provides the primary deployment gate for this PoC. AWS Signer adds
runtime artifact verification which would be required before production
deployment.

## Consequences

- Two security tools must be maintained and updated.
- The Checkov `bridgecrewio/checkov-action` version should be pinned
  to a specific SHA in production to prevent supply chain attacks on
  the pipeline itself.
- When Snyk IaC adds Pulumi Python support, consolidate to Snyk only
  and retire the Checkov dependency.
