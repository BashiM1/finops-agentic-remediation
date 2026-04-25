# ADR 0003: S3 Object Lock Mode — Lab vs Production Deviation

## Status
Accepted

## Date
2026-04-25

## Context
SCC 7.2 non-repudiation requires immutable audit records. S3 Object
Lock is the primary control for integrity (WORM guarantee).

Two Object Lock modes exist:
- COMPLIANCE: Immutable even for root account. Cannot be shortened.
  Objects cannot be deleted for the full retention period under any
  circumstances.
- GOVERNANCE: Immutable by default. Root account with
  s3:BypassGovernanceRetention can override. Retention can be shortened.

## Decision

**Lab deployment (account 582600397173):**
Object Lock is disabled entirely. The lab deployment is ephemeral and
exists to document deployment behaviour and generate PoC evidence
screenshots. Object Lock with COMPLIANCE mode would create
undeleteable objects for 2555 days in an account being used for testing,
preventing clean teardown.

**Demonstration deployment (tobedetermined):**
Object Lock enabled in GOVERNANCE mode with 30-day retention.
GOVERNANCE mode allows clean teardown via root account override while
still demonstrating the WORM control architecture. 30-day retention is
sufficient to demonstrate the control to an auditor without creating a
7-year liability.

**Production deployment:**
Object Lock in COMPLIANCE mode with 2555-day (7-year) retention,
matching FSI and UK government record-keeping requirements under SCC 7.2.

## Consequences

The lab deployment does not fully satisfy SCC 7.2 integrity requirements.
This is documented, intentional, and acceptable for a PoC that is not
processing real remediation actions against production infrastructure.

The demonstration deployment satisfies the SCC 7.2 architecture review
with a documented deviation (GOVERNANCE vs COMPLIANCE) that an auditor
can verify and accept.
