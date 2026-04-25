# SCC 7.2 Non-Repudiation Audit Procedures

## 1. Intent

To provide an irrefutable chain of evidence for every high-privileged
remediation action taken by the FinOps Engine, satisfying the
non-repudiation requirements of Security Control Catalogue 7.2.

Non-repudiation requires four verifiable properties:

| Property | Requirement | Control |
|---|---|---|
| Integrity | Record has not been tampered with | S3 Object Lock (GOVERNANCE/COMPLIANCE) |
| Authenticity | Record genuinely came from the system | HMAC-SHA256 + CloudTrail |
| Completeness | No records are missing from the chain | Athena Gap Query |
| Detectability | Tampering attempts are themselves detectable | CloudWatch metric filters |

## 2. The Cryptographic Chain of Custody

Every remediation action traces through the following chain:

    Slack Button Click
          |
          v
    HMAC-SHA256 Verification (Slack signing secret)
          |  Proves: request authenticity
          v
    DynamoDB Approvers Lookup (Slack User ID)
          |  Proves: human identity and authorisation
          v
    EC2 State Hash Comparison (SHA-256)
          |  Proves: no architectural drift since approval request
          v
    Step Functions SendTaskSuccess (Task Token)
          |  Proves: authorised execution chain
          v
    Lambda Execution (ec2:StopInstances)
          |  Proves: specific action taken
          v
    S3 PutObject (audit record, Object Lock protected)
          |  Proves: immutable record persisted
          v
    CloudTrail PutObject event
               Proves: AWS-signed record of the write

## 3. Completeness Assertion - Athena Gap Query

While S3 Object Lock (Compliance Mode) ensures Integrity
(protection against alteration), it cannot prove Completeness
(protection against omission - events that were processed but
never persisted).

The gap query cross-references Step Function execution success logs
against S3 Access Logs. Any execution ID that appears as SUCCEEDED
in Step Functions but has no corresponding PutObject event in the
S3 access log is a SCC 7.2 finding.

This provides a cryptographically-anchored completeness assertion:
for every Step Function execution marked SUCCEEDED, a corresponding
S3 PutObject event must appear. Any gap is surfaced as a finding
within the next scheduled Athena run, closing the silent-failure
loophole in SCC 7.2 non-repudiation.

### 3.1 Prerequisites

Before running the gap query, the following must exist:

1. Athena workgroup configured in eu-west-2
2. S3 access logs table created (see Section 3.2)
3. Step Functions execution log table created (see Section 3.3)
4. At least one successful execution to query against

### 3.2 Create the S3 Access Logs Athena Table

Run once in the Athena console (eu-west-2):

    CREATE EXTERNAL TABLE s3_access_logs (
      bucket_owner      STRING,
      bucket            STRING,
      request_datetime  STRING,
      remote_ip         STRING,
      requester         STRING,
      request_id        STRING,
      operation         STRING,
      s3_key            STRING,
      request_uri       STRING,
      http_status       INT,
      error_code        STRING,
      bytes_sent        BIGINT,
      object_size       BIGINT,
      total_time        INT,
      turn_around_time  INT,
      referrer          STRING,
      user_agent        STRING,
      version_id        STRING
    )
    ROW FORMAT REGEX
    SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
    WITH SERDEPROPERTIES (
      'input.regex' = '([^ ]*) ([^ ]*) \[(.*?)\] ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ("([^"]*)"|-) (-|[0-9]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ("([^"]*)"|-) ([^ ]*)'
    )
    LOCATION 's3://finops-access-logs-582600397173/s3-access-logs/'
    TBLPROPERTIES ('has_encrypted_data'='false');

### 3.3 Weekly Gap Query

Run this query weekly in the Athena console to detect silent failures:

    WITH executions AS (
      SELECT execution_id,
             start_date,
             status
      FROM step_functions_executions
      WHERE status = 'SUCCEEDED'
        AND start_date >= CURRENT_DATE - INTERVAL '7' DAY
    ),
    written AS (
      SELECT regexp_extract(s3_key, 'events/([^/]+)/', 1) AS execution_id
      FROM s3_access_logs
      WHERE operation = 'REST.PUT.OBJECT'
        AND s3_key LIKE 'events/%'
    )
    SELECT e.execution_id,
           e.start_date,
           'NO S3 OBJECT' AS gap_type
    FROM executions e
    LEFT JOIN written w ON e.execution_id = w.execution_id
    WHERE w.execution_id IS NULL;

Interpretation:
- Zero rows returned: completeness assertion holds for the period
- One or more rows returned: SCC 7.2 finding - investigate immediately

## 4. Anomaly Detection Queries

### 4.1 Unexpected requesters

    SELECT requester, COUNT(*) AS request_count
    FROM s3_access_logs
    WHERE bucket LIKE 'finops-audit-ledger-%'
      AND requester NOT LIKE 'arn:aws:sts::582600397173:%'
      AND requester != '-'
    GROUP BY requester
    ORDER BY request_count DESC;

### 4.2 High error rate by IP (probe detection)

    SELECT remote_ip,
           COUNT(*) AS total,
           SUM(CASE WHEN http_status >= 400 THEN 1 ELSE 0 END) AS errors,
           ROUND(
             SUM(CASE WHEN http_status >= 400 THEN 1 ELSE 0 END) * 100.0
             / COUNT(*), 1
           ) AS error_pct
    FROM s3_access_logs
    WHERE bucket LIKE 'finops-audit-ledger-%'
    GROUP BY remote_ip
    HAVING error_pct > 20 AND total > 10
    ORDER BY error_pct DESC;

## 5. Audit Checklist

Before presenting this system to an auditor:

    [ ] S3 Object Lock mode documented in ADR-0003
    [ ] CloudTrail data events enabled on audit bucket
    [ ] Athena table created over S3 access logs
    [ ] Gap query run and returned zero rows
    [ ] DynamoDB approvers table contains only verified identities
    [ ] OIDC sub claim pinned to specific repo and branch
    [ ] .snyk ignore policy has no entries without justification and expiry
    [ ] Bedrock model ID verified as ACTIVE at deployment time
