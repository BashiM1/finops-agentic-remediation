"""finops-followup-notifier Lambda.

Invoked by EventBridge Scheduler `review_after_days` after a PR merge
breached the cost-gate threshold. Receives the original event detail
as its `event` payload (the scheduler put it in the Target.Input),
formats a Block Kit follow-up, and POSTs to the Slack incoming
webhook stored in Secrets Manager.

In addition to the Slack post, the Lambda federates into GCP via
the aws-finops-bridge Workload Identity Pool to pull right-sizing
recommendations from the GCP Recommender API for any GCE resources
in the breach. AWS→GCP token exchange is the mirror of the
GCP→AWS path the cost-gate service uses for the Pricing API.
Recommender calls are best-effort; failures do not block the Slack
post.

Stays minimal on purpose — no buttons, no callback flow. Promoting
this to a remediation-approval card is P2.
"""
import json
import os
import urllib.request
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from google.auth import aws as google_aws
from google.auth.exceptions import GoogleAuthError, RefreshError
from google.auth.transport.requests import AuthorizedSession, Request

secretsmanager = boto3.client("secretsmanager", region_name="eu-west-2")
compute_optimizer = boto3.client("compute-optimizer", region_name="eu-west-2")
_AWS_ACCOUNT_ID = "582600397173"

SLACK_WEBHOOK_SECRET_ARN = os.environ["SLACK_WEBHOOK_SECRET_ARN"]
GCP_WIF_PROVIDER_RESOURCE_NAME = os.environ.get("GCP_WIF_PROVIDER_RESOURCE_NAME", "")
GCP_SA_EMAIL = os.environ.get("GCP_SA_EMAIL", "")
GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")

# GCP Recommender for VM right-sizing.
_GCE_RECOMMENDER_ID = "google.compute.instance.MachineTypeRecommender"

_webhook_cache: str | None = None
_gcp_credentials = None
_gcp_session: AuthorizedSession | None = None


def _ec2_arn(instance_id: str, region: str) -> str:
    return f"arn:aws:ec2:{region}:{_AWS_ACCOUNT_ID}:instance/{instance_id}"


def _enrich_aws_instance(instance_id: str, region: str) -> dict:
    """Pull a Compute Optimizer recommendation for one EC2 instance.

    Returns an enrichment dict whose `status` is one of:
      - `ok`           : finding present (may be OPTIMIZED or OVER/UNDER_PROVISIONED)
      - `no_data`      : Compute Optimizer has no findings yet (needs ~30h of metrics)
      - `not_opted_in` : the account hasn't enrolled in Compute Optimizer
      - `error`        : transient/unexpected failure
    Never raises.
    """
    arn = _ec2_arn(instance_id, region)
    try:
        resp = compute_optimizer.get_ec2_instance_recommendations(instanceArns=[arn])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("OptInRequiredException", "AccessDeniedException"):
            print(f"COMPUTE_OPTIMIZER_NOT_OPTED_IN: instance={instance_id} code={code}")
            return {"status": "not_opted_in", "instance_id": instance_id}
        print(f"COMPUTE_OPTIMIZER_ERROR: instance={instance_id} code={code}")
        return {"status": "error", "instance_id": instance_id, "code": code}

    errors = resp.get("errors") or []
    recs = resp.get("instanceRecommendations") or []
    if not recs:
        # An entry in `errors` here typically means the instance is not yet
        # known to Compute Optimizer (insufficient metric history). Empty
        # both lists = enrolled but haven't seen this instance yet.
        err_code = errors[0].get("code", "no_recommendation") if errors else "no_recommendation"
        print(f"COMPUTE_OPTIMIZER_NO_DATA: instance={instance_id} code={err_code}")
        return {"status": "no_data", "instance_id": instance_id, "code": err_code}

    rec = recs[0]
    finding = rec.get("finding", "UNKNOWN")
    current_type = rec.get("currentInstanceType", "")
    options = rec.get("recommendationOptions") or []
    top = options[0] if options else {}
    recommended_type = top.get("instanceType", "")
    savings = (top.get("estimatedMonthlySavings") or {}).get("value", 0.0)
    util = {
        m.get("name", "").upper(): m.get("value")
        for m in (rec.get("utilizationMetrics") or [])
        if m.get("statistic") == "MAXIMUM"
    }

    print(
        f"COMPUTE_OPTIMIZER_OK: instance={instance_id} finding={finding} "
        f"current={current_type} recommend={recommended_type} savings_usd={savings}"
    )
    return {
        "status": "ok",
        "instance_id": instance_id,
        "current_type": current_type,
        "recommended_type": recommended_type,
        "finding": finding,
        "estimated_monthly_savings_usd": savings,
        "utilisation": {  # only MAX statistic, the most actionable for right-sizing
            "cpu_pct": util.get("CPU"),
            "memory_pct": util.get("MEMORY"),
        },
    }


_GCP_PENDING_NOTE = "GCP Recommender enrichment pending — ships with GCP remediation engine"


def _build_enriched_resources(detail: dict) -> list[dict]:
    """Per-resource enrichment loop. Each entry = original resource + `enrichment`."""
    enriched: list[dict] = []
    for r in detail.get("resources") or []:
        out = dict(r)
        cloud = r.get("cloud")
        rtype = r.get("resource_type", "")
        if cloud == "aws" and rtype == "aws_instance":
            instance_id = r.get("instance_id")
            if not instance_id:
                out["enrichment"] = {
                    "status": "skipped",
                    "reason": "no instance_id in event detail",
                }
            else:
                out["enrichment"] = _enrich_aws_instance(instance_id, r.get("region", "eu-west-2"))
        elif cloud == "gcp":
            out["enrichment"] = {"status": "pending", "reason": _GCP_PENDING_NOTE}
        else:
            out["enrichment"] = {"status": "skipped", "reason": f"no enricher for {cloud}/{rtype}"}
        enriched.append(out)
    return enriched


def _get_webhook_url() -> str:
    """Cache the webhook for the lifetime of the warm container."""
    global _webhook_cache
    if _webhook_cache is None:
        resp = secretsmanager.get_secret_value(SecretId=SLACK_WEBHOOK_SECRET_ARN)
        _webhook_cache = resp["SecretString"]
    return _webhook_cache


def _days_since(iso_timestamp: str | None) -> int:
    if not iso_timestamp:
        return 0
    try:
        merged = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    except ValueError:
        return 0
    delta = datetime.now(timezone.utc) - merged
    return max(int(delta.total_seconds() // 86400), 0)


def _build_blocks(detail: dict) -> list[dict]:
    pr_number = detail.get("pr_number")
    repository = detail.get("repository", "")
    author = detail.get("author", "")
    total = float(detail.get("total_monthly_cost_usd", 0))
    threshold = float(detail.get("threshold_usd_monthly", 0))
    days = _days_since(detail.get("merged_at"))
    pr_url = f"https://github.com/{repository}/pull/{pr_number}"

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Cost Gate Follow-Up — PR #{pr_number} merged {days} day{'s' if days != 1 else ''} ago",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Repository*\n<https://github.com/{repository}|{repository}>"},
                {"type": "mrkdwn", "text": f"*Pull Request*\n<{pr_url}|#{pr_number}>"},
                {"type": "mrkdwn", "text": f"*Author*\n{author}"},
                {
                    "type": "mrkdwn",
                    "text": f"*Net Δ Monthly*\n${total:,.2f} (threshold ${threshold:,.2f})",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"Added *${total:,.2f}/mo* to infrastructure. Review recommended.",
            },
        },
        {"type": "divider"},
    ]

    resources = detail.get("resources") or []
    if resources:
        rows = [
            (
                r.get("address", ""),
                r.get("cloud", ""),
                r.get("change_action", ""),
                f"${float(r.get('monthly_cost_usd', 0)):,.2f}",
                r.get("confidence", ""),
            )
            for r in resources
        ]
        header = ("Resource", "Cloud", "Action", "Δ Monthly", "Confidence")
        widths = [max(len(h), max(len(row[i]) for row in rows)) for i, h in enumerate(header)]
        header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(header))
        body_lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)) for row in rows]
        text = "```\n" + "\n".join([header_line, *body_lines]) + "\n```"
        # Section text caps at 3000; truncate defensively.
        if len(text) > 2900:
            text = text[:2896] + "\n```"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})

    blocks.append(
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "Approval flow not wired yet (P2)."}],
        }
    )
    return blocks


def _gcp_federation_configured() -> bool:
    return bool(GCP_WIF_PROVIDER_RESOURCE_NAME and GCP_SA_EMAIL and GCP_PROJECT_ID)


def _get_gcp_session() -> AuthorizedSession | None:
    """Return an authorised requests session backed by AWS→GCP federation.

    The credentials object handles its own expiry/refresh — google-auth
    will mint a fresh GCP access token when the cached one is within
    its skew window of expiring. Returns None if federation is not
    configured (env vars missing) or token mint fails.
    """
    global _gcp_credentials, _gcp_session
    if not _gcp_federation_configured():
        return None
    if _gcp_session is not None:
        return _gcp_session

    config = {
        "type": "external_account",
        "audience": f"//iam.googleapis.com/{GCP_WIF_PROVIDER_RESOURCE_NAME}",
        "subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
        "service_account_impersonation_url": (
            f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
            f"{GCP_SA_EMAIL}:generateAccessToken"
        ),
        "token_url": "https://sts.googleapis.com/v1/token",
        "credential_source": {
            "environment_id": "aws1",
            # On Lambda, google-auth reads AWS_ACCESS_KEY_ID/SECRET/SESSION_TOKEN
            # and AWS_REGION from env vars; the IMDS URLs are never reached.
            "region_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone",
            "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials",
            "regional_cred_verification_url": (
                "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
            ),
        },
    }
    try:
        creds = google_aws.Credentials.from_info(
            config,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        creds.refresh(Request())
    except (GoogleAuthError, RefreshError) as exc:
        print(f"GCP_FEDERATION_ERROR: {type(exc).__name__}: {exc}")
        return None

    _gcp_credentials = creds
    _gcp_session = AuthorizedSession(creds)
    print(f"GCP_TOKEN_MINTED: sa={GCP_SA_EMAIL} expires={creds.expiry}")
    return _gcp_session


def _gce_zones_in_detail(detail: dict) -> set[str]:
    """Pull GCE zones out of the resources list — Recommender is zone-scoped."""
    zones: set[str] = set()
    for r in detail.get("resources") or []:
        if r.get("cloud") != "gcp":
            continue
        # Cost-gate emits region; for the demo path the real zone is
        # inferred. The detail body carries `region` (e.g. "us-central1");
        # the running demo instance is at us-central1-a. Without zone
        # data in the event, default to the canonical demo zone.
        region = r.get("region") or ""
        if region:
            zones.add(f"{region}-a")
    return zones


def _list_recommendations(session: AuthorizedSession, zone: str) -> list[dict] | None:
    """Call the Recommender REST API for a single zone. Best-effort."""
    url = (
        f"https://recommender.googleapis.com/v1/projects/{GCP_PROJECT_ID}"
        f"/locations/{zone}/recommenders/{_GCE_RECOMMENDER_ID}/recommendations"
    )
    try:
        resp = session.get(url, timeout=8)
    except Exception as exc:
        print(f"RECOMMENDER_REQUEST_ERROR: {type(exc).__name__}")
        return None
    if resp.status_code != 200:
        print(f"RECOMMENDER_HTTP_{resp.status_code}: {resp.text[:300]}")
        return None
    body = resp.json() or {}
    return body.get("recommendations") or []


def _query_recommender(detail: dict) -> dict:
    """Best-effort enrichment: never raises, never blocks Slack."""
    if not _gcp_federation_configured():
        return {"status": "skipped", "reason": "federation not configured"}
    session = _get_gcp_session()
    if session is None:
        return {"status": "error", "reason": "token mint failed"}

    zones = _gce_zones_in_detail(detail)
    if not zones:
        return {"status": "ok", "zones": [], "recommendations": []}

    all_recs: list[dict] = []
    for zone in zones:
        recs = _list_recommendations(session, zone)
        if recs is None:
            continue
        for rec in recs:
            all_recs.append({"zone": zone, "name": rec.get("name", ""), "description": rec.get("description", "")})

    print(f"RECOMMENDER_SUMMARY: zones={sorted(zones)} recommendations={len(all_recs)}")
    return {"status": "ok", "zones": sorted(zones), "recommendations": all_recs}


def _format_finding_line(r: dict) -> str:
    e = r.get("enrichment") or {}
    addr = r.get("address", "?")
    status = e.get("status")
    if status == "ok":
        finding = e.get("finding", "UNKNOWN")
        cur = e.get("current_type", "?")
        rec = e.get("recommended_type", "")
        savings = e.get("estimated_monthly_savings_usd", 0.0) or 0.0
        util = e.get("utilisation") or {}
        cpu = util.get("cpu_pct")
        mem = util.get("memory_pct")
        util_bits = []
        if cpu is not None:
            util_bits.append(f"CPU {cpu:.1f}% max")
        if mem is not None:
            util_bits.append(f"Mem {mem:.1f}% max")
        util_str = f" — {', '.join(util_bits)}" if util_bits else ""
        if finding == "OPTIMIZED" or not rec:
            return f"• `{addr}` ({cur}) — Compute Optimizer: OPTIMIZED, no change recommended{util_str}"
        return (
            f"• `{addr}` ({cur}) — Compute Optimizer: {finding} → "
            f"{rec}, save ${savings:,.2f}/mo{util_str}"
        )
    if status == "no_data":
        return f"• `{addr}` — Compute Optimizer: no data yet (needs ~30h of metrics)"
    if status == "not_opted_in":
        return f"• `{addr}` — Compute Optimizer: account not opted in"
    if status == "pending":
        return f"• `{addr}` — {e.get('reason', '')}"
    if status == "skipped":
        return f"• `{addr}` — enrichment skipped: {e.get('reason', '')}"
    return f"• `{addr}` — enrichment unavailable"


def _build_findings_section(enriched: list[dict]) -> dict | None:
    if not enriched:
        return None
    lines = [_format_finding_line(r) for r in enriched]
    text = "*Optimisation findings*\n" + "\n".join(lines)
    if len(text) > 2900:
        text = text[:2896] + "\n…"
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def _post(webhook_url: str, blocks: list[dict], fallback_text: str) -> bool:
    payload = json.dumps({"text": fallback_text, "blocks": blocks}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        # Log the type only — exception str may carry the URL.
        print(f"SLACK_POST_ERROR: {type(exc).__name__}")
        return False


def lambda_handler(event, _context):
    # Scheduler delivers the schedule's Input as the event itself.
    # event is the detail dict from the original CostGateThresholdExceeded.
    detail = event if isinstance(event, dict) else {}
    pr_number = detail.get("pr_number")
    repository = detail.get("repository", "")

    if pr_number is None or not repository:
        print(f"REJECT: missing pr_number/repository: {detail}")
        return {"status": "rejected"}

    try:
        webhook = _get_webhook_url()
    except ClientError as exc:
        print(f"SECRET_FETCH_ERROR: {type(exc).__name__}")
        raise

    # Per-resource enrichment. Compute Optimizer for AWS EC2; "pending"
    # placeholder for GCP. Never raises; never blocks the Slack post.
    enriched = _build_enriched_resources(detail)

    # Keep the GCP federation call exercised so the bridge stays warm
    # and we'd notice if it broke; the result no longer drives Slack
    # rendering — per-resource view replaces it.
    _query_recommender(detail)

    fallback = f"Cost Gate follow-up for {repository} PR#{pr_number}"
    blocks = _build_blocks(detail)
    findings_section = _build_findings_section(enriched)
    if findings_section is not None:
        blocks.insert(-1, findings_section)
    if not _post(webhook, blocks, fallback):
        # Raise so Scheduler records this as a failed invocation. The
        # schedule deletes itself afterwards either way (one-time +
        # ActionAfterCompletion=DELETE), but the Lambda metric reflects
        # the failure for alerting.
        raise RuntimeError("Slack webhook POST failed")

    print(f"NOTIFIED: pr={pr_number} repo={repository}")
    return {"status": "ok"}
