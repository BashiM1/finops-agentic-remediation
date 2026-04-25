# ADR 0001: Choice of LLM for FinOps Analysis

## Status
Accepted

## Date
2026-04-25

## Context
The FinOps Remediation Engine requires an LLM to analyse CloudTrail
event data and generate a 2-sentence financial impact warning before
presenting an approval request to a human operator.

The LLM runs inside an AWS Step Functions state machine via native
Bedrock integration. Requirements: low latency, low cost per invocation,
data sovereignty (data must not leave the AWS perimeter), and resistance
to prompt injection.

## Decision
We selected Anthropic Claude Haiku 4.5 via Amazon Bedrock.

Model ID: `anthropic.claude-haiku-4-5-20251001-v1:0`

At deployment time (2026-04-25), `anthropic.claude-3-haiku-20240307-v1:0`
was verified as LEGACY status in eu-west-2. The Haiku 4.5 successor was
selected as the current active equivalent.

Verification command:
```bash
aws bedrock list-foundation-models \
  --region eu-west-2 \
  --query "modelSummaries[?contains(modelId,'anthropic')].{id:modelId,status:modelLifecycle.status}" \
  --output table
```

## Rationale

1.  **Cost discipline:** Haiku is the lowest-cost Anthropic model. The  
    analysis task (2-sentence warning from structured CloudTrail data)  
    does not require Sonnet or Opus capability. Using a more capable  
    model would be overengineering.
    
2.  **Data sovereignty:** Bedrock keeps all inference within the AWS  
    perimeter. Data does not transit to Anthropic's infrastructure.
    
3.  **Prompt injection resistance:** The XML boundary defence  
    (`<untrusted_data>` tags in the system prompt) is natively supported  
    by Claude's instruction-following behaviour.
    
4.  **Native Step Functions integration:** Bedrock is a first-class  
    Step Functions integration, eliminating a Lambda invocation for the  
    AI analysis step.
    

## Rejected alternatives

- **OpenAI GPT-4o:** Data leaves the AWS perimeter. Rejected on  
    sovereignty grounds.
- **Claude Sonnet 4.5:** ~5x the cost of Haiku for the same 2-sentence  
    output. Rejected on cost discipline grounds.
- **Self-hosted model (Ollama/vLLM):** Operational overhead incompatible  
    with serverless architecture. Rejected.

## Consequences

- The model ID must be re-validated at each deployment. Add the  
    verification command to the deployment runbook.
- If Haiku 4.5 reaches LEGACY status, evaluate the current active  
    Haiku generation. The cost-first selection principle holds.  
