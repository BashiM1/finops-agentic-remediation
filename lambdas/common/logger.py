from aws_lambda_powertools import Logger

# Standardised structured logger for SCC 7.2 traceability.
# Import in Lambda handlers: from common.logger import logger
logger = Logger(service="finops-remediation")