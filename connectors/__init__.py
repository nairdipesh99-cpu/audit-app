"""IAM Audit Tool — Connector package."""
from .base        import BaseConnector, ConnectorResult
from .okta        import OktaConnector
from .entra       import EntraConnector
from .google_ws   import GoogleWorkspaceConnector
from .bamboohr    import BambooHRConnector
from .workday     import WorkdayConnector
from .github_conn import GitHubConnector
from .aws_iam     import AWSIAMConnector
from .salesforce  import SalesforceConnector

__all__ = [
    "BaseConnector", "ConnectorResult",
    "OktaConnector", "EntraConnector", "GoogleWorkspaceConnector",
    "BambooHRConnector", "WorkdayConnector", "GitHubConnector",
    "AWSIAMConnector", "SalesforceConnector",
]
