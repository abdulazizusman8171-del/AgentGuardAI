import json
import math
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class AgentGuardError(Exception):
    """Raised when AgentGuard API requests fail."""


class AgentGuardClient:
    """
    Python client for the AgentGuard AI Security Gateway.

    This SDK only inspects transactions.
    It never signs, broadcasts, approves, or executes transactions.
    """

    def __init__(
        self,
        base_url="https://agentguardai.onrender.com",
        timeout=15,
        api_key=None
    ):
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("A valid AgentGuard API URL is required.")

        base_url = base_url.strip()

        try:
            parsed_url = urlsplit(base_url)
            valid_url = (
                parsed_url.scheme in ("http", "https")
                and bool(parsed_url.netloc)
                and bool(parsed_url.hostname)
                and parsed_url.username is None
                and parsed_url.password is None
            )
        except ValueError:
            valid_url = False

        if not valid_url:
            raise ValueError(
                "API URL must be a valid HTTP or HTTPS URL "
                "without embedded credentials."
            )

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Timeout must be a finite positive number.")

        if api_key is not None and (
            not isinstance(api_key, str)
            or not api_key.startswith("ag_live_")
            or len(api_key) > 256
        ):
            raise ValueError("A valid AgentGuard API key is required.")

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.api_key = api_key

    def inspect(self, transaction):
        """
        Submit a proposed transaction for security inspection.

        Returns the gateway security report.
        No transaction is executed.
        """

        if not self.api_key:
            raise AgentGuardError(
                "An AgentGuard API key is required. "
                "Pass api_key when creating AgentGuardClient."
            )

        if not isinstance(transaction, dict):
            raise ValueError("Transaction must be a dictionary.")

        try:
            payload = json.dumps(
                transaction,
                allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise ValueError(
                "Transaction must contain valid JSON-compatible data."
            ) from error

        url = f"{self.base_url}/agent/inspect"

        request = Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-API-Key": self.api_key
            },
            method="POST"
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                response_body = response.read()

            result = json.loads(response_body.decode("utf-8"))

        except HTTPError as error:
            try:
                detail = error.read().decode("utf-8")
            except (OSError, UnicodeDecodeError, AttributeError):
                detail = "No readable error details."

            raise AgentGuardError(
                f"AgentGuard API returned HTTP {error.code}: {detail}"
            ) from error

        except URLError as error:
            raise AgentGuardError(
                f"Could not connect to AgentGuard API: {error.reason}"
            ) from error

        except (TimeoutError, OSError) as error:
            raise AgentGuardError(
                f"AgentGuard connection failed: {error}"
            ) from error

        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise AgentGuardError(
                "AgentGuard returned an invalid response."
            ) from error

        if not isinstance(result, dict):
            raise AgentGuardError(
                "AgentGuard returned an unexpected response."
            )

        return result

    @staticmethod
    def is_permitted(result):
        return (
            isinstance(result, dict)
            and result.get("gateway_status") == "PERMITTED"
        )

    @staticmethod
    def requires_approval(result):
        return (
            isinstance(result, dict)
            and result.get("gateway_status") == "APPROVAL_REQUIRED"
        )

    @staticmethod
    def is_rejected(result):
        return (
            isinstance(result, dict)
            and result.get("gateway_status") == "REJECTED"
        )