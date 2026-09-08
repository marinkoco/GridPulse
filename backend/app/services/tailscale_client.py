from __future__ import annotations

from collections.abc import AsyncIterator
import logging
from typing import Any, Dict, List, Optional
import httpx

from app.config import settings
from app.schemas.tailscale import (
    TailscaleDevice,
    TailscaleDevicesResponse,
)

logger = logging.getLogger(__name__)


class TailscaleError(Exception):
    """Base exception for all Tailscale API client errors."""

    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class TailscaleConfigError(TailscaleError):
    """Raised when Tailscale client configuration (e.g., API key) is missing or invalid."""
    pass


class TailscaleAuthError(TailscaleError):
    """Raised when Tailscale returns 401 Unauthorized or 403 Forbidden."""
    pass


class TailscaleNotFoundError(TailscaleError):
    """Raised when a requested Tailscale resource (device, tailnet) is not found (404)."""
    pass


class TailscaleRateLimitError(TailscaleError):
    """Raised when Tailscale API rate limit is reached (429)."""
    pass


class TailscaleConnectionError(TailscaleError):
    """Raised on network timeout or connection failure to Tailscale API."""
    pass


class TailscaleAPIError(TailscaleError):
    """Raised for unexpected 4xx/5xx HTTP errors from the Tailscale API."""
    pass


class TailscaleClient:
    """Async HTTPX client for interacting with the Tailscale API v2.

    Fetches device telemetry, posture identity, network endpoints, and device states.
    Credentials and settings default to pydantic-settings (app.config.settings).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        tailnet: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self._api_key = api_key or settings.TAILSCALE_API_KEY
        self.tailnet = tailnet or settings.TAILSCALE_TAILNET
        self.base_url = (base_url or settings.TAILSCALE_BASE_URL).rstrip("/")
        self.timeout = timeout if timeout is not None else settings.TAILSCALE_REQUEST_TIMEOUT

        self._custom_client = client is not None
        self._client: Optional[httpx.AsyncClient] = client

    @property
    def api_key(self) -> Optional[str]:
        """Returns the configured API key."""
        return self._api_key

    @property
    def is_configured(self) -> bool:
        """Checks if the client has an API key configured."""
        return bool(self._api_key)

    def _ensure_configured(self) -> None:
        """Validates that required API credentials are present."""
        if not self._api_key:
            raise TailscaleConfigError(
                "Tailscale API key is not configured. Set TAILSCALE_API_KEY in environment or pass api_key to TailscaleClient."
            )

    def _get_headers(self) -> Dict[str, str]:
        """Constructs secure request headers with Bearer token authentication."""
        self._ensure_configured()
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            "User-Agent": f"GridPulse/{settings.VERSION} (Fleet Telemetry)",
        }

    def _get_client(self) -> httpx.AsyncClient:
        """Returns or creates the underlying httpx.AsyncClient instance."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(self.timeout),
                headers=self._get_headers(),
            )
        return self._client

    async def __aenter__(self) -> "TailscaleClient":
        self._get_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def close(self) -> None:
        """Closes the underlying httpx client session if owned by this instance."""
        if not self._custom_client and self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def aclose(self) -> None:
        """Alias for close()."""
        await self.close()

    def _handle_response_error(self, response: httpx.Response) -> None:
        """Parses error details and raises appropriate domain-specific TailscaleError."""
        status = response.status_code
        error_msg = f"HTTP {status}"
        details: Dict[str, Any] = {}

        try:
            data = response.json()
            if isinstance(data, dict):
                details = data
                error_msg = data.get("message") or data.get("error") or error_msg
        except Exception:
            text = response.text[:200]
            if text:
                error_msg = f"{error_msg}: {text}"

        endpoint = str(response.request.url.path) if response.request else "unknown"

        if status in (401, 403):
            logger.warning("Tailscale auth failed (%d) for endpoint %s: %s", status, endpoint, error_msg)
            raise TailscaleAuthError(
                f"Tailscale authentication/authorization failed ({status}): {error_msg}",
                status_code=status,
                details=details,
            )
        elif status == 404:
            logger.warning("Tailscale resource not found (404) at %s: %s", endpoint, error_msg)
            raise TailscaleNotFoundError(
                f"Tailscale resource not found at {endpoint}: {error_msg}",
                status_code=status,
                details=details,
            )
        elif status == 429:
            logger.warning("Tailscale rate limit exceeded (429) at %s: %s", endpoint, error_msg)
            raise TailscaleRateLimitError(
                f"Tailscale rate limit exceeded (429): {error_msg}",
                status_code=status,
                details=details,
            )
        else:
            logger.error("Tailscale API error (%d) at %s: %s", status, endpoint, error_msg)
            raise TailscaleAPIError(
                f"Tailscale API request to {endpoint} failed ({status}): {error_msg}",
                status_code=status,
                details=details,
            )

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        content: Optional[bytes] = None,
        headers_override: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Internal helper executing authenticated HTTP requests with centralized error handling."""
        self._ensure_configured()
        client = self._get_client()

        # Update headers if custom client was injected
        headers = self._get_headers() if self._custom_client else {}
        if headers_override:
            headers.update(headers_override)

        try:
            response = await client.request(
                method=method,
                url=path,
                params=params,
                json=json,
                content=content,
                headers=headers or None,
            )
        except httpx.TimeoutException as exc:
            logger.error("Tailscale request timed out: %s %s", method, path)
            raise TailscaleConnectionError(f"Tailscale request timed out: {exc}") from exc
        except httpx.NetworkError as exc:
            logger.error("Tailscale network error: %s %s - %s", method, path, str(exc))
            raise TailscaleConnectionError(f"Tailscale network connection error: {exc}") from exc

        if not response.is_success:
            self._handle_response_error(response)

        try:
            return response.json()
        except Exception as exc:
            raise TailscaleAPIError(f"Failed to parse JSON response from Tailscale: {exc}") from exc

    async def get_acl(
        self,
        tailnet: Optional[str] = None,
        details: bool = True,
    ) -> Dict[str, Any]:
        """Fetches the tailnet ACL policy file from `/api/v2/tailnet/{tailnet}/acl`.

        Args:
            tailnet: Organization or tailnet name. Defaults to `self.tailnet` or "-".
            details: Whether to request detailed policy response.

        Returns:
            Dictionary containing ACL policy rules, groups, tags, and grants.
        """
        target_tailnet = tailnet or self.tailnet or "-"
        endpoint = f"/api/v2/tailnet/{target_tailnet}/acl"
        params = {"details": "true"} if details else None
        return await self._request("GET", endpoint, params=params)

    async def validate_acl(
        self,
        acl_data: Dict[str, Any] | str,
        tailnet: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validates an ACL policy without applying it via `/api/v2/tailnet/{tailnet}/acl/validate`.

        Args:
            acl_data: Dict or JSON string of the ACL policy to validate.
            tailnet: Organization or tailnet name. Defaults to `self.tailnet` or "-".

        Returns:
            Dictionary with validation results.
        """
        target_tailnet = tailnet or self.tailnet or "-"
        endpoint = f"/api/v2/tailnet/{target_tailnet}/acl/validate"
        if isinstance(acl_data, str):
            import json as json_lib
            try:
                acl_data = json_lib.loads(acl_data)
            except Exception:
                pass
        return await self._request("POST", endpoint, json=acl_data)

    async def get_devices_raw(
        self,
        tailnet: Optional[str] = None,
        fields: str = "all",
    ) -> Dict[str, Any]:
        """Fetches the raw devices JSON response from `/api/v2/tailnet/{tailnet}/devices`.

        Args:
            tailnet: Organization or tailnet name. Defaults to `self.tailnet` or "-".
            fields: Telemetry detail level (defaults to "all" to fetch posture, keys, and connectivity).

        Returns:
            Dictionary containing the raw payload e.g. `{"devices": [...]}`.
        """
        target_tailnet = tailnet or self.tailnet or "-"
        endpoint = f"/api/v2/tailnet/{target_tailnet}/devices"
        params = {"fields": fields} if fields else None
        return await self._request("GET", endpoint, params=params)

    async def get_devices(
        self,
        tailnet: Optional[str] = None,
        fields: str = "all",
    ) -> TailscaleDevicesResponse:
        """Fetches and validates devices list as structured Pydantic models.

        Args:
            tailnet: Organization or tailnet name. Defaults to `self.tailnet` or "-".
            fields: Telemetry detail level (defaults to "all").

        Returns:
            `TailscaleDevicesResponse` model containing list of `TailscaleDevice`.
        """
        data = await self.get_devices_raw(tailnet=tailnet, fields=fields)
        return TailscaleDevicesResponse.model_validate(data)

    async def get_device_raw(
        self,
        device_id: str,
        fields: str = "all",
    ) -> Dict[str, Any]:
        """Fetches raw device telemetry from `/api/v2/device/{device_id}`.

        Args:
            device_id: Tailscale device ID or node ID.
            fields: Telemetry detail level.

        Returns:
            Dictionary containing device details.
        """
        endpoint = f"/api/v2/device/{device_id}"
        params = {"fields": fields} if fields else None
        return await self._request("GET", endpoint, params=params)

    async def get_device(
        self,
        device_id: str,
        fields: str = "all",
    ) -> TailscaleDevice:
        """Fetches single device telemetry as structured Pydantic model.

        Args:
            device_id: Tailscale device ID or node ID.
            fields: Telemetry detail level.

        Returns:
            `TailscaleDevice` validated model.
        """
        data = await self.get_device_raw(device_id=device_id, fields=fields)
        return TailscaleDevice.model_validate(data)

    async def test_connection(self, tailnet: Optional[str] = None) -> bool:
        """Tests connectivity and authentication by querying the tailnet devices endpoint.

        Returns:
            True if authentication and connection succeeded, False otherwise.
        """
        try:
            await self.get_devices_raw(tailnet=tailnet)
            return True
        except (TailscaleError, Exception) as exc:
            logger.warning("Tailscale connection test failed: %s", exc)
            return False

    def __repr__(self) -> str:
        # Mask API key for security to prevent credentials leakage
        masked_key = (
            f"{self._api_key[:8]}...{self._api_key[-4:]}"
            if self._api_key and len(self._api_key) > 12
            else ("***" if self._api_key else "None")
        )
        return (
            f"<TailscaleClient(tailnet='{self.tailnet}', base_url='{self.base_url}', "
            f"api_key='{masked_key}')>"
        )


async def get_tailscale_client() -> AsyncIterator[TailscaleClient]:
    """FastAPI dependency yielding an async TailscaleClient instance with automatic cleanup."""
    async with TailscaleClient() as client:
        yield client
