from datetime import datetime, timezone
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.config import settings
from app.schemas.tailscale import (
    TailscaleDevice,
    TailscaleDevicesResponse,
)
from app.services.tailscale_client import (
    TailscaleAPIError,
    TailscaleAuthError,
    TailscaleClient,
    TailscaleConfigError,
    TailscaleConnectionError,
    TailscaleNotFoundError,
    TailscaleRateLimitError,
    get_tailscale_client,
)

# Dummy test fixtures - NO real credentials or sensitive secrets
MOCK_API_KEY = "tskey-api-mocktestkey1234567890abcdef"
MOCK_TAILNET = "example-fleet.org"
MOCK_BASE_URL = "https://api.tailscale.com"

SAMPLE_DEVICES_PAYLOAD = {
    "devices": [
        {
            "id": "10001",
            "nodeId": "n10001CNTRL",
            "name": "edge-router-01.example-fleet.org.beta.tailscale.net",
            "hostname": "edge-router-01",
            "user": "admin@example-fleet.org",
            "os": "linux",
            "osVersion": "Ubuntu 22.04 LTS",
            "clientVersion": "1.56.0",
            "addresses": ["100.64.0.1", "fd7a:115c:a1e0::1"],
            "tags": ["tag:server", "tag:edge"],
            "authorized": True,
            "isExternal": False,
            "machineKey": "mkey:mock-machine-key-1",
            "nodeKey": "nodekey:mock-node-key-1",
            "keyExpiryDisabled": True,
            "expires": "2027-01-01T00:00:00Z",
            "lastSeen": "2026-09-08T14:50:00Z",
            "created": "2026-01-01T00:00:00Z",
            "updateAvailable": False,
            "blocksIncomingConnections": False,
            "clientConnectivity": {
                "endpoints": ["198.51.100.10:41641", "10.0.0.1:41641"],
                "derp": "fra",
                "mappingVariesByDestIP": False,
                "latency": {
                    "fra": {"latencyMs": 14.2, "preferred": True},
                    "ord": {"latencyMs": 92.5, "preferred": False},
                },
                "clientVersion": {
                    "runningVersion": "1.56.0",
                    "latestVersion": "1.56.0",
                },
            },
            "postureIdentity": {
                "serialNumbers": ["SR-1234567"],
                "disabled": False,
            },
        },
        {
            "id": "10002",
            "nodeId": "n10002CNTRL",
            "name": "dev-macbook.example-fleet.org.beta.tailscale.net",
            "hostname": "dev-macbook",
            "user": "alice@example-fleet.org",
            "os": "macOS",
            "osVersion": "macOS 14.5 Sonoma",
            "clientVersion": "1.54.0",
            "addresses": ["100.64.0.2", "fd7a:115c:a1e0::2"],
            "tags": ["tag:workstation"],
            "authorized": True,
            "isExternal": False,
            "machineKey": "mkey:mock-machine-key-2",
            "nodeKey": "nodekey:mock-node-key-2",
            "keyExpiryDisabled": False,
            "expires": "2026-10-01T00:00:00Z",
            "lastSeen": "2026-09-08T15:00:00Z",
            "created": "2026-02-15T00:00:00Z",
            "updateAvailable": True,
            "blocksIncomingConnections": False,
            "clientConnectivity": {
                "endpoints": ["203.0.113.20:41641"],
                "derp": "ord",
                "latency": {
                    "ord": {"latencyMs": 22.8, "preferred": True},
                },
            },
        },
    ]
}


@pytest.mark.asyncio
async def test_client_initialization_from_settings():
    """Verifies that client picks up credentials from app.config.settings by default."""
    with patch.object(settings, "TAILSCALE_API_KEY", MOCK_API_KEY), \
         patch.object(settings, "TAILSCALE_TAILNET", MOCK_TAILNET), \
         patch.object(settings, "TAILSCALE_BASE_URL", "https://api.tailscale.com"):
        client = TailscaleClient()
        assert client.api_key == MOCK_API_KEY
        assert client.tailnet == MOCK_TAILNET
        assert client.base_url == "https://api.tailscale.com"
        assert client.is_configured is True
        await client.close()


@pytest.mark.asyncio
async def test_client_initialization_with_explicit_overrides():
    """Verifies constructor parameters override default settings."""
    custom_key = "tskey-api-customoverride"
    custom_tailnet = "custom.tailnet"
    custom_url = "https://custom.tailscale.internal"
    client = TailscaleClient(
        api_key=custom_key,
        tailnet=custom_tailnet,
        base_url=custom_url,
        timeout=15.0,
    )
    assert client.api_key == custom_key
    assert client.tailnet == custom_tailnet
    assert client.base_url == "https://custom.tailscale.internal"
    assert client.timeout == 15.0
    await client.close()


def test_client_repr_masks_api_key():
    """Ensures secret API keys are never leaked in string representations or logs."""
    client = TailscaleClient(api_key=MOCK_API_KEY, tailnet=MOCK_TAILNET)
    client_repr = repr(client)
    assert MOCK_API_KEY not in client_repr
    assert "tskey-ap..." in client_repr or "..." in client_repr
    assert MOCK_TAILNET in client_repr


@pytest.mark.asyncio
async def test_unconfigured_client_raises_config_error():
    """Ensures attempting to use an unconfigured client raises TailscaleConfigError."""
    with patch.object(settings, "TAILSCALE_API_KEY", None):
        client = TailscaleClient(api_key=None)
        assert client.is_configured is False
        with pytest.raises(TailscaleConfigError) as exc_info:
            await client.get_devices()
        assert "TAILSCALE_API_KEY" in str(exc_info.value)


@pytest.mark.asyncio
async def test_get_devices_success():
    """Verifies fetching devices list returns validated TailscaleDevicesResponse schema."""
    captured_requests = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(
            status_code=200,
            json=SAMPLE_DEVICES_PAYLOAD,
            headers={"Content-Type": "application/json"},
        )

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(
            api_key=MOCK_API_KEY,
            tailnet=MOCK_TAILNET,
            client=http_client,
        )

        response = await client.get_devices(tailnet=MOCK_TAILNET, fields="all")

        # Verify HTTP request details
        assert len(captured_requests) == 1
        req = captured_requests[0]
        assert req.method == "GET"
        assert f"/api/v2/tailnet/{MOCK_TAILNET}/devices" in str(req.url)
        assert "fields=all" in str(req.url)
        assert req.headers["Authorization"] == f"Bearer {MOCK_API_KEY}"
        assert "GridPulse" in req.headers["User-Agent"]

        # Verify parsed schema response
        assert isinstance(response, TailscaleDevicesResponse)
        assert len(response) == 2

        # Check first device
        dev1 = response.devices[0]
        assert dev1.id == "10001"
        assert dev1.node_id == "n10001CNTRL"
        assert dev1.hostname == "edge-router-01"
        assert dev1.os == "linux"
        assert dev1.os_version == "Ubuntu 22.04 LTS"
        assert dev1.client_version == "1.56.0"
        assert dev1.addresses == ["100.64.0.1", "fd7a:115c:a1e0::1"]
        assert dev1.tags == ["tag:server", "tag:edge"]
        assert dev1.derp_region == "fra"
        assert dev1.latency_ms == 14.2
        assert dev1.endpoints == ["198.51.100.10:41641", "10.0.0.1:41641"]
        assert dev1.key_expiry_disabled is True
        assert dev1.stable_id == "n10001CNTRL"

        # Check Node ORM dictionary mapping
        node_dict = dev1.to_node_dict(tailnet_override=MOCK_TAILNET)
        assert node_dict["id"] == "10001"
        assert node_dict["node_id"] == "n10001CNTRL"
        assert node_dict["hostname"] == "edge-router-01"
        assert node_dict["tailnet"] == MOCK_TAILNET
        assert node_dict["os"] == "linux"
        assert "client_connectivity" in node_dict["telemetry_metadata"]

        # Check NodeState dictionary mapping
        state_dict = dev1.to_node_state_dict()
        assert state_dict["node_id"] == "10001"
        assert state_dict["derp_region"] == "fra"
        assert state_dict["latency_ms"] == 14.2
        assert state_dict["key_expired"] is False

        # Check second device
        dev2 = response.devices[1]
        assert dev2.id == "10002"
        assert dev2.hostname == "dev-macbook"
        assert dev2.derp_region == "ord"
        assert dev2.latency_ms == 22.8
        assert dev2.update_available is True


@pytest.mark.asyncio
async def test_get_devices_default_tailnet():
    """Verifies that omission of tailnet argument falls back to client.tailnet."""
    captured_requests = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"devices": []})

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(
            api_key=MOCK_API_KEY,
            tailnet="default-org.tailscale",
            client=http_client,
        )
        await client.get_devices()
        assert len(captured_requests) == 1
        assert "/api/v2/tailnet/default-org.tailscale/devices" in str(captured_requests[0].url)


@pytest.mark.asyncio
async def test_get_devices_raw():
    """Verifies get_devices_raw returns unaltered dictionary."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=SAMPLE_DEVICES_PAYLOAD)

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(
            api_key=MOCK_API_KEY,
            tailnet=MOCK_TAILNET,
            client=http_client,
        )
        raw_data = await client.get_devices_raw()
        assert isinstance(raw_data, dict)
        assert "devices" in raw_data
        assert len(raw_data["devices"]) == 2


@pytest.mark.asyncio
async def test_get_single_device_success():
    """Verifies fetching a single device by ID returns a validated TailscaleDevice model."""
    single_device = SAMPLE_DEVICES_PAYLOAD["devices"][0]

    def mock_handler(request: httpx.Request) -> httpx.Response:
        assert "/api/v2/device/10001" in str(request.url)
        return httpx.Response(200, json=single_device)

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(
            api_key=MOCK_API_KEY,
            tailnet=MOCK_TAILNET,
            client=http_client,
        )
        device = await client.get_device("10001")
        assert isinstance(device, TailscaleDevice)
        assert device.id == "10001"
        assert device.hostname == "edge-router-01"


@pytest.mark.asyncio
async def test_test_connection_success():
    """Verifies test_connection returns True when API responds with 200 OK."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"devices": []})

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(api_key=MOCK_API_KEY, client=http_client)
        assert await client.test_connection() is True


@pytest.mark.asyncio
async def test_test_connection_failure():
    """Verifies test_connection returns False when API responds with an error."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "invalid key"})

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(api_key=MOCK_API_KEY, client=http_client)
        assert await client.test_connection() is False


@pytest.mark.asyncio
async def test_error_handling_401_unauthorized():
    """Verifies 401 response raises TailscaleAuthError."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "invalid api key supplied"})

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(api_key=MOCK_API_KEY, client=http_client)
        with pytest.raises(TailscaleAuthError) as exc_info:
            await client.get_devices()
        assert exc_info.value.status_code == 401
        assert "invalid api key" in str(exc_info.value)


@pytest.mark.asyncio
async def test_error_handling_403_forbidden():
    """Verifies 403 response raises TailscaleAuthError."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "unauthorized tailnet scope"})

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(api_key=MOCK_API_KEY, client=http_client)
        with pytest.raises(TailscaleAuthError) as exc_info:
            await client.get_devices()
        assert exc_info.value.status_code == 403
        assert "unauthorized tailnet" in str(exc_info.value)


@pytest.mark.asyncio
async def test_error_handling_404_not_found():
    """Verifies 404 response raises TailscaleNotFoundError."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "device does not exist"})

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(api_key=MOCK_API_KEY, client=http_client)
        with pytest.raises(TailscaleNotFoundError) as exc_info:
            await client.get_device("invalid-id")
        assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_error_handling_429_rate_limit():
    """Verifies 429 response raises TailscaleRateLimitError."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"message": "too many requests"})

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(api_key=MOCK_API_KEY, client=http_client)
        with pytest.raises(TailscaleRateLimitError) as exc_info:
            await client.get_devices()
        assert exc_info.value.status_code == 429


@pytest.mark.asyncio
async def test_error_handling_500_api_error():
    """Verifies 500 response raises TailscaleAPIError."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"message": "internal upstream failure"})

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(api_key=MOCK_API_KEY, client=http_client)
        with pytest.raises(TailscaleAPIError) as exc_info:
            await client.get_devices()
        assert exc_info.value.status_code == 500


@pytest.mark.asyncio
async def test_error_handling_timeout():
    """Verifies httpx.TimeoutException maps to TailscaleConnectionError."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Request timed out")

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(api_key=MOCK_API_KEY, client=http_client)
        with pytest.raises(TailscaleConnectionError) as exc_info:
            await client.get_devices()
        assert "timed out" in str(exc_info.value)


@pytest.mark.asyncio
async def test_async_context_manager():
    """Verifies TailscaleClient works as an async context manager."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"devices": []})

    mock_transport = httpx.MockTransport(mock_handler)
    with patch.object(settings, "TAILSCALE_API_KEY", MOCK_API_KEY):
        async with TailscaleClient() as client:
            client._client = httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL)
            devices = await client.get_devices()
            assert len(devices) == 0


@pytest.mark.asyncio
async def test_fastapi_dependency_generator():
    """Verifies get_tailscale_client dependency yields a client instance and cleans up."""
    with patch.object(settings, "TAILSCALE_API_KEY", MOCK_API_KEY):
        gen = get_tailscale_client()
        client = await gen.__anext__()
        assert isinstance(client, TailscaleClient)
        assert client.api_key == MOCK_API_KEY
        try:
            await gen.__anext__()
        except StopAsyncIteration:
            pass


@pytest.mark.asyncio
async def test_error_handling_network_error():
    """Verifies httpx.NetworkError maps to TailscaleConnectionError."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused by peer")

    mock_transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=mock_transport, base_url=MOCK_BASE_URL) as http_client:
        client = TailscaleClient(api_key=MOCK_API_KEY, client=http_client)
        with pytest.raises(TailscaleConnectionError) as exc_info:
            await client.get_devices()
        assert "connection error" in str(exc_info.value)
