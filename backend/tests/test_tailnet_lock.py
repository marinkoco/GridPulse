from __future__ import annotations

import pytest

from app.models.enums import TailnetLockStatus
from app.schemas.tailscale import TailscaleDevice
from app.services.tailnet_lock import (
    audit_node_tailnet_lock,
    determine_tailnet_lock_status,
    is_node_lock_exempt,
    is_node_locked_out,
    is_node_quarantined,
    is_node_unsigned,
    is_signing_node,
    parse_tailnet_lock_error,
    parse_tailnet_lock_key,
)


def make_device(
    device_id: str = "dev-1",
    name: str = "node1.example.com",
    attributes: dict | None = None,
    tags: list[str] | None = None,
    tailnet_lock_key: str | None = None,
    tailnet_lock_error: str | None = None,
) -> TailscaleDevice:
    attrs = dict(attributes or {})
    if tailnet_lock_key:
        attrs["tailnet_lock_key"] = tailnet_lock_key
    if tailnet_lock_error:
        attrs["tailnet_lock_error"] = tailnet_lock_error

    return TailscaleDevice.model_validate(
        {
            "id": device_id,
            "nodeId": f"nodeId-{device_id}",
            "name": name,
            "hostname": name.split(".")[0],
            "os": "linux",
            "attributes": attrs,
            "tags": tags or [],
            "tailnet_lock_key": tailnet_lock_key,
            "tailnet_lock_error": tailnet_lock_error,
        }
    )


def test_parse_tailnet_lock_key():
    dev = make_device(tailnet_lock_key="nlpub:1234567890abcdef")
    assert parse_tailnet_lock_key(dev) == "nlpub:1234567890abcdef"

    dev_no_key = make_device()
    assert parse_tailnet_lock_key(dev_no_key) is None


def test_parse_tailnet_lock_error():
    dev = make_device(tailnet_lock_error="node is not signed by tailnet lock")
    assert parse_tailnet_lock_error(dev) == "node is not signed by tailnet lock"


def test_is_node_locked_out():
    dev_locked = make_device(tailnet_lock_error="node locked out")
    assert is_node_locked_out(dev_locked) is True

    dev_ok = make_device(tailnet_lock_key="nlpub:abc")
    assert is_node_locked_out(dev_ok) is False


def test_is_node_quarantined():
    dev_quarantine = make_device(tags=["tag:quarantine"])
    assert is_node_quarantined(dev_quarantine) is True

    dev_clean = make_device()
    assert is_node_quarantined(dev_clean) is False


def test_is_signing_node():
    dev_signing = make_device(tags=["tag:tailnet-lock-signer"])
    assert is_signing_node(dev_signing) is True

    dev_regular = make_device()
    assert is_signing_node(dev_regular) is False


def test_is_node_lock_exempt():
    dev_exempt = make_device(tags=["tag:lock-exempt"])
    assert is_node_lock_exempt(dev_exempt) is True


def test_determine_tailnet_lock_status():
    dev_quarantine = make_device(tags=["tag:quarantine"])
    assert determine_tailnet_lock_status(dev_quarantine) == TailnetLockStatus.QUARANTINED

    dev_unsigned = make_device(tags=["tag:unsigned"])
    assert determine_tailnet_lock_status(dev_unsigned) == TailnetLockStatus.UNSIGNED

    dev_signed = make_device(tailnet_lock_key="nlpub:trusted-key-1")
    assert determine_tailnet_lock_status(dev_signed) == TailnetLockStatus.SIGNED


def test_audit_node_tailnet_lock():
    dev_locked = make_device(tailnet_lock_error="node locked out")
    audit = audit_node_tailnet_lock(dev_locked)
    assert audit["lock_status"] == TailnetLockStatus.QUARANTINED.value
    assert audit["is_locked_out"] is True
    assert len(audit["alerts"]) > 0


from unittest.mock import AsyncMock, patch
from httpx import ASGITransport, AsyncClient
from app.main import app


@pytest.mark.asyncio
async def test_api_v1_fleet_tailnet_lock_overview():
    with patch("app.api.v1.router.get_fleet_tailnet_lock_overview", new_callable=AsyncMock) as mock_ov:
        mock_ov.return_value = {
            "total_nodes": 10,
            "locked_out_count": 1,
            "quarantined_count": 1,
            "unsigned_count": 0,
            "signing_node_count": 2,
            "signed_count": 7,
            "exempt_count": 0,
            "status": "warning",
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/fleet/tailnet-lock/overview")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_nodes"] == 10
            assert data["locked_out_count"] == 1


@pytest.mark.asyncio
async def test_api_v1_node_tailnet_lock_audit_404():
    with patch("app.api.v1.router.get_node_tailnet_lock_audit", new_callable=AsyncMock) as mock_audit:
        mock_audit.return_value = {"error": "node_not_found"}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/fleet/nodes/missing-id/tailnet-lock")
            assert resp.status_code == 404
