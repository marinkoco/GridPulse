from __future__ import annotations

import hashlib
import hmac
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.main import app
from app.models.enums import AuditEventType, EventCategory
from app.models.node import Node
from app.schemas.webhook import WebhookResponse
from app.services.webhook import (
    WebhookError,
    WebhookPayloadError,
    WebhookVerificationError,
    classify_webhook_event,
    compute_tailscale_signature,
    generate_tailscale_signature,
    get_fleet_acl_events,
    get_fleet_acl_overview,
    get_webhook_listener_status,
    parse_webhook_events,
    process_tailscale_webhook,
    split_tailscale_signature_header,
    validate_tailscale_signature,
    verify_tailscale_signature,
)


TEST_WEBHOOK_SECRET = "test-secret-gridpulse-key-xyz"


# ---------------------------------------------------------------------------
# Unit Tests: Header Splitting (split_tailscale_signature_header)
# ---------------------------------------------------------------------------


def test_split_signature_header_standard():
    header = "t=1626380695,v1=93e986b208eb6757be456789abcdef"
    ts, sigs = split_tailscale_signature_header(header)
    assert ts == 1626380695
    assert sigs == ["93e986b208eb6757be456789abcdef"]


def test_split_signature_header_multiple_v1():
    header = "t=1700000000,v1=sig_alpha,v1=sig_beta,v1=sig_gamma"
    ts, sigs = split_tailscale_signature_header(header)
    assert ts == 1700000000
    assert sigs == ["sig_alpha", "sig_beta", "sig_gamma"]


def test_split_signature_header_whitespace_and_quotes():
    header = '  t = 1712345678  ,  v1 = "abc123def456" , extra=ignored  '
    ts, sigs = split_tailscale_signature_header(header)
    assert ts == 1712345678
    assert sigs == ["abc123def456"]


def test_split_signature_header_missing_t():
    header = "v1=93e986b208eb6757be456789abcdef"
    ts, sigs = split_tailscale_signature_header(header)
    assert ts is None
    assert sigs == ["93e986b208eb6757be456789abcdef"]


def test_split_signature_header_invalid_non_int_t():
    header = "t=not_a_number,v1=sig123"
    ts, sigs = split_tailscale_signature_header(header)
    assert ts is None
    assert sigs == ["sig123"]


def test_split_signature_header_negative_t():
    header = "t=-500,v1=sig123"
    ts, sigs = split_tailscale_signature_header(header)
    assert ts is None
    assert sigs == ["sig123"]


def test_split_signature_header_missing_v1():
    header = "t=1700000000,v2=something"
    ts, sigs = split_tailscale_signature_header(header)
    assert ts == 1700000000
    assert sigs == []


def test_split_signature_header_none_or_empty():
    assert split_tailscale_signature_header(None) == (None, [])
    assert split_tailscale_signature_header("") == (None, [])
    assert split_tailscale_signature_header("   ") == (None, [])
    assert split_tailscale_signature_header("malformed_without_equals") == (None, [])


# ---------------------------------------------------------------------------
# Unit Tests: HMAC Computation & Generation
# ---------------------------------------------------------------------------


def test_compute_tailscale_signature_deterministic():
    body = b'{"type": "policyUpdate"}'
    ts = 1626380695
    secret = "my-secret-key"

    expected = hmac.new(
        secret.encode("utf-8"),
        f"{ts}.".encode("utf-8") + body,
        hashlib.sha256,
    ).hexdigest()

    computed = compute_tailscale_signature(raw_body=body, secret=secret, timestamp=ts)
    assert computed == expected


def test_compute_tailscale_signature_str_and_bytes():
    body_str = '{"message": "hello"}'
    body_bytes = body_str.encode("utf-8")
    secret = "secret"
    ts = 1234567

    sig1 = compute_tailscale_signature(raw_body=body_str, secret=secret, timestamp=ts)
    sig2 = compute_tailscale_signature(raw_body=body_bytes, secret=secret, timestamp=ts)
    assert sig1 == sig2


def test_generate_tailscale_signature():
    body = b'{"type": "nodeCreated"}'
    secret = "test-secret"
    ts = 1710000000

    header = generate_tailscale_signature(raw_body=body, secret=secret, timestamp=ts)
    assert header.startswith(f"t={ts},v1=")

    # Verification of generated signature
    assert verify_tailscale_signature(
        raw_body=body,
        signature_header=header,
        secret=secret,
        tolerance_seconds=10,
        current_time=float(ts),
    ) is True


# ---------------------------------------------------------------------------
# Unit Tests: Signature Validation & Tolerance Checks
# ---------------------------------------------------------------------------


def test_validate_signature_success():
    body = b'{"type": "policyUpdate", "tailnet": "corp.net"}'
    now = 1700000500.0
    header = generate_tailscale_signature(raw_body=body, secret=TEST_WEBHOOK_SECRET, timestamp=1700000450)

    is_valid, reason = validate_tailscale_signature(
        raw_body=body,
        signature_header=header,
        secret=TEST_WEBHOOK_SECRET,
        tolerance_seconds=300,
        current_time=now,
    )
    assert is_valid is True
    assert reason is None


def test_validate_signature_with_multiple_v1_signatures():
    body = b'{"type": "policyUpdate"}'
    ts = 1700000000
    valid_sig = compute_tailscale_signature(raw_body=body, secret=TEST_WEBHOOK_SECRET, timestamp=ts)
    bogus_sig = "0000000000000000000000000000000000000000000000000000000000000000"

    header = f"t={ts},v1={bogus_sig},v1={valid_sig}"
    assert verify_tailscale_signature(
        raw_body=body,
        signature_header=header,
        secret=TEST_WEBHOOK_SECRET,
        tolerance_seconds=60,
        current_time=float(ts),
    ) is True


def test_validate_signature_with_secret_rollover():
    body = b'{"type": "policyUpdate"}'
    ts = 1700000000
    old_secret = "old-shared-secret-1"
    new_secret = "new-shared-secret-2"

    header = generate_tailscale_signature(raw_body=body, secret=new_secret, timestamp=ts)

    # Server configured with multiple comma-separated secrets
    is_valid, _ = validate_tailscale_signature(
        raw_body=body,
        signature_header=header,
        secret=f"{old_secret},{new_secret}",
        tolerance_seconds=60,
        current_time=float(ts),
    )
    assert is_valid is True

    # List of secrets
    is_valid_list, _ = validate_tailscale_signature(
        raw_body=body,
        signature_header=header,
        secret=[old_secret, new_secret],
        tolerance_seconds=60,
        current_time=float(ts),
    )
    assert is_valid_list is True


def test_validate_signature_rejects_expired_timestamp():
    body = b'{"type": "test"}'
    now = 1700001000.0
    # 301 seconds old, tolerance 300
    ts = int(now - 301)
    header = generate_tailscale_signature(raw_body=body, secret=TEST_WEBHOOK_SECRET, timestamp=ts)

    is_valid, reason = validate_tailscale_signature(
        raw_body=body,
        signature_header=header,
        secret=TEST_WEBHOOK_SECRET,
        tolerance_seconds=300,
        current_time=now,
    )
    assert is_valid is False
    assert "exceeds tolerance" in (reason or "").lower()


def test_validate_signature_rejects_future_timestamp_out_of_tolerance():
    body = b'{"type": "test"}'
    now = 1700000000.0
    ts = int(now + 305)  # 305 seconds in future
    header = generate_tailscale_signature(raw_body=body, secret=TEST_WEBHOOK_SECRET, timestamp=ts)

    is_valid, reason = validate_tailscale_signature(
        raw_body=body,
        signature_header=header,
        secret=TEST_WEBHOOK_SECRET,
        tolerance_seconds=300,
        current_time=now,
    )
    assert is_valid is False
    assert "exceeds tolerance" in (reason or "").lower()


def test_validate_signature_rejects_tampered_body():
    body = b'{"type": "policyUpdate", "action": "allow"}'
    tampered_body = b'{"type": "policyUpdate", "action": "deny"}'
    ts = 1700000000
    header = generate_tailscale_signature(raw_body=body, secret=TEST_WEBHOOK_SECRET, timestamp=ts)

    is_valid, reason = validate_tailscale_signature(
        raw_body=tampered_body,
        signature_header=header,
        secret=TEST_WEBHOOK_SECRET,
        tolerance_seconds=60,
        current_time=float(ts),
    )
    assert is_valid is False
    assert "mismatch" in (reason or "").lower()


def test_validate_signature_rejects_tampered_timestamp_in_header():
    body = b'{"type": "policyUpdate"}'
    ts = 1700000000
    header = generate_tailscale_signature(raw_body=body, secret=TEST_WEBHOOK_SECRET, timestamp=ts)
    # Alter the timestamp in the header without recomputing HMAC
    tampered_header = header.replace(f"t={ts}", f"t={ts + 1}")

    is_valid, reason = validate_tailscale_signature(
        raw_body=body,
        signature_header=tampered_header,
        secret=TEST_WEBHOOK_SECRET,
        tolerance_seconds=60,
        current_time=float(ts),
    )
    assert is_valid is False
    assert "mismatch" in (reason or "").lower()


def test_validate_signature_rejects_wrong_secret():
    body = b'{"type": "nodeCreated"}'
    ts = 1700000000
    header = generate_tailscale_signature(raw_body=body, secret="wrong-secret", timestamp=ts)

    is_valid, reason = validate_tailscale_signature(
        raw_body=body,
        signature_header=header,
        secret=TEST_WEBHOOK_SECRET,
        tolerance_seconds=60,
        current_time=float(ts),
    )
    assert is_valid is False
    assert "mismatch" in (reason or "").lower()


def test_validate_signature_missing_header():
    body = b'{"type": "nodeCreated"}'
    is_valid, reason = validate_tailscale_signature(
        raw_body=body,
        signature_header=None,
        secret=TEST_WEBHOOK_SECRET,
    )
    assert is_valid is False
    assert "missing" in (reason or "").lower()


def test_validate_signature_missing_secret():
    body = b'{"type": "nodeCreated"}'
    header = "t=1700000000,v1=abcdef"
    is_valid, reason = validate_tailscale_signature(
        raw_body=body,
        signature_header=header,
        secret="",
    )
    assert is_valid is False
    assert "not configured" in (reason or "").lower()


# ---------------------------------------------------------------------------
# Pipeline Integration: process_tailscale_webhook
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_tailscale_webhook_valid_signature_creates_audit_log():
    now_ts = int(time.time())
    payload_obj = [
        {
            "type": "policyUpdate",
            "tailnet": "corp.example.com",
            "timestamp": "2026-09-08T15:00:00Z",
            "message": "ACL updated by admin@example.com",
            "actor": {"displayName": "Security Admin", "loginName": "admin@example.com"},
            "data": {"url": "https://login.tailscale.com/admin/acls"},
        }
    ]
    raw_body = json.dumps(payload_obj).encode("utf-8")
    sig_header = generate_tailscale_signature(raw_body=raw_body, secret=TEST_WEBHOOK_SECRET, timestamp=now_ts)

    mock_session = AsyncMock()
    added_items = []
    mock_session.add = MagicMock(side_effect=lambda item: added_items.append(item))
    mock_session.commit = AsyncMock()

    response = await process_tailscale_webhook(
        raw_body=raw_body,
        signature_header=sig_header,
        session=mock_session,
        secret_override=TEST_WEBHOOK_SECRET,
        verify_signature=True,
    )

    assert isinstance(response, WebhookResponse)
    assert response.status == "ok"
    assert response.received_events == 1
    assert response.processed_events == 1
    assert response.events[0].event_type == AuditEventType.POLICY_UPDATE.value
    assert response.events[0].event_category == EventCategory.ACL.value
    assert response.events[0].actor == "Security Admin"
    assert len(added_items) == 1
    mock_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_process_tailscale_webhook_rejects_invalid_signature():
    raw_body = b'[{"type": "policyUpdate"}]'
    sig_header = f"t={int(time.time())},v1=invalidhexsignature"
    mock_session = AsyncMock()

    with pytest.raises(WebhookVerificationError) as exc_info:
        await process_tailscale_webhook(
            raw_body=raw_body,
            signature_header=sig_header,
            session=mock_session,
            secret_override=TEST_WEBHOOK_SECRET,
            verify_signature=True,
        )

    assert exc_info.value.status_code == 401
    assert "mismatch" in exc_info.value.message.lower()


@pytest.mark.asyncio
async def test_process_tailscale_webhook_rejects_expired_timestamp():
    raw_body = b'[{"type": "policyUpdate"}]'
    old_ts = int(time.time()) - 400  # Older than 300s tolerance
    sig_header = generate_tailscale_signature(raw_body=raw_body, secret=TEST_WEBHOOK_SECRET, timestamp=old_ts)
    mock_session = AsyncMock()

    with pytest.raises(WebhookVerificationError) as exc_info:
        await process_tailscale_webhook(
            raw_body=raw_body,
            signature_header=sig_header,
            session=mock_session,
            secret_override=TEST_WEBHOOK_SECRET,
            tolerance_seconds=300,
            verify_signature=True,
        )

    assert exc_info.value.status_code == 401
    assert "exceeds tolerance" in exc_info.value.message.lower()


@pytest.mark.asyncio
async def test_process_tailscale_webhook_bypass_verification():
    raw_body = json.dumps([{"type": "test", "message": "Test event"}]).encode("utf-8")
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()

    response = await process_tailscale_webhook(
        raw_body=raw_body,
        signature_header=None,
        session=mock_session,
        verify_signature=False,
    )

    assert response.status == "ok"
    assert response.processed_events == 1


@pytest.mark.asyncio
async def test_process_tailscale_webhook_node_deleted_updates_node_state():
    target_node_id = f"node-{uuid.uuid4().hex[:8]}"
    node = Node(
        id=str(uuid.uuid4()),
        node_id=target_node_id,
        name="web-01.corp.ts.net",
        hostname="web-01",
        is_online=True,
    )
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = node
    mock_session.execute.return_value = mock_result
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()

    payload = [
        {
            "type": "nodeDeleted",
            "message": "Node web-01 was removed",
            "data": {"node_id": target_node_id},
        }
    ]
    raw_body = json.dumps(payload).encode("utf-8")
    sig_header = generate_tailscale_signature(raw_body=raw_body, secret=TEST_WEBHOOK_SECRET)

    response = await process_tailscale_webhook(
        raw_body=raw_body,
        signature_header=sig_header,
        session=mock_session,
        secret_override=TEST_WEBHOOK_SECRET,
        verify_signature=True,
    )

    assert response.processed_events == 1
    assert node.is_online is False
    assert (node.telemetry_metadata or {}).get("deleted_via_webhook") is True


# ---------------------------------------------------------------------------
# HTTP Endpoint Tests: /api/v1/webhooks/tailscale & /webhooks/tailscale
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_webhook_endpoint_success():
    payload = [
        {
            "type": "policyUpdate",
            "tailnet": "test.tailnet",
            "message": "ACL updated via API",
            "actor": {"displayName": "DevOps Bot"},
        }
    ]
    raw_body = json.dumps(payload).encode("utf-8")
    now_ts = int(time.time())

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()

    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with patch("app.config.settings.TAILSCALE_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET), \
             patch("app.config.settings.TAILSCALE_WEBHOOK_VERIFY_SIGNATURE", True):
            sig_header = generate_tailscale_signature(raw_body=raw_body, secret=TEST_WEBHOOK_SECRET, timestamp=now_ts)

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/webhooks/tailscale",
                    content=raw_body,
                    headers={
                        "Content-Type": "application/json",
                        "Tailscale-Webhook-Signature": sig_header,
                    },
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["status"] == "ok"
                assert data["received_events"] == 1
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_api_webhook_endpoint_missing_signature_returns_401():
    raw_body = b'[{"type": "policyUpdate"}]'

    mock_db = AsyncMock()
    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with patch("app.config.settings.TAILSCALE_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET), \
             patch("app.config.settings.TAILSCALE_WEBHOOK_VERIFY_SIGNATURE", True):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/webhooks/tailscale",
                    content=raw_body,
                    headers={"Content-Type": "application/json"},
                )
                assert resp.status_code == 401
                assert "missing" in resp.json()["detail"].lower()
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_api_webhook_endpoint_invalid_signature_returns_401():
    raw_body = b'[{"type": "policyUpdate"}]'
    bad_header = f"t={int(time.time())},v1=0123456789abcdef"

    mock_db = AsyncMock()
    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with patch("app.config.settings.TAILSCALE_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET), \
             patch("app.config.settings.TAILSCALE_WEBHOOK_VERIFY_SIGNATURE", True):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/webhooks/tailscale",
                    content=raw_body,
                    headers={
                        "Content-Type": "application/json",
                        "Tailscale-Webhook-Signature": bad_header,
                    },
                )
                assert resp.status_code == 401
                assert "mismatch" in resp.json()["detail"].lower()
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_api_webhook_endpoint_expired_timestamp_returns_401():
    raw_body = b'[{"type": "policyUpdate"}]'
    expired_ts = int(time.time()) - 400
    expired_header = generate_tailscale_signature(raw_body=raw_body, secret=TEST_WEBHOOK_SECRET, timestamp=expired_ts)

    mock_db = AsyncMock()
    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with patch("app.config.settings.TAILSCALE_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET), \
             patch("app.config.settings.TAILSCALE_WEBHOOK_VERIFY_SIGNATURE", True):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/webhooks/tailscale",
                    content=raw_body,
                    headers={
                        "Content-Type": "application/json",
                        "Tailscale-Webhook-Signature": expired_header,
                    },
                )
                assert resp.status_code == 401
                assert "exceeds tolerance" in resp.json()["detail"].lower()
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_api_webhook_endpoint_root_alias():
    payload = [{"type": "test", "message": "Root webhook alias test"}]
    raw_body = json.dumps(payload).encode("utf-8")
    now_ts = int(time.time())

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()

    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with patch("app.config.settings.TAILSCALE_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET), \
             patch("app.config.settings.TAILSCALE_WEBHOOK_VERIFY_SIGNATURE", True):
            sig_header = generate_tailscale_signature(raw_body=raw_body, secret=TEST_WEBHOOK_SECRET, timestamp=now_ts)

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/webhooks/tailscale",
                    content=raw_body,
                    headers={
                        "Content-Type": "application/json",
                        "Tailscale-Webhook-Signature": sig_header,
                    },
                )
                assert resp.status_code == 200
                assert resp.json()["status"] == "ok"
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_api_webhook_status_endpoint():
    mock_db = AsyncMock()
    mock_res = MagicMock()
    mock_res.scalars.return_value.all.return_value = []
    mock_db.execute.return_value = mock_res

    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/webhooks/status")
            assert resp.status_code == 200
            data = resp.json()
            assert "webhook_enabled" in data
            assert "tolerance_seconds" in data
            assert "total_webhook_events" in data
    finally:
        app.dependency_overrides.pop(get_db, None)
