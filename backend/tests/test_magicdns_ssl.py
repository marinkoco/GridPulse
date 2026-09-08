from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import socket
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

from httpx import ASGITransport, AsyncClient, ConnectError, Response
import pytest

from app.config import settings
from app.main import app
from app.models.audit_log import AuditLog
from app.models.enums import (
    AuditEventType,
    AuditSeverity,
    EventCategory,
    SSLCertificateStatus,
)
from app.models.node import Node
from app.schemas.tailscale import TailscaleDevice
from app.services.magicdns_ssl import (
    DEFAULT_CRITICAL_DAYS,
    DEFAULT_SSL_PORT,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_WARNING_DAYS,
    MAGICDNS_DOMAIN_SUFFIX,
    audit_node_magicdns_ssl,
    extract_magicdns_domain,
    format_countdown_human,
    get_fleet_expiring_certificates,
    get_fleet_magicdns_ssl_overview,
    get_node_magicdns_ssl_audit,
    monitor_magicdns_certificates,
    parse_date_to_utc,
    parse_name_tuples,
    parse_tls_certificate_info,
    probe_domain_ssl,
)


# ---------------------------------------------------------------------------
# Test Fixtures & Helpers
# ---------------------------------------------------------------------------


def make_test_device(
    device_id: str = "dev-1",
    hostname: str = "host1",
    name: str = "host1.example.ts.net",
    attributes: dict | None = None,
    tags: list[str] | None = None,
    online: bool = True,
) -> TailscaleDevice:
    """Helper to construct valid TailscaleDevice schemas for testing."""
    return TailscaleDevice.model_validate(
        {
            "id": device_id,
            "nodeId": f"nodeId-{device_id}",
            "name": name,
            "hostname": hostname,
            "os": "linux",
            "attributes": attributes or {},
            "tags": tags or [],
            "online": online,
            "keyExpiryDisabled": True,
        }
    )


def make_test_node(
    node_id: str = "n-1",
    hostname: str = "host1",
    name: str = "host1.example.ts.net",
    tailnet: str = "example.ts.net",
    telemetry_metadata: dict | None = None,
) -> Node:
    """Helper to construct Node ORM models for testing."""
    node = Node(
        id=node_id,
        node_id=f"nodeId-{node_id}",
        hostname=hostname,
        name=name,
        user="dev@example.org",
        tailnet=tailnet,
        os="linux",
        client_version="1.60.0",
        is_online=True,
        key_expiry_disabled=True,
        telemetry_metadata=telemetry_metadata or {},
    )
    return node


# ---------------------------------------------------------------------------
# Domain Extraction Tests (extract_magicdns_domain)
# ---------------------------------------------------------------------------


def test_extract_magicdns_domain_from_explicit_attribute():
    """Extracts domain from explicit magicdns_domain attribute."""
    class CustomDevice:
        magicdns_domain = "srv-01.custom.ts.net"

    assert extract_magicdns_domain(CustomDevice()) == "srv-01.custom.ts.net"


def test_extract_magicdns_domain_from_name():
    """Extracts domain from node name containing .ts.net."""
    device = make_test_device(name="box1.beta.tailscale.net.ts.net")
    assert extract_magicdns_domain(device) == "box1.beta.tailscale.net.ts.net"

    node = make_test_node(name="web-01.mycorp.ts.net")
    assert extract_magicdns_domain(node) == "web-01.mycorp.ts.net"


def test_extract_magicdns_domain_from_hostname():
    """Extracts domain from hostname if it ends with .ts.net."""
    node = make_test_node(hostname="db-primary.tailnet-xyz.ts.net", name="db-primary")
    assert extract_magicdns_domain(node) == "db-primary.tailnet-xyz.ts.net"


def test_extract_magicdns_domain_from_attributes_dict():
    """Extracts domain from posture / node attributes dictionary."""
    dev1 = make_test_device(
        name="internal-box",
        attributes={"dns:magicdnsName": "internal-box.tailnet.ts.net"},
    )
    assert extract_magicdns_domain(dev1) == "internal-box.tailnet.ts.net"

    dev2 = make_test_device(
        name="internal-box2",
        attributes={"fqdn": "box2.tailnet.ts.net"},
    )
    assert extract_magicdns_domain(dev2) == "box2.tailnet.ts.net"

    dev3 = make_test_device(
        name="internal-box3",
        attributes={"magicdns_domain": "box3.tailnet.ts.net"},
    )
    assert extract_magicdns_domain(dev3) == "box3.tailnet.ts.net"


def test_extract_magicdns_domain_from_telemetry_metadata():
    """Extracts domain from previously stored magicdns_ssl telemetry metadata."""
    node = make_test_node(
        name="plain-node",
        hostname="plain-node",
        tailnet="other",
        telemetry_metadata={"magicdns_ssl": {"domain": "cached-domain.ts.net"}},
    )
    assert extract_magicdns_domain(node) == "cached-domain.ts.net"


def test_extract_magicdns_domain_derived_from_hostname_and_tailnet():
    """Derives domain from hostname and tailnet name."""
    # When tailnet contains .ts.net
    node1 = make_test_node(hostname="api-gateway", name="api-gateway", tailnet="infra.ts.net")
    assert extract_magicdns_domain(node1) == "api-gateway.infra.ts.net"

    # When tailnet is a simple name
    node2 = make_test_node(hostname="monitor-01", name="monitor-01", tailnet="tailnet-alpha")
    assert extract_magicdns_domain(node2) == "monitor-01.tailnet-alpha.ts.net"

    # When tailnet is passed explicitly as an argument
    node3 = {"hostname": "worker-node", "name": "worker"}
    assert extract_magicdns_domain(node3, tailnet="test-tailnet") == "worker-node.test-tailnet.ts.net"


def test_extract_magicdns_domain_normalizes_trailing_dot_and_case():
    """Verifies trailing dot and uppercase characters are stripped and lowercased."""
    node = make_test_node(name="PROD-SERVER.MYNET.TS.NET.")
    assert extract_magicdns_domain(node) == "prod-server.mynet.ts.net"


def test_extract_magicdns_domain_returns_none_for_non_ts_net():
    """Returns None when no .ts.net domain can be found or inferred."""
    dev = make_test_device(name="node.external.com", hostname="node")
    assert extract_magicdns_domain(dev) is None

    assert extract_magicdns_domain({}) is None
    assert extract_magicdns_domain({"name": None, "hostname": None}) is None


# ---------------------------------------------------------------------------
# Date Parsing & Countdown Tests (parse_date_to_utc, format_countdown_human)
# ---------------------------------------------------------------------------


def test_parse_date_to_utc_none_and_empty():
    """Verifies None or empty values return None."""
    assert parse_date_to_utc(None) is None
    assert parse_date_to_utc("") is None
    assert parse_date_to_utc("   ") is None


def test_parse_date_to_utc_datetime_instances():
    """Handles timezone-naive and timezone-aware datetimes."""
    naive = datetime(2027, 5, 25, 12, 0, 0)
    utc_dt = parse_date_to_utc(naive)
    assert utc_dt is not None
    assert utc_dt.tzinfo == timezone.utc
    assert utc_dt.year == 2027

    aware = datetime(2027, 5, 25, 12, 0, 0, tzinfo=timezone.utc)
    assert parse_date_to_utc(aware) == aware


def test_parse_date_to_utc_openssl_gmt_format():
    """Parses OpenSSL getpeercert format: 'May 25 12:00:00 2027 GMT'."""
    parsed = parse_date_to_utc("May 25 12:00:00 2027 GMT")
    assert parsed is not None
    assert parsed.year == 2027
    assert parsed.month == 5
    assert parsed.day == 25
    assert parsed.tzinfo == timezone.utc


def test_parse_date_to_utc_iso8601():
    """Parses standard ISO 8601 strings."""
    parsed = parse_date_to_utc("2027-05-25T14:30:00Z")
    assert parsed is not None
    assert parsed.year == 2027
    assert parsed.hour == 14
    assert parsed.tzinfo == timezone.utc


def test_parse_date_to_utc_numeric_timestamp():
    """Parses unix timestamps (int and float)."""
    ts = 1811246400.0  # 2027-05-25T12:00:00 UTC
    parsed = parse_date_to_utc(ts)
    assert parsed is not None
    assert parsed.year == 2027
    assert parsed.month == 5


def test_parse_date_to_utc_invalid_string():
    """Returns None for unparseable strings without raising."""
    assert parse_date_to_utc("invalid-date-format-xyz") is None


def test_format_countdown_human():
    """Verifies countdown strings for future and past durations."""
    # Future durations
    assert format_countdown_human(30 * 86400) == "30 days"
    assert format_countdown_human(86400) == "1 day"
    assert "1 day" in format_countdown_human(86400 + 3600)
    assert format_countdown_human(3600) == "1 hour"
    assert format_countdown_human(300) == "5 minutes"
    assert format_countdown_human(45) == "< 1 minute"

    # Past durations (expired)
    expired_str = format_countdown_human(-86400)
    assert "expired" in expired_str
    assert "1 day ago" in expired_str

    expired_hr = format_countdown_human(-7200)
    assert "expired" in expired_hr
    assert "2 hours ago" in expired_hr


# ---------------------------------------------------------------------------
# Certificate Parsing Tests (parse_name_tuples, parse_tls_certificate_info)
# ---------------------------------------------------------------------------


def test_parse_name_tuples():
    """Flattens OpenSSL subject and issuer nested tuple structures."""
    sample_tuples = (
        (("countryName", "US"),),
        (("organizationName", "Let's Encrypt"),),
        (("commonName", "R3"),),
    )
    result = parse_name_tuples(sample_tuples)
    assert result == {
        "countryName": "US",
        "organizationName": "Let's Encrypt",
        "commonName": "R3",
    }
    assert parse_name_tuples(None) == {}
    assert parse_name_tuples([]) == {}


def test_parse_tls_certificate_info_valid():
    """Parses certificate with plenty of validity remaining."""
    ref_now = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    expiry = ref_now + timedelta(days=60)
    issued = ref_now - timedelta(days=30)

    cert_payload = {
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
        "notBefore": issued.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": ((("commonName", "node-01.example.ts.net"),),),
        "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R3"),)),
        "subjectAltName": (("DNS", "node-01.example.ts.net"), ("DNS", "alt.example.ts.net")),
        "serialNumber": "A1B2C3D4",
        "version": 3,
    }

    info = parse_tls_certificate_info(cert_payload, now=ref_now)
    assert info["status"] == SSLCertificateStatus.VALID.value
    assert info["severity"] == AuditSeverity.INFO.value
    assert info["is_expired"] is False
    assert info["is_expiring_soon"] is False
    assert round(info["remaining_days"]) == 60
    assert info["common_name"] == "node-01.example.ts.net"
    assert "node-01.example.ts.net" in info["subject_alt_names"]
    assert "alt.example.ts.net" in info["subject_alt_names"]
    assert info["serial_number"] == "A1B2C3D4"


def test_parse_tls_certificate_info_expiring_soon_warning():
    """Parses certificate expiring within 30 days (warning threshold)."""
    ref_now = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    expiry = ref_now + timedelta(days=15)  # <= 30 days, > 7 days

    cert_payload = {
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": ((("commonName", "expiring.ts.net"),),),
    }

    info = parse_tls_certificate_info(cert_payload, now=ref_now)
    assert info["status"] == SSLCertificateStatus.EXPIRING_SOON.value
    assert info["severity"] == AuditSeverity.WARNING.value
    assert info["is_expiring_soon"] is True
    assert info["is_expired"] is False
    assert round(info["remaining_days"]) == 15


def test_parse_tls_certificate_info_expiring_soon_critical():
    """Parses certificate expiring within 7 days (critical threshold)."""
    ref_now = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    expiry = ref_now + timedelta(days=3)  # <= 7 days

    cert_payload = {
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": ((("commonName", "urgent.ts.net"),),),
    }

    info = parse_tls_certificate_info(cert_payload, now=ref_now)
    assert info["status"] == SSLCertificateStatus.EXPIRING_SOON.value
    assert info["severity"] == AuditSeverity.CRITICAL.value
    assert info["is_expiring_soon"] is True
    assert info["is_expired"] is False


def test_parse_tls_certificate_info_expired():
    """Parses expired certificate."""
    ref_now = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    expiry = ref_now - timedelta(days=2)  # Expired 2 days ago

    cert_payload = {
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": ((("commonName", "expired.ts.net"),),),
    }

    info = parse_tls_certificate_info(cert_payload, now=ref_now)
    assert info["status"] == SSLCertificateStatus.EXPIRED.value
    assert info["severity"] == AuditSeverity.CRITICAL.value
    assert info["is_expired"] is True
    assert info["is_expiring_soon"] is False
    assert info["remaining_days"] < 0
    assert "expired" in info["countdown_human"]


def test_parse_tls_certificate_info_missing_dates():
    """Parses certificate with missing or unparseable notAfter date."""
    cert_payload = {"subject": ((("commonName", "broken.ts.net"),),)}
    info = parse_tls_certificate_info(cert_payload)
    assert info["status"] == SSLCertificateStatus.ERROR.value
    assert info["severity"] == AuditSeverity.ERROR.value
    assert info["expires_at"] is None


# ---------------------------------------------------------------------------
# Domain SSL Probing Tests (probe_domain_ssl)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_domain_ssl_success():
    """Tests successful TLS connection and HTTP probe."""
    ref_now = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    expiry = ref_now + timedelta(days=45)

    mock_ssl_obj = MagicMock()
    mock_ssl_obj.getpeercert.return_value = {
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": ((("commonName", "box1.example.ts.net"),),),
        "subjectAltName": (("DNS", "box1.example.ts.net"),),
    }
    mock_ssl_obj.version.return_value = "TLSv1.3"
    mock_ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    mock_writer = MagicMock()
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_reader = MagicMock()

    mock_http_client = AsyncMock(spec=AsyncClient)
    mock_http_response = Response(status_code=200, request=MagicMock())
    mock_http_client.get.return_value = mock_http_response

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        mock_connect.return_value = (mock_reader, mock_writer)

        result = await probe_domain_ssl(
            domain="box1.example.ts.net",
            port=443,
            http_client=mock_http_client,
            now=ref_now,
        )

        assert result["domain"] == "box1.example.ts.net"
        assert result["is_reachable"] is True
        assert result["http_reachable"] is True
        assert result["http_status_code"] == 200
        assert result["status"] == SSLCertificateStatus.VALID.value
        assert result["tls_version"] == "TLSv1.3"
        assert result["cipher"][0] == "TLS_AES_256_GCM_SHA384"
        assert result["is_expired"] is False
        assert result["is_expiring_soon"] is False


@pytest.mark.asyncio
async def test_probe_domain_ssl_certificate_expired_error():
    """Tests handling of SSLCertVerificationError for expired certificate."""
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        mock_connect.side_effect = ssl.SSLCertVerificationError(
            1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired"
        )

        result = await probe_domain_ssl(
            domain="expired.example.ts.net",
            port=443,
        )

        assert result["is_reachable"] is True
        assert result["is_expired"] is True
        assert result["status"] == SSLCertificateStatus.EXPIRED.value
        assert result["error_type"] == "ssl_verification_error"


@pytest.mark.asyncio
async def test_probe_domain_ssl_verification_error_other():
    """Tests handling of SSLCertVerificationError for self-signed or invalid CA."""
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        mock_connect.side_effect = ssl.SSLCertVerificationError(
            1, "[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate in certificate chain"
        )

        result = await probe_domain_ssl(
            domain="self-signed.example.ts.net",
            port=443,
        )

        assert result["is_reachable"] is True
        assert result["status"] == SSLCertificateStatus.ERROR.value
        assert result["error_type"] == "ssl_verification_error"


@pytest.mark.asyncio
async def test_probe_domain_ssl_timeout():
    """Tests handling of connection timeout."""
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        mock_connect.side_effect = asyncio.TimeoutError()

        result = await probe_domain_ssl(
            domain="slow.example.ts.net",
            timeout=2.0,
        )

        assert result["is_reachable"] is False
        assert result["status"] == SSLCertificateStatus.UNREACHABLE.value
        assert result["error_type"] == "timeout"


@pytest.mark.asyncio
async def test_probe_domain_ssl_connection_refused():
    """Tests handling of connection refused."""
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        mock_connect.side_effect = ConnectionRefusedError()

        result = await probe_domain_ssl(
            domain="refused.example.ts.net",
        )

        assert result["is_reachable"] is False
        assert result["status"] == SSLCertificateStatus.UNREACHABLE.value
        assert result["error_type"] == "connection_refused"


@pytest.mark.asyncio
async def test_probe_domain_ssl_dns_failure():
    """Tests handling of DNS resolution failure."""
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        mock_connect.side_effect = socket.gaierror(-2, "Name or service not known")

        result = await probe_domain_ssl(
            domain="unknown.example.ts.net",
        )

        assert result["is_reachable"] is False
        assert result["status"] == SSLCertificateStatus.UNREACHABLE.value
        assert result["error_type"] == "dns_resolution_failed"


@pytest.mark.asyncio
async def test_probe_domain_ssl_http_error_tls_preserved():
    """Tests that HTTP connection failure does not overwrite valid TLS certificate."""
    ref_now = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    expiry = ref_now + timedelta(days=50)

    mock_ssl_obj = MagicMock()
    mock_ssl_obj.getpeercert.return_value = {
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": ((("commonName", "box2.example.ts.net"),),),
    }
    mock_ssl_obj.version.return_value = "TLSv1.3"
    mock_ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    mock_writer = MagicMock()
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_reader = MagicMock()

    mock_http_client = AsyncMock(spec=AsyncClient)
    mock_http_client.get.side_effect = ConnectError("HTTP service stopped")

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        mock_connect.return_value = (mock_reader, mock_writer)

        result = await probe_domain_ssl(
            domain="box2.example.ts.net",
            http_client=mock_http_client,
            now=ref_now,
        )

        assert result["is_reachable"] is True
        assert result["http_reachable"] is False
        assert result["status"] == SSLCertificateStatus.VALID.value
        assert result["expires_at"] is not None


# ---------------------------------------------------------------------------
# Node SSL Audit Tests (audit_node_magicdns_ssl)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_node_magicdns_ssl_not_configured():
    """Node without .ts.net domain returns not_configured status without probing."""
    node = make_test_node(name="external-srv.org", hostname="external-srv", tailnet="example.com")
    result = await audit_node_magicdns_ssl(node)
    assert result["is_configured"] is False
    assert result["status"] == SSLCertificateStatus.NOT_CONFIGURED.value
    assert result["alerts"] == []


@pytest.mark.asyncio
async def test_audit_node_magicdns_ssl_valid_no_alerts():
    """Valid certificate results in no alerts logged to session."""
    node = make_test_node(name="valid-box.demo.ts.net")
    mock_session = AsyncMock()
    mock_session.add = MagicMock()

    mock_probe_result = {
        "domain": "valid-box.demo.ts.net",
        "is_reachable": True,
        "status": SSLCertificateStatus.VALID.value,
        "is_expired": False,
        "is_expiring_soon": False,
        "expires_at": "2027-01-01T00:00:00+00:00",
        "remaining_days": 115.0,
        "countdown_human": "115 days",
    }

    with patch("app.services.magicdns_ssl.probe_domain_ssl", new_callable=AsyncMock) as mock_probe:
        mock_probe.return_value = mock_probe_result

        report = await audit_node_magicdns_ssl(node, session=mock_session, log_events=True)
        assert report["is_configured"] is True
        assert report["alerts"] == []
        mock_session.add.assert_not_called()


@pytest.mark.asyncio
async def test_audit_node_magicdns_ssl_logs_expiring_soon_alert():
    """Expiring certificate triggers SSL_CERT_EXPIRING audit log entry."""
    node = make_test_node(name="expiring-box.demo.ts.net")
    mock_session = AsyncMock()
    added_logs: list[AuditLog] = []
    mock_session.add = MagicMock(side_effect=lambda log_obj: added_logs.append(log_obj))

    mock_probe_result = {
        "domain": "expiring-box.demo.ts.net",
        "is_reachable": True,
        "status": SSLCertificateStatus.EXPIRING_SOON.value,
        "is_expired": False,
        "is_expiring_soon": True,
        "expires_at": "2026-09-20T00:00:00+00:00",
        "remaining_days": 12.0,
        "countdown_human": "12 days",
    }

    with patch("app.services.magicdns_ssl.probe_domain_ssl", new_callable=AsyncMock) as mock_probe:
        mock_probe.return_value = mock_probe_result

        report = await audit_node_magicdns_ssl(node, session=mock_session, log_events=True)
        assert len(report["alerts"]) == 1
        assert report["alerts"][0]["event_type"] == AuditEventType.SSL_CERT_EXPIRING.value
        assert len(added_logs) == 1
        assert added_logs[0].event_type == AuditEventType.SSL_CERT_EXPIRING.value
        assert added_logs[0].severity == AuditSeverity.WARNING.value


@pytest.mark.asyncio
async def test_audit_node_magicdns_ssl_logs_expired_alert():
    """Expired certificate triggers SSL_CERT_EXPIRED audit log with critical severity."""
    node = make_test_node(name="expired-box.demo.ts.net")
    mock_session = AsyncMock()
    added_logs: list[AuditLog] = []
    mock_session.add = MagicMock(side_effect=lambda log_obj: added_logs.append(log_obj))

    mock_probe_result = {
        "domain": "expired-box.demo.ts.net",
        "is_reachable": True,
        "status": SSLCertificateStatus.EXPIRED.value,
        "is_expired": True,
        "is_expiring_soon": False,
        "expires_at": "2026-09-01T00:00:00+00:00",
        "remaining_days": -7.0,
        "countdown_human": "expired 7 days ago",
    }

    with patch("app.services.magicdns_ssl.probe_domain_ssl", new_callable=AsyncMock) as mock_probe:
        mock_probe.return_value = mock_probe_result

        report = await audit_node_magicdns_ssl(node, session=mock_session, log_events=True)
        assert len(report["alerts"]) == 1
        assert report["alerts"][0]["event_type"] == AuditEventType.SSL_CERT_EXPIRED.value
        assert len(added_logs) == 1
        assert added_logs[0].event_type == AuditEventType.SSL_CERT_EXPIRED.value
        assert added_logs[0].severity == AuditSeverity.CRITICAL.value


@pytest.mark.asyncio
async def test_audit_node_magicdns_ssl_logs_renewal_transition():
    """Transition from expired to valid logs SSL_CERT_VALID recovery event."""
    node = make_test_node(
        name="renewed-box.demo.ts.net",
        telemetry_metadata={"magicdns_ssl": {"status": SSLCertificateStatus.EXPIRED.value}},
    )
    mock_session = AsyncMock()
    added_logs: list[AuditLog] = []
    mock_session.add = MagicMock(side_effect=lambda log_obj: added_logs.append(log_obj))

    mock_probe_result = {
        "domain": "renewed-box.demo.ts.net",
        "is_reachable": True,
        "status": SSLCertificateStatus.VALID.value,
        "is_expired": False,
        "is_expiring_soon": False,
        "expires_at": "2027-09-01T00:00:00+00:00",
        "remaining_days": 358.0,
        "countdown_human": "358 days",
    }

    with patch("app.services.magicdns_ssl.probe_domain_ssl", new_callable=AsyncMock) as mock_probe:
        mock_probe.return_value = mock_probe_result

        report = await audit_node_magicdns_ssl(node, session=mock_session, log_events=True)
        assert len(report["alerts"]) == 1
        assert report["alerts"][0]["event_type"] == AuditEventType.SSL_CERT_VALID.value
        assert len(added_logs) == 1
        assert added_logs[0].event_type == AuditEventType.SSL_CERT_VALID.value
        assert added_logs[0].severity == AuditSeverity.INFO.value


# ---------------------------------------------------------------------------
# Background Task Tests (monitor_magicdns_certificates)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_monitor_magicdns_certificates_worker():
    """Tests the background task discovering nodes, probing them, and updating telemetry_metadata."""
    node1 = make_test_node(node_id="n-101", name="node1.corp.ts.net")
    node2 = make_test_node(node_id="n-102", name="node2.corp.ts.net")
    node3 = make_test_node(node_id="n-103", name="external.org", hostname="external", tailnet="example.com")

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [node1, node2, node3]
    mock_session.execute.return_value = mock_result
    mock_session.commit = AsyncMock()

    class MockSessionFactory:
        def __call__(self):
            return self

        async def __aenter__(self):
            return mock_session

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            return None

    # Mock audit_node_magicdns_ssl
    async def mock_audit_side_effect(node, **kwargs):
        if node.id == "n-101":
            return {
                "domain": "node1.corp.ts.net",
                "probe": {
                    "status": SSLCertificateStatus.VALID.value,
                    "is_reachable": True,
                    "expires_at": "2027-01-01T00:00:00+00:00",
                    "remaining_days": 115.0,
                    "is_expired": False,
                    "is_expiring_soon": False,
                },
                "alerts": [],
            }
        else:
            return {
                "domain": "node2.corp.ts.net",
                "probe": {
                    "status": SSLCertificateStatus.EXPIRING_SOON.value,
                    "is_reachable": True,
                    "expires_at": "2026-09-18T00:00:00+00:00",
                    "remaining_days": 10.0,
                    "is_expired": False,
                    "is_expiring_soon": True,
                },
                "alerts": [{"event_type": AuditEventType.SSL_CERT_EXPIRING.value}],
            }

    with patch(
        "app.services.magicdns_ssl.audit_node_magicdns_ssl", side_effect=mock_audit_side_effect
    ):
        result = await monitor_magicdns_certificates(
            session_factory=MockSessionFactory(),
            concurrency_limit=2,
            log_events=True,
        )

        assert result["status"] == "completed"
        assert result["total_nodes_checked"] == 2  # node3 not a .ts.net domain
        assert result["valid_count"] == 1
        assert result["expiring_soon_count"] == 1
        assert result["alerts_logged"] == 1
        mock_session.commit.assert_awaited_once()

        # Telemetry metadata should be updated
        assert "magicdns_ssl" in node1.telemetry_metadata
        assert node1.telemetry_metadata["magicdns_ssl"]["status"] == SSLCertificateStatus.VALID.value
        assert node2.telemetry_metadata["magicdns_ssl"]["status"] == SSLCertificateStatus.EXPIRING_SOON.value


# ---------------------------------------------------------------------------
# Fleet Aggregation & Query Tests (get_fleet_..., get_node_...)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_fleet_magicdns_ssl_overview():
    """Tests fleet-wide SSL certificate aggregation."""
    node_valid = make_test_node(
        node_id="n-v",
        name="valid.demo.ts.net",
        telemetry_metadata={
            "magicdns_ssl": {
                "domain": "valid.demo.ts.net",
                "status": SSLCertificateStatus.VALID.value,
                "remaining_days": 55.0,
                "is_expired": False,
                "is_expiring_soon": False,
            }
        },
    )
    node_expiring = make_test_node(
        node_id="n-e",
        name="expiring.demo.ts.net",
        telemetry_metadata={
            "magicdns_ssl": {
                "domain": "expiring.demo.ts.net",
                "status": SSLCertificateStatus.EXPIRING_SOON.value,
                "remaining_days": 12.0,
                "is_expired": False,
                "is_expiring_soon": True,
            }
        },
    )
    node_plain = make_test_node(
        node_id="n-p",
        name="other.org",
        hostname="other",
        tailnet="example.com",
    )

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [node_valid, node_expiring, node_plain]
    mock_session.execute.return_value = mock_result

    overview = await get_fleet_magicdns_ssl_overview(mock_session)
    assert overview["total_fleet_nodes"] == 3
    assert overview["monitored_domains_count"] == 2
    assert overview["valid_count"] == 1
    assert overview["expiring_soon_count"] == 1
    assert len(overview["expiring_soon_list"]) == 1
    assert overview["expiring_soon_list"][0]["node_id"] == "n-e"


@pytest.mark.asyncio
async def test_get_fleet_expiring_certificates():
    """Tests filtering fleet certificates by days threshold."""
    node_expiring = make_test_node(
        node_id="n-e",
        name="expiring.demo.ts.net",
        telemetry_metadata={
            "magicdns_ssl": {
                "domain": "expiring.demo.ts.net",
                "status": SSLCertificateStatus.EXPIRING_SOON.value,
                "remaining_days": 10.0,
                "is_expiring_soon": True,
            }
        },
    )
    node_valid = make_test_node(
        node_id="n-v",
        name="valid.demo.ts.net",
        telemetry_metadata={
            "magicdns_ssl": {
                "domain": "valid.demo.ts.net",
                "status": SSLCertificateStatus.VALID.value,
                "remaining_days": 60.0,
                "is_expiring_soon": False,
            }
        },
    )

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [node_expiring, node_valid]
    mock_session.execute.return_value = mock_result

    expiring = await get_fleet_expiring_certificates(mock_session, days_threshold=14)
    assert len(expiring) == 1
    assert expiring[0]["node_id"] == "n-e"


@pytest.mark.asyncio
async def test_get_node_magicdns_ssl_audit():
    """Tests fetching SSL audit for a single node including audit logs."""
    node = make_test_node(
        node_id="n-target",
        name="target.demo.ts.net",
        telemetry_metadata={
            "magicdns_ssl": {
                "domain": "target.demo.ts.net",
                "status": SSLCertificateStatus.VALID.value,
                "remaining_days": 75.0,
            }
        },
    )
    audit_log = AuditLog(
        id="log-ssl-1",
        node_id="n-target",
        event_type=AuditEventType.SSL_CERT_VALID.value,
        severity=AuditSeverity.INFO.value,
        action="MagicDNS TLS Certificate Valid",
        actor="system/magicdns-ssl-monitor",
        message="Certificate is valid",
        details={},
    )

    mock_session = AsyncMock()
    mock_node_res = MagicMock()
    mock_node_res.scalar_one_or_none.return_value = node
    mock_log_res = MagicMock()
    mock_log_res.scalars.return_value.all.return_value = [audit_log]

    mock_session.execute.side_effect = [mock_node_res, mock_log_res]

    audit = await get_node_magicdns_ssl_audit(mock_session, "n-target")
    assert audit["id"] == "n-target"
    assert audit["domain"] == "target.demo.ts.net"
    assert audit["status"] == SSLCertificateStatus.VALID.value
    assert len(audit["audit_events"]) == 1
    assert audit["audit_events"][0]["event_type"] == AuditEventType.SSL_CERT_VALID.value

    # Test not found
    mock_session.execute.side_effect = None
    mock_not_found = MagicMock()
    mock_not_found.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_not_found

    res_404 = await get_node_magicdns_ssl_audit(mock_session, "unknown")
    assert res_404["error"] == "node_not_found"


# ---------------------------------------------------------------------------
# API Endpoint Tests (/api/v1/fleet/magicdns-ssl/...)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_v1_fleet_magicdns_ssl_overview_endpoint():
    """Tests GET /api/v1/fleet/magicdns-ssl API endpoint."""
    with patch(
        "app.api.v1.router.get_fleet_magicdns_ssl_overview", new_callable=AsyncMock
    ) as mock_overview:
        mock_overview.return_value = {
            "total_fleet_nodes": 5,
            "monitored_domains_count": 4,
            "valid_count": 3,
            "expiring_soon_count": 1,
            "expired_count": 0,
            "unreachable_count": 0,
            "certificates": [],
            "expiring_soon_list": [],
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/fleet/magicdns-ssl")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_fleet_nodes"] == 5
            assert data["monitored_domains_count"] == 4
            assert data["valid_count"] == 3


@pytest.mark.asyncio
async def test_api_v1_fleet_magicdns_ssl_expiring_endpoint():
    """Tests GET /api/v1/fleet/magicdns-ssl/expiring API endpoint."""
    with patch(
        "app.api.v1.router.get_fleet_expiring_certificates", new_callable=AsyncMock
    ) as mock_fn:
        mock_fn.return_value = [
            {
                "node_id": "n-exp-1",
                "domain": "exp.ts.net",
                "remaining_days": 8.0,
                "status": "expiring_soon",
            }
        ]

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/fleet/magicdns-ssl/expiring?days=14")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data) == 1
            assert data[0]["node_id"] == "n-exp-1"


@pytest.mark.asyncio
async def test_api_v1_trigger_magicdns_ssl_probe_endpoint():
    """Tests POST /api/v1/fleet/magicdns-ssl/probe API endpoint."""
    with patch(
        "app.api.v1.router.monitor_magicdns_certificates", new_callable=AsyncMock
    ) as mock_probe:
        mock_probe.return_value = {
            "status": "completed",
            "total_nodes_checked": 2,
            "valid_count": 2,
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/fleet/magicdns-ssl/probe")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "completed"
            assert data["total_nodes_checked"] == 2


@pytest.mark.asyncio
async def test_api_v1_node_magicdns_ssl_audit_endpoint():
    """Tests GET /api/v1/fleet/nodes/{node_id}/magicdns-ssl and 404 handling."""
    with patch(
        "app.api.v1.router.get_node_magicdns_ssl_audit", new_callable=AsyncMock
    ) as mock_audit:
        mock_audit.return_value = {
            "id": "node-target-01",
            "hostname": "target-box",
            "domain": "target-box.demo.ts.net",
            "status": "valid",
            "is_configured": True,
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/fleet/nodes/node-target-01/magicdns-ssl")
            assert resp.status_code == 200
            data = resp.json()
            assert data["hostname"] == "target-box"
            assert data["domain"] == "target-box.demo.ts.net"
            assert data["status"] == "valid"

            # 404 test
            mock_audit.return_value = {"error": "node_not_found", "node_id": "nonexistent"}
            resp_404 = await client.get("/api/v1/fleet/nodes/nonexistent/magicdns-ssl")
            assert resp_404.status_code == 404
            assert "Node 'nonexistent' not found" in resp_404.json()["detail"]
