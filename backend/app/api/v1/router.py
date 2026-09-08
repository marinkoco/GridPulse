from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.database import get_db
from app.services.fleet import (
    get_fleet_os_distribution,
    get_fleet_uptime_overview,
    get_node_uptime_history,
)
from app.services.geolocation import (
    get_fleet_geolocation_overview,
    get_fleet_impossible_travel_events,
    get_node_geolocation_audit,
)
from app.services.magicdns_ssl import (
    get_fleet_expiring_certificates,
    get_fleet_magicdns_ssl_overview,
    get_node_magicdns_ssl_audit,
    monitor_magicdns_certificates,
)
from app.services.network_auditor import (
    get_fleet_derp_overview,
    get_fleet_network_routing_overview,
    get_node_network_routing_audit,
)
from app.services.poller import poll_tailscale_devices
from app.services.posture import (
    get_fleet_non_compliant_endpoints,
    get_fleet_posture_compliance_overview,
    get_node_posture_compliance_audit,
)
from app.services.scheduler import get_scheduler_status
from app.services.tailnet_lock import (
    get_fleet_locked_out_nodes,
    get_fleet_signing_nodes,
    get_fleet_tailnet_lock_overview,
    get_fleet_unsigned_nodes,
    get_node_tailnet_lock_audit,
)
from app.services.tailscale_client import (
    TailscaleClient,
    TailscaleError,
    TailscaleNotFoundError,
    get_tailscale_client,
)
from app.services.version_monitor import (
    get_fleet_key_expiry_overview,
    get_fleet_version_drift_overview,
    get_node_security_posture,
)
from app.services.webhook import (
    WebhookError,
    WebhookPayloadError,
    WebhookVerificationError,
    get_fleet_acl_events,
    get_fleet_acl_overview,
    get_webhook_listener_status,
    process_tailscale_webhook,
)

api_router = APIRouter(prefix="/api/v1")


@api_router.get("/health", tags=["Health"])
async def v1_health():
    """V1 API health check endpoint."""
    return {"status": "ok", "service": "gridpulse-api-v1"}


@api_router.get("/scheduler/status", tags=["Scheduler"])
async def v1_scheduler_status(request: Request):
    """Returns current status, active jobs, and interval configuration of APScheduler."""
    scheduler = getattr(request.app.state, "scheduler", None)
    return get_scheduler_status(scheduler)


@api_router.post("/tailscale/sync", tags=["Tailscale"])
async def v1_tailscale_sync(db: AsyncSession = Depends(get_db)):
    """Manually triggers an immediate background poll and synchronization of Tailscale fleet devices."""
    result = await poll_tailscale_devices(session_factory=None)
    return result


@api_router.get("/fleet/os-distribution", tags=["Fleet"])
async def v1_fleet_os_distribution(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns aggregated OS fleet distribution, percentages, and OS versions."""
    return await get_fleet_os_distribution(session=db, tailnet=tailnet)


@api_router.get("/fleet/uptime", tags=["Fleet"])
async def v1_fleet_uptime(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns overall fleet uptime metrics and current online/offline streaks for every node."""
    return await get_fleet_uptime_overview(session=db, tailnet=tailnet)


@api_router.get("/fleet/nodes/{node_id}/uptime", tags=["Fleet"])
async def v1_node_uptime_history(
    node_id: str,
    limit: int = Query(50, ge=1, le=500, description="Max snapshots to retrieve"),
    db: AsyncSession = Depends(get_db),
):
    """Returns historical uptime snapshots and availability ratio for a specific node."""
    result = await get_node_uptime_history(session=db, node_id=node_id, limit=limit)
    if "error" in result and result["error"] == "node_not_found":
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    return result


@api_router.get("/fleet/version-drift", tags=["Security", "Fleet"])
async def v1_fleet_version_drift(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    stable_version: Optional[str] = Query(None, description="Override target stable Tailscale version"),
    db: AsyncSession = Depends(get_db),
):
    """Returns aggregated fleet Tailscale version drift, vulnerable outdated devices, and semver breakdown."""
    return await get_fleet_version_drift_overview(session=db, tailnet=tailnet, stable_version=stable_version)


@api_router.get("/fleet/key-expiry", tags=["Security", "Fleet"])
async def v1_fleet_key_expiry(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    warning_days: Optional[int] = Query(None, description="Custom warning threshold in days"),
    critical_days: Optional[int] = Query(None, description="Custom critical threshold in days"),
    db: AsyncSession = Depends(get_db),
):
    """Returns fleet key expiration countdowns, urgent renewal alerts, and status distribution."""
    return await get_fleet_key_expiry_overview(
        session=db, tailnet=tailnet, warning_days=warning_days, critical_days=critical_days
    )


@api_router.get("/fleet/nodes/{node_id}/security", tags=["Security", "Fleet"])
@api_router.get("/fleet/nodes/{node_id}/posture", tags=["Security", "Fleet"])
async def v1_node_security_posture(
    node_id: str,
    stable_version: Optional[str] = Query(None, description="Override target stable Tailscale version"),
    db: AsyncSession = Depends(get_db),
):
    """Returns deep security posture, version drift analysis, and key expiry countdown for a specific node."""
    result = await get_node_security_posture(session=db, node_id=node_id, stable_version=stable_version)
    if "error" in result and result["error"] == "node_not_found":
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    return result


@api_router.get("/fleet/routes", tags=["Network", "Fleet"])
@api_router.get("/fleet/network-routing", tags=["Network", "Fleet"])
@api_router.get("/fleet/routing", tags=["Network", "Fleet"])
async def v1_fleet_network_routing(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns aggregated fleet network routes, exit nodes, unauthorized advertisements, and subnets."""
    return await get_fleet_network_routing_overview(session=db, tailnet=tailnet)


@api_router.get("/fleet/derp", tags=["Network", "Fleet"])
@api_router.get("/fleet/derp-overview", tags=["Network", "Fleet"])
async def v1_fleet_derp_overview(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns fleet-wide DERP relay usage distribution, fallback rates, and region performance."""
    return await get_fleet_derp_overview(session=db, tailnet=tailnet)


@api_router.get("/fleet/nodes/{node_id}/routes", tags=["Network", "Fleet"])
@api_router.get("/fleet/nodes/{node_id}/routing", tags=["Network", "Fleet"])
@api_router.get("/fleet/nodes/{node_id}/network", tags=["Network", "Fleet"])
async def v1_node_network_routing_audit(
    node_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Returns detailed network routing audit, exit node authorization, and DERP telemetry for a specific node."""
    result = await get_node_network_routing_audit(session=db, node_id=node_id)
    if "error" in result and result["error"] == "node_not_found":
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    return result


@api_router.get("/fleet/posture", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/posture/overview", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/posture-compliance", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/compliance", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/compliance/overview", tags=["Compliance", "Posture", "Fleet"])
async def v1_fleet_posture_compliance_overview(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns aggregated fleet device posture compliance overview for auto-updates and encryption."""
    return await get_fleet_posture_compliance_overview(session=db, tailnet=tailnet)


@api_router.get("/fleet/posture/non-compliant", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/compliance/non-compliant", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/non-compliant", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/non-compliant-endpoints", tags=["Compliance", "Posture", "Fleet"])
async def v1_fleet_non_compliant_endpoints(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    violation_filter: Optional[str] = Query(
        None,
        description="Filter by violation type ('auto_update', 'state_encrypted', 'all')",
    ),
    db: AsyncSession = Depends(get_db),
):
    """Returns list of non-compliant endpoints with violation details and remediation recommendations."""
    return await get_fleet_non_compliant_endpoints(
        session=db, tailnet=tailnet, violation_filter=violation_filter
    )


@api_router.get("/fleet/nodes/{node_id}/compliance", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/nodes/{node_id}/compliance-audit", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/nodes/{node_id}/device-posture", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/nodes/{node_id}/posture-compliance", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/nodes/{node_id}/posture/audit", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/posture/nodes/{node_id}", tags=["Compliance", "Posture", "Fleet"])
@api_router.get("/fleet/compliance/nodes/{node_id}", tags=["Compliance", "Posture", "Fleet"])
async def v1_node_posture_compliance_audit(
    node_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Returns detailed device posture compliance audit, attribute values, violations, and state history for a specific node."""
    result = await get_node_posture_compliance_audit(session=db, node_id=node_id)
    if "error" in result and result["error"] == "node_not_found":
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    return result


@api_router.get("/fleet/geolocation", tags=["Geolocation", "Security", "Fleet"])
@api_router.get("/fleet/geolocation/overview", tags=["Geolocation", "Security", "Fleet"])
@api_router.get("/fleet/geo", tags=["Geolocation", "Security", "Fleet"])
async def v1_fleet_geolocation_overview(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns aggregated fleet geolocation distribution, country breakdown, and impossible travel alerts."""
    return await get_fleet_geolocation_overview(session=db, tailnet=tailnet)


@api_router.get("/fleet/geolocation/impossible-travel", tags=["Geolocation", "Security", "Fleet"])
@api_router.get("/fleet/impossible-travel", tags=["Geolocation", "Security", "Fleet"])
@api_router.get("/fleet/impossible-travel-events", tags=["Geolocation", "Security", "Fleet"])
@api_router.get("/fleet/geolocation/events", tags=["Geolocation", "Security", "Fleet"])
async def v1_fleet_impossible_travel_events(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    limit: int = Query(50, ge=1, le=500, description="Max events to retrieve"),
    db: AsyncSession = Depends(get_db),
):
    """Returns logged impossible travel security events from fleet audit logs."""
    return await get_fleet_impossible_travel_events(session=db, tailnet=tailnet, limit=limit)


@api_router.get("/fleet/nodes/{node_id}/geolocation", tags=["Geolocation", "Security", "Fleet"])
@api_router.get("/fleet/nodes/{node_id}/geo", tags=["Geolocation", "Security", "Fleet"])
@api_router.get("/fleet/geolocation/nodes/{node_id}", tags=["Geolocation", "Security", "Fleet"])
async def v1_node_geolocation_audit(
    node_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Returns detailed geolocation tracking, physical location, and impossible travel audit for a specific node."""
    result = await get_node_geolocation_audit(session=db, node_id=node_id)
    if "error" in result and result["error"] == "node_not_found":
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    return result

@api_router.get("/fleet/tailnet-lock", tags=["Tailnet Lock", "Security", "Fleet"])
@api_router.get("/fleet/tailnet-lock/overview", tags=["Tailnet Lock", "Security", "Fleet"])
@api_router.get("/fleet/lock", tags=["Tailnet Lock", "Security", "Fleet"])
async def v1_fleet_tailnet_lock_overview(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns aggregated fleet tailnet lock overview, signing nodes, and lockout status."""
    return await get_fleet_tailnet_lock_overview(session=db, tailnet=tailnet)


@api_router.get("/fleet/tailnet-lock/locked-out", tags=["Tailnet Lock", "Security", "Fleet"])
@api_router.get("/fleet/locked-out", tags=["Tailnet Lock", "Security", "Fleet"])
async def v1_fleet_locked_out_nodes(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns nodes that are locked out from the tailnet."""
    return await get_fleet_locked_out_nodes(session=db, tailnet=tailnet)


@api_router.get("/fleet/tailnet-lock/unsigned", tags=["Tailnet Lock", "Security", "Fleet"])
@api_router.get("/fleet/unsigned-nodes", tags=["Tailnet Lock", "Security", "Fleet"])
async def v1_fleet_unsigned_nodes(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns nodes with unsigned or unverified node keys."""
    return await get_fleet_unsigned_nodes(session=db, tailnet=tailnet)


@api_router.get("/fleet/tailnet-lock/signing-nodes", tags=["Tailnet Lock", "Security", "Fleet"])
@api_router.get("/fleet/signing-nodes", tags=["Tailnet Lock", "Security", "Fleet"])
async def v1_fleet_signing_nodes(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns authorized tailnet lock signing nodes."""
    return await get_fleet_signing_nodes(session=db, tailnet=tailnet)


@api_router.get("/fleet/nodes/{node_id}/tailnet-lock", tags=["Tailnet Lock", "Security", "Fleet"])
@api_router.get("/fleet/nodes/{node_id}/lock", tags=["Tailnet Lock", "Security", "Fleet"])
async def v1_node_tailnet_lock_audit(
    node_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Returns detailed tailnet lock status and key audit for a specific node."""
    result = await get_node_tailnet_lock_audit(session=db, node_id=node_id)
    if "error" in result and result["error"] == "node_not_found":
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    return result


@api_router.get("/fleet/magicdns-ssl", tags=["MagicDNS", "SSL", "Security", "Fleet"])
@api_router.get("/fleet/magicdns-ssl/overview", tags=["MagicDNS", "SSL", "Security", "Fleet"])
@api_router.get("/fleet/ssl", tags=["MagicDNS", "SSL", "Security", "Fleet"])
@api_router.get("/fleet/certificates", tags=["MagicDNS", "SSL", "Security", "Fleet"])
async def v1_fleet_magicdns_ssl_overview(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns fleet MagicDNS TLS certificate overview, expiration distribution, and health."""
    return await get_fleet_magicdns_ssl_overview(session=db, tailnet=tailnet)


@api_router.get("/fleet/magicdns-ssl/expiring", tags=["MagicDNS", "SSL", "Security", "Fleet"])
@api_router.get("/fleet/ssl/expiring", tags=["MagicDNS", "SSL", "Security", "Fleet"])
@api_router.get("/fleet/certificates/expiring", tags=["MagicDNS", "SSL", "Security", "Fleet"])
async def v1_fleet_expiring_certificates(
    tailnet: Optional[str] = Query(None, description="Filter fleet by tailnet domain"),
    days: Optional[int] = Query(None, description="Expiration threshold in days"),
    db: AsyncSession = Depends(get_db),
):
    """Returns fleet MagicDNS certificates expiring within threshold days or expired."""
    return await get_fleet_expiring_certificates(session=db, tailnet=tailnet, days_threshold=days)


@api_router.post("/fleet/magicdns-ssl/probe", tags=["MagicDNS", "SSL", "Scheduler"])
@api_router.post("/fleet/ssl/probe", tags=["MagicDNS", "SSL", "Scheduler"])
async def v1_trigger_magicdns_ssl_probe():
    """Manually triggers the MagicDNS TLS/SSL certificate monitoring task."""
    return await monitor_magicdns_certificates()


@api_router.get("/fleet/nodes/{node_id}/magicdns-ssl", tags=["MagicDNS", "SSL", "Security", "Fleet"])
@api_router.get("/fleet/nodes/{node_id}/ssl", tags=["MagicDNS", "SSL", "Security", "Fleet"])
@api_router.get("/fleet/nodes/{node_id}/certificate", tags=["MagicDNS", "SSL", "Security", "Fleet"])
async def v1_node_magicdns_ssl_audit(
    node_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Returns detailed MagicDNS TLS certificate status and audit history for a specific node."""
    result = await get_node_magicdns_ssl_audit(session=db, node_id=node_id)
    if "error" in result and result["error"] == "node_not_found":
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    return result


@api_router.post("/webhooks/tailscale", tags=["Webhooks", "Tailscale"])
@api_router.post("/tailscale/webhook", tags=["Webhooks", "Tailscale"])
async def v1_tailscale_webhook_listener(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Real-time HTTPS webhook listener endpoint receiving Tailscale configuration changes and ACL modification events."""
    raw_body = await request.body()
    sig_header = request.headers.get("Tailscale-Webhook-Signature") or request.headers.get("X-Tailscale-Signature")
    client_ip = request.client.host if request.client else None

    # Instantiate tailscale client if configured
    ts_client: Optional[TailscaleClient] = None
    try:
        ts_client = TailscaleClient()
        if not ts_client.is_configured:
            ts_client = None
    except Exception:
        ts_client = None

    try:
        result = await process_tailscale_webhook(
            raw_body=raw_body,
            signature_header=sig_header,
            session=db,
            tailscale_client=ts_client,
            client_ip=client_ip,
        )
        return result
    except WebhookVerificationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    except WebhookPayloadError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Internal webhook processing error: {str(exc)}")
    finally:
        if ts_client is not None:
            await ts_client.close()


@api_router.get("/fleet/acl/events", tags=["ACL", "Security", "Fleet"])
@api_router.get("/fleet/acl", tags=["ACL", "Security", "Fleet"])
@api_router.get("/acl/events", tags=["ACL", "Security", "Fleet"])
async def v1_fleet_acl_events(
    limit: int = Query(50, ge=1, le=500, description="Max ACL events to retrieve"),
    tailnet: Optional[str] = Query(None, description="Filter events by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns chronological audit log of Tailscale ACL modifications and policy changes."""
    return await get_fleet_acl_events(session=db, limit=limit, tailnet=tailnet)


@api_router.get("/fleet/acl/overview", tags=["ACL", "Security", "Fleet"])
@api_router.get("/acl/overview", tags=["ACL", "Security", "Fleet"])
async def v1_fleet_acl_overview(
    tailnet: Optional[str] = Query(None, description="Filter overview by tailnet domain"),
    db: AsyncSession = Depends(get_db),
):
    """Returns high-level summary and metrics for Tailscale ACL and configuration update events."""
    return await get_fleet_acl_overview(session=db, tailnet=tailnet)


@api_router.get("/fleet/acl/policy", tags=["ACL", "Tailscale"])
@api_router.get("/tailscale/acl", tags=["ACL", "Tailscale"])
async def v1_get_tailscale_acl_policy(
    tailnet: Optional[str] = Query(None, description="Target tailnet name"),
    client: TailscaleClient = Depends(get_tailscale_client),
):
    """Fetches the live tailnet ACL policy file directly from the Tailscale API."""
    try:
        return await client.get_acl(tailnet=tailnet)
    except TailscaleNotFoundError:
        raise HTTPException(status_code=404, detail="Tailnet or ACL policy not found")
    except TailscaleError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=exc.message)


@api_router.get("/webhooks/status", tags=["Webhooks"])
@api_router.get("/fleet/webhooks/overview", tags=["Webhooks"])
async def v1_webhooks_status(
    db: AsyncSession = Depends(get_db),
):
    """Returns operational status, security verification config, and event statistics for the webhook listener."""
    return await get_webhook_listener_status(session=db)


