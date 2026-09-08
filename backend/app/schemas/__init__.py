"""Pydantic schemas package."""

from app.schemas.tailscale import (
    ClientVersionInfo,
    DerpLatencyInfo,
    TailscaleClientConnectivity,
    TailscaleDevice,
    TailscaleDevicesResponse,
    TailscalePostureIdentity,
)
from app.schemas.webhook import (
    AclAuditSummaryResponse,
    TailscaleWebhookActor,
    TailscaleWebhookEvent,
    WebhookProcessedEvent,
    WebhookResponse,
    WebhookStatusResponse,
)

__all__ = [
    "ClientVersionInfo",
    "DerpLatencyInfo",
    "TailscaleClientConnectivity",
    "TailscaleDevice",
    "TailscaleDevicesResponse",
    "TailscalePostureIdentity",
    "AclAuditSummaryResponse",
    "TailscaleWebhookActor",
    "TailscaleWebhookEvent",
    "WebhookProcessedEvent",
    "WebhookResponse",
    "WebhookStatusResponse",
]
