from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, model_validator


class TailscaleWebhookActor(BaseModel):
    """Actor identity metadata representing the user or API token that triggered the webhook event."""

    id: Optional[str] = None
    login_name: Optional[str] = Field(None, alias="loginName")
    display_name: Optional[str] = Field(None, alias="displayName")
    type: Optional[str] = None
    profile_pic_url: Optional[str] = Field(None, alias="profilePicUrl")

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    @property
    def identifier(self) -> str:
        """Returns the most human-readable identifier for the actor."""
        return self.display_name or self.login_name or self.id or "unknown"


class TailscaleWebhookEvent(BaseModel):
    """Structured Pydantic model for a single Tailscale webhook event notification."""

    timestamp: Optional[str] = None
    version: Optional[int] = 1
    type: str
    tailnet: Optional[str] = None
    message: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    actor: Optional[Union[TailscaleWebhookActor, Dict[str, Any], str]] = None

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    @property
    def actor_name(self) -> Optional[str]:
        """Resolves the actor string from either top-level actor or nested data.actor."""
        if isinstance(self.actor, TailscaleWebhookActor):
            return self.actor.identifier
        elif isinstance(self.actor, dict):
            return (
                self.actor.get("displayName")
                or self.actor.get("loginName")
                or self.actor.get("id")
                or self.actor.get("name")
            )
        elif isinstance(self.actor, str) and self.actor.strip():
            return self.actor.strip()

        data_actor = self.data.get("actor") if isinstance(self.data, dict) else None
        if isinstance(data_actor, dict):
            return (
                data_actor.get("displayName")
                or data_actor.get("loginName")
                or data_actor.get("id")
                or data_actor.get("name")
            )
        elif isinstance(data_actor, str) and data_actor.strip():
            return data_actor.strip()

        return None

    @property
    def target_node_id(self) -> Optional[str]:
        """Extracts target device/node ID from the event data payload if applicable."""
        if not isinstance(self.data, dict):
            return None

        for key in ("node_id", "nodeId", "nodeID", "id", "deviceID", "deviceId"):
            val = self.data.get(key)
            if val and isinstance(val, (str, int)):
                return str(val)

        node_obj = self.data.get("node") or self.data.get("device")
        if isinstance(node_obj, dict):
            for key in ("id", "nodeId", "node_id"):
                val = node_obj.get(key)
                if val:
                    return str(val)

        return None

    @property
    def is_policy_update(self) -> bool:
        """Returns True if this event represents an ACL policy modification."""
        return self.type in ("policyUpdate", "policy.update", "aclUpdate", "acl.updated")

    @property
    def is_node_event(self) -> bool:
        """Returns True if this event relates to node lifecycle."""
        return self.type.lower().startswith("node")

    @property
    def is_user_event(self) -> bool:
        """Returns True if this event relates to user lifecycle."""
        return self.type.lower().startswith("user")


class WebhookProcessedEvent(BaseModel):
    """Schema summarizing an event processed and recorded in the audit log."""

    id: str
    event_type: str
    event_category: str
    severity: str
    action: str
    actor: Optional[str] = None
    node_id: Optional[str] = None
    tailnet: Optional[str] = None
    created_at: str

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class WebhookResponse(BaseModel):
    """API response model returned to the webhook sender."""

    status: str = "ok"
    received_events: int = 0
    processed_events: int = 0
    ignored_events: int = 0
    events: List[WebhookProcessedEvent] = Field(default_factory=list)
    message: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class WebhookStatusResponse(BaseModel):
    """Overview of webhook endpoint health, configuration, and traffic statistics."""

    webhook_enabled: bool = True
    secret_configured: bool = False
    verify_signature_enabled: bool = True
    tolerance_seconds: int = 300
    total_webhook_events: int = 0
    last_event_received_at: Optional[str] = None
    event_types_breakdown: Dict[str, int] = Field(default_factory=dict)
    recent_events: List[Dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class AclAuditSummaryResponse(BaseModel):
    """Overview of ACL policy updates and configuration changes."""

    total_acl_events: int = 0
    last_policy_update_at: Optional[str] = None
    last_actor: Optional[str] = None
    recent_events: List[Dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True, extra="allow")
