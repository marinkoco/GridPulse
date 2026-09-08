from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import re
from typing import Any, Dict, List, Optional, Self
from pydantic import BaseModel, ConfigDict, Field, BeforeValidator, model_validator
from typing_extensions import Annotated


class DerpLatencyInfo(BaseModel):
    """Latency and routing details for a specific DERP relay region."""

    latency_ms: Optional[float] = Field(None, alias="latencyMs")
    preferred: bool = False

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class ClientVersionInfo(BaseModel):
    """Client version metadata reported by Tailscale."""

    running_version: Optional[str] = Field(None, alias="runningVersion")
    latest_version: Optional[str] = Field(None, alias="latestVersion")

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class TailscaleClientConnectivity(BaseModel):
    """Network connectivity telemetry reported by the Tailscale daemon."""

    endpoints: List[str] = Field(default_factory=list)
    derp: Optional[str] = None
    mapping_varies_by_dest_ip: Optional[bool] = Field(None, alias="mappingVariesByDestIP")
    latency: Dict[str, Any] = Field(default_factory=dict)
    client_version: Optional[ClientVersionInfo] = Field(None, alias="clientVersion")

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    @property
    def preferred_latency_ms(self) -> Optional[float]:
        """Extracts the latency in milliseconds to the preferred DERP relay."""
        if not self.latency:
            return None
        # Check preferred DERP region first
        if self.derp and self.derp in self.latency:
            entry = self.latency[self.derp]
            if isinstance(entry, dict) and "latencyMs" in entry:
                return float(entry["latencyMs"])
        # Check any entry marked preferred
        for region_data in self.latency.values():
            if isinstance(region_data, dict):
                if region_data.get("preferred") and "latencyMs" in region_data:
                    return float(region_data["latencyMs"])
        # Fallback: lowest non-zero latency
        latencies = [
            float(v["latencyMs"])
            for v in self.latency.values()
            if isinstance(v, dict) and "latencyMs" in v and v["latencyMs"] is not None
        ]
        return min(latencies) if latencies else None


class TailscalePostureIdentity(BaseModel):
    """Device posture and machine identity attributes."""

    serial_numbers: List[str] = Field(default_factory=list, alias="serialNumbers")
    disabled: Optional[bool] = None

    model_config = ConfigDict(populate_by_name=True, extra="allow")


_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
]


def is_internal_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Checks if an IP address is internal (RFC1918, CGNAT/Tailscale, loopback, link-local, multicast)."""
    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
        return True
    return any(ip_obj in net for net in _INTERNAL_NETWORKS)


def _empty_string_to_none(v: Any) -> Any:
    """Coerces empty strings or whitespace-only strings into None for datetime/optional fields."""
    if v == "" or (isinstance(v, str) and not v.strip()):
        return None
    return v


OptionalDatetime = Annotated[Optional[datetime], BeforeValidator(_empty_string_to_none)]


class TailscaleDevice(BaseModel):
    """Pydantic model representing a single Tailscale device node payload."""

    id: str
    node_id: Optional[str] = Field(None, alias="nodeId")
    name: str
    hostname: str
    user: Optional[str] = None
    tailnet: Optional[str] = None
    os: str
    os_version: Optional[str] = Field(None, alias="osVersion")
    client_version: Optional[str] = Field(None, alias="clientVersion")
    addresses: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    exposed_routes: List[str] = Field(default_factory=list, alias="exposedRoutes")
    enabled_routes: List[str] = Field(default_factory=list, alias="enabledRoutes")
    authorized: bool = True
    is_external: bool = Field(False, alias="isExternal")
    machine_key: Optional[str] = Field(None, alias="machineKey")
    node_key: Optional[str] = Field(None, alias="nodeKey")
    key_expiry_disabled: bool = Field(False, alias="keyExpiryDisabled")
    expires: OptionalDatetime = None
    key_expiry: OptionalDatetime = Field(None, alias="keyExpiry")
    last_seen: OptionalDatetime = Field(None, alias="lastSeen")
    created: OptionalDatetime = None
    update_available: bool = Field(False, alias="updateAvailable")
    blocks_incoming_connections: bool = Field(False, alias="blocksIncomingConnections")
    online: Optional[bool] = None
    connected_to_control: Optional[bool] = Field(None, alias="connectedToControl")
    attributes: Dict[str, Any] = Field(default_factory=dict)
    client_connectivity: Optional[TailscaleClientConnectivity] = Field(
        None, alias="clientConnectivity"
    )
    posture_identity: Optional[TailscalePostureIdentity] = Field(
        None, alias="postureIdentity"
    )
    tailnet_lock_key: Optional[str] = Field(None, alias="tailnetLockKey")
    tailnet_lock_error: Optional[str] = Field(None, alias="tailnetLockError")
    locked_out: Optional[bool] = Field(None, alias="lockedOut")

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    @model_validator(mode="after")
    def sync_expiry_fields(self) -> Self:
        """Synchronizes expires and key_expiry (keyExpiry) fields, and tailnet lock error aliases."""
        if self.expires is None and self.key_expiry is not None:
            self.expires = self.key_expiry
        elif self.key_expiry is None and self.expires is not None:
            self.key_expiry = self.expires

        # Support tailnetLockErr or tailnet_lock_err alias if tailnet_lock_error is unset
        if self.tailnet_lock_error is None:
            raw_extra = getattr(self, "__pydantic_extra__", None) or {}
            for err_key in ("tailnetLockErr", "tailnet_lock_err", "tailnet_lock_error"):
                if err_key in raw_extra and raw_extra[err_key]:
                    self.tailnet_lock_error = str(raw_extra[err_key])
                    break
        return self

    @property
    def stable_id(self) -> str:
        """Returns the primary node identifier: nodeId if present, else id."""
        return self.node_id or self.id

    @property
    def derp_region(self) -> Optional[str]:
        """Returns the primary DERP region identifier."""
        if self.client_connectivity:
            return self.client_connectivity.derp
        return None

    @property
    def latency_ms(self) -> Optional[float]:
        """Returns DERP latency in milliseconds."""
        if self.client_connectivity:
            return self.client_connectivity.preferred_latency_ms
        return None

    @property
    def endpoints(self) -> List[str]:
        """Returns active network endpoints."""
        if self.client_connectivity:
            return self.client_connectivity.endpoints
        return []

    def get_exposed_routes(self) -> List[str]:
        """Extracts advertised/exposed CIDR routes from device attributes or top-level fields."""
        routes: List[str] = []
        if self.exposed_routes:
            for r in self.exposed_routes:
                if isinstance(r, str) and r.strip():
                    routes.append(r.strip())

        if not routes and self.attributes:
            for key in ("exposedroutes", "exposed_routes", "advertisedroutes", "advertised_routes", "routes"):
                for attr_k, attr_v in self.attributes.items():
                    if attr_k.lower().replace(":", "_") == key or attr_k.lower() == key:
                        if isinstance(attr_v, list):
                            for item in attr_v:
                                if isinstance(item, str) and item.strip():
                                    routes.append(item.strip())
                        elif isinstance(attr_v, str) and attr_v.strip():
                            for item in re.split(r"[, ]+", attr_v.strip()):
                                if item.strip():
                                    routes.append(item.strip())
                        break
                if routes:
                    break

        if not routes:
            for tag in self.tags:
                tag_lower = tag.lower()
                if tag_lower.startswith("route:") or tag_lower.startswith("exposed-route:"):
                    cidr = tag.split(":", 1)[1].strip()
                    if cidr:
                        routes.append(cidr)

        seen = set()
        deduped = []
        for r in routes:
            if r not in seen:
                seen.add(r)
                deduped.append(r)
        return deduped

    def get_enabled_routes(self) -> List[str]:
        """Extracts approved/enabled CIDR routes from top-level field or attributes."""
        routes: List[str] = []
        if self.enabled_routes:
            for r in self.enabled_routes:
                if isinstance(r, str) and r.strip():
                    routes.append(r.strip())
        if not routes and self.attributes:
            for key in ("enabledroutes", "enabled_routes"):
                for attr_k, attr_v in self.attributes.items():
                    if attr_k.lower().replace(":", "_") == key or attr_k.lower() == key:
                        if isinstance(attr_v, list):
                            for item in attr_v:
                                if isinstance(item, str) and item.strip():
                                    routes.append(item.strip())
                        elif isinstance(attr_v, str) and attr_v.strip():
                            for item in re.split(r"[, ]+", attr_v.strip()):
                                if item.strip():
                                    routes.append(item.strip())
                        break
                if routes:
                    break
        seen = set()
        deduped = []
        for r in routes:
            if r not in seen:
                seen.add(r)
                deduped.append(r)
        return deduped

    @property
    def has_exposed_routes(self) -> bool:
        """Indicates whether this device exposes/advertises any network routes."""
        return bool(self.get_exposed_routes())

    @property
    def is_advertising_exit_node(self) -> bool:
        """Indicates whether this device advertises default exit node route (0.0.0.0/0 or ::/0)."""
        return any(r in ("0.0.0.0/0", "::/0") for r in self.get_exposed_routes())

    def get_node_os_attribute(self) -> Optional[str]:
        """Extracts the 'node:os' attribute if present in attributes or posture tags."""
        if self.attributes:
            for k, v in self.attributes.items():
                if k.lower() in ("node:os", "node_os", "os") and v is not None:
                    return str(v).strip()
        for tag in self.tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("node:os:"):
                return tag.split("node:os:", 1)[1].strip()
        return None

    def get_node_ts_version_attribute(self) -> Optional[str]:
        """Extracts the 'node:tsVersion' posture attribute if present in attributes or tags."""
        if self.attributes:
            for k, v in self.attributes.items():
                if (
                    k.lower()
                    in (
                        "node:tsversion",
                        "node:ts_version",
                        "tsversion",
                        "ts_version",
                        "tailscale_version",
                    )
                    and v is not None
                ):
                    return str(v).strip()
        for tag in self.tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("node:tsversion:") or tag_lower.startswith("node:ts_version:"):
                return tag.split(":", 2)[-1].strip()
        if self.client_version:
            return self.client_version.strip()
        if self.client_connectivity and self.client_connectivity.client_version:
            if self.client_connectivity.client_version.running_version:
                return self.client_connectivity.client_version.running_version.strip()
        return None

    def get_node_auto_update_attribute(self) -> Optional[bool]:
        """Extracts the 'node:tsAutoUpdate' posture attribute."""
        if self.attributes:
            for k, v in self.attributes.items():
                k_norm = k.lower().replace(":", "_").replace("-", "_")
                if k_norm in (
                    "node_tsautoupdate",
                    "node_ts_auto_update",
                    "tsautoupdate",
                    "ts_auto_update",
                    "autoupdate",
                    "auto_update",
                ) and v is not None:
                    if isinstance(v, bool):
                        return v
                    cleaned = str(v).strip().lower()
                    if cleaned in ("true", "1", "yes", "enabled", "on"):
                        return True
                    if cleaned in ("false", "0", "no", "disabled", "off"):
                        return False

        for tag in self.tags:
            tag_lower = tag.lower().strip()
            if tag_lower.startswith("node:tsautoupdate:") or tag_lower.startswith("node:ts_auto_update:"):
                val_str = tag_lower.split(":", 2)[-1].strip()
                if val_str in ("true", "1", "yes", "enabled", "on"):
                    return True
                if val_str in ("false", "0", "no", "disabled", "off"):
                    return False
            elif tag_lower in ("tag:auto-update", "tag:autoupdate", "tag:auto-update-enabled"):
                return True
            elif tag_lower in ("tag:no-auto-update", "tag:auto-update-disabled"):
                return False

        return None

    def get_node_state_encrypted_attribute(self) -> Optional[bool]:
        """Extracts the 'node:tsStateEncrypted' posture attribute."""
        if self.attributes:
            for k, v in self.attributes.items():
                k_norm = k.lower().replace(":", "_").replace("-", "_")
                if k_norm in (
                    "node_tsstateencrypted",
                    "node_ts_state_encrypted",
                    "tsstateencrypted",
                    "ts_state_encrypted",
                    "stateencrypted",
                    "state_encrypted",
                    "disk_encrypted",
                    "disk_encryption",
                ) and v is not None:
                    if isinstance(v, bool):
                        return v
                    cleaned = str(v).strip().lower()
                    if cleaned in ("true", "1", "yes", "enabled", "on"):
                        return True
                    if cleaned in ("false", "0", "no", "disabled", "off"):
                        return False

        for tag in self.tags:
            tag_lower = tag.lower().strip()
            if tag_lower.startswith("node:tsstateencrypted:") or tag_lower.startswith("node:ts_state_encrypted:"):
                val_str = tag_lower.split(":", 2)[-1].strip()
                if val_str in ("true", "1", "yes", "enabled", "on"):
                    return True
                if val_str in ("false", "0", "no", "disabled", "off"):
                    return False
            elif tag_lower in ("tag:state-encrypted", "tag:disk-encrypted", "tag:encrypted-state"):
                return True
            elif tag_lower in ("tag:unencrypted-state", "tag:state-unencrypted", "tag:no-state-encryption"):
                return False

        return None

    def get_node_country_attribute(self) -> Optional[str]:
        """Extracts the 'ip:country' posture attribute from device attributes or tags."""
        if self.attributes:
            for k, v in self.attributes.items():
                k_norm = k.lower().replace(":", "_").replace("-", "_")
                if k_norm in (
                    "ip_country",
                    "ip_country_code",
                    "country",
                    "country_code",
                    "countrycode",
                ) and v is not None:
                    cleaned = str(v).strip()
                    if cleaned:
                        return cleaned.upper() if len(cleaned) == 2 else cleaned

        for tag in self.tags:
            tag_lower = tag.lower().strip()
            if (
                tag_lower.startswith("ip:country:")
                or tag_lower.startswith("country:")
                or tag_lower.startswith("tag:country:")
                or tag_lower.startswith("tag:ip:country:")
            ):
                val_str = tag.split(":", 2)[-1].strip()
                if val_str:
                    return val_str.upper() if len(val_str) == 2 else val_str

        return None

    def get_node_public_address_attribute(self) -> Optional[str]:
        """Extracts the 'ip:publicAddress' posture attribute from device attributes, tags, or endpoints."""
        if self.attributes:
            for k, v in self.attributes.items():
                k_norm = k.lower().replace(":", "_").replace("-", "_")
                if k_norm in (
                    "ip_publicaddress",
                    "ip_public_address",
                    "publicaddress",
                    "public_address",
                    "public_ip",
                    "publicip",
                ) and v is not None:
                    cleaned = str(v).strip()
                    if cleaned:
                        return cleaned

        for tag in self.tags:
            tag_lower = tag.lower().strip()
            if (
                tag_lower.startswith("ip:publicaddress:")
                or tag_lower.startswith("ip:public_address:")
                or tag_lower.startswith("public-ip:")
                or tag_lower.startswith("tag:public-ip:")
                or tag_lower.startswith("tag:ip:publicaddress:")
            ):
                val_str = tag.split(":", 2)[-1].strip()
                if val_str:
                    return val_str

        # Fallback to discovered client endpoints
        all_endpoints = list(self.endpoints)
        if self.client_connectivity and self.client_connectivity.endpoints:
            all_endpoints.extend(self.client_connectivity.endpoints)

        for ep in all_endpoints:
            if not isinstance(ep, str) or not ep.strip():
                continue
            ep_clean = ep.strip()
            raw_ip = ep_clean
            if ep_clean.startswith("[") and "]" in ep_clean:
                raw_ip = ep_clean[1 : ep_clean.index("]")]
            elif ":" in ep_clean:
                raw_ip = ep_clean.split(":", 1)[0]
            try:
                ip_obj = ipaddress.ip_address(raw_ip)
                if not is_internal_ip(ip_obj):
                    return str(ip_obj)
            except ValueError:
                continue

        return None

    def get_tailnet_lock_key(self) -> Optional[str]:
        """Extracts the Tailnet Lock public key (nlpub:... or tlpub:...) from fields, attributes, or tags."""
        if self.tailnet_lock_key and self.tailnet_lock_key.strip():
            return self.tailnet_lock_key.strip()
        if self.attributes:
            for k, v in self.attributes.items():
                k_norm = k.lower().replace(":", "_").replace("-", "_")
                if k_norm in (
                    "tailnetlockkey",
                    "tailnet_lock_key",
                    "node_tailnetlockkey",
                    "node_tailnet_lock_key",
                    "tailnet_lock_public_key",
                    "lock_key",
                    "tlpub",
                    "nlpub",
                ) and v is not None:
                    cleaned = str(v).strip()
                    if cleaned:
                        return cleaned
        for tag in self.tags:
            tag_clean = tag.strip()
            tag_lower = tag_clean.lower()
            if tag_lower.startswith("nlpub:") or tag_lower.startswith("tlpub:"):
                return tag_clean
            if tag_lower.startswith("node:tailnetlockkey:") or tag_lower.startswith("node:tailnet_lock_key:"):
                return tag_clean.split(":", 2)[-1].strip()
            if tag_lower.startswith("tag:tailnet-lock-key:") or tag_lower.startswith("tag:lock-key:"):
                return tag_clean.split(":", 2)[-1].strip()
        return None

    def get_tailnet_lock_error(self) -> Optional[str]:
        """Extracts the Tailnet Lock error string if the node failed signature verification or is locked out."""
        if self.tailnet_lock_error and self.tailnet_lock_error.strip():
            return self.tailnet_lock_error.strip()
        if self.attributes:
            for k, v in self.attributes.items():
                k_norm = k.lower().replace(":", "_").replace("-", "_")
                if k_norm in (
                    "tailnetlockerror",
                    "tailnetlockerr",
                    "tailnet_lock_error",
                    "tailnet_lock_err",
                    "node_tailnetlockerror",
                    "node_tailnet_lock_error",
                    "lock_error",
                    "lock_err",
                ) and v is not None:
                    cleaned = str(v).strip()
                    if cleaned:
                        return cleaned
        for tag in self.tags:
            tag_clean = tag.strip()
            tag_lower = tag_clean.lower()
            if tag_lower.startswith("tag:tailnet-lock-error:") or tag_lower.startswith("tag:lock-error:"):
                return tag_clean.split(":", 2)[-1].strip()
            if tag_lower.startswith("node:tailnetlockerror:") or tag_lower.startswith("node:tailnet_lock_error:"):
                return tag_clean.split(":", 2)[-1].strip()
        return None

    def is_locked_out_status(self) -> bool:
        """Determines if the node is locked out by Tailnet Lock."""
        err = self.get_tailnet_lock_error()
        if err:
            return True
        if self.locked_out is not None:
            return bool(self.locked_out)
        if self.attributes:
            for k, v in self.attributes.items():
                k_norm = k.lower().replace(":", "_").replace("-", "_")
                if k_norm in (
                    "lockedout",
                    "locked_out",
                    "islockedout",
                    "is_locked_out",
                    "node_lockedout",
                    "node_locked_out",
                    "quarantined",
                    "is_quarantined",
                ) and v is not None:
                    if isinstance(v, bool):
                        return v
                    if str(v).strip().lower() in ("true", "1", "yes"):
                        return True
        for tag in self.tags:
            tag_lower = tag.strip().lower()
            if tag_lower in (
                "tag:locked-out",
                "tag:lockedout",
                "tag:quarantined",
                "tag:tailnet-lock-quarantined",
                "tag:lock-quarantined",
                "node:lockedout",
                "node:locked-out",
            ):
                return True
        return False

    def is_quarantined_status(self) -> bool:
        """Determines if the node is quarantined."""
        if self.is_locked_out_status():
            return True
        for tag in self.tags:
            tag_lower = tag.strip().lower()
            if "quarantine" in tag_lower:
                return True
        if self.attributes:
            for k, v in self.attributes.items():
                if "quarantine" in k.lower():
                    if v is True or str(v).lower() in ("true", "1", "yes"):
                        return True
        return False

    def is_signing_node_status(self) -> bool:
        """Determines if the node is a designated Tailnet Lock signing node."""
        if self.attributes:
            for k, v in self.attributes.items():
                k_norm = k.lower().replace(":", "_").replace("-", "_")
                if k_norm in (
                    "is_signing_node",
                    "issigningnode",
                    "signing_node",
                    "tailnet_lock_signer",
                    "lock_signer",
                ) and v is not None:
                    if isinstance(v, bool):
                        return v
                    if str(v).strip().lower() in ("true", "1", "yes"):
                        return True
        for tag in self.tags:
            tag_lower = tag.strip().lower()
            if tag_lower in (
                "tag:tailnet-lock-signer",
                "tag:lock-signer",
                "tag:signing-node",
                "tag:signer",
            ):
                return True
        return False

    def is_unsigned_status(self) -> bool:
        """Determines if the node is unsigned under Tailnet Lock."""
        err = self.get_tailnet_lock_error()
        if err:
            err_lower = err.lower()
            if any(term in err_lower for term in ("unsigned", "missing signature", "signature missing", "not signed", "no signature")):
                return True
        if self.attributes:
            for k, v in self.attributes.items():
                k_norm = k.lower().replace(":", "_").replace("-", "_")
                if k_norm in ("unsigned", "is_unsigned", "not_signed") and v is not None:
                    if isinstance(v, bool):
                        return v
                    if str(v).strip().lower() in ("true", "1", "yes"):
                        return True
        for tag in self.tags:
            tag_lower = tag.strip().lower()
            if tag_lower in (
                "tag:unsigned",
                "tag:tailnet-lock-unsigned",
                "tag:not-signed",
                "tag:lock-unsigned",
            ):
                return True
        return False

    def check_is_online(self, threshold_seconds: int = 300) -> bool:
        """Determines online status based on explicit flags or last_seen recency (default: 5 minutes)."""
        if self.online is not None:
            return bool(self.online)
        if self.connected_to_control is not None:
            return bool(self.connected_to_control)
        if self.last_seen is None:
            return False
        now = datetime.now(timezone.utc)
        last = self.last_seen if self.last_seen.tzinfo else self.last_seen.replace(tzinfo=timezone.utc)
        delta = (now - last).total_seconds()
        return 0 <= delta <= threshold_seconds

    def to_node_dict(self, tailnet_override: Optional[str] = None) -> Dict[str, Any]:
        """Converts this device payload into a dict matching the Node SQLAlchemy model."""
        ts_ver = self.get_node_ts_version_attribute() or self.client_version
        ts_auto_update = self.get_node_auto_update_attribute()
        ts_state_encrypted = self.get_node_state_encrypted_attribute()
        country = self.get_node_country_attribute()
        public_addr = self.get_node_public_address_attribute()
        lock_key = self.get_tailnet_lock_key()
        lock_err = self.get_tailnet_lock_error()
        is_locked_out = self.is_locked_out_status()
        is_quarantined = self.is_quarantined_status()
        is_signing = self.is_signing_node_status()
        is_unsigned = self.is_unsigned_status()
        expiry_dt = self.expires or self.key_expiry
        exposed_rts = self.get_exposed_routes()
        enabled_rts = self.get_enabled_routes()
        return {
            "id": self.id,
            "node_id": self.node_id or self.id,
            "name": self.name,
            "hostname": self.hostname,
            "user": self.user,
            "tailnet": tailnet_override or self.tailnet,
            "os": self.os,
            "os_version": self.os_version,
            "client_version": ts_ver,
            "addresses": self.addresses,
            "tags": self.tags,
            "endpoints": self.endpoints,
            "is_online": self.check_is_online(),
            "last_seen": self.last_seen,
            "machine_key": self.machine_key,
            "node_key": self.node_key,
            "is_external": self.is_external,
            "authorized": self.authorized,
            "key_expiry_disabled": self.key_expiry_disabled,
            "expires_at": expiry_dt,
            "update_available": self.update_available,
            "telemetry_metadata": {
                "node_ts_version": ts_ver,
                "ts_auto_update": ts_auto_update,
                "ts_state_encrypted": ts_state_encrypted,
                "country": country,
                "public_address": public_addr,
                "tailnet_lock_key": lock_key,
                "tailnet_lock_error": lock_err,
                "is_locked_out": is_locked_out,
                "is_quarantined": is_quarantined,
                "is_signing_node": is_signing,
                "is_unsigned": is_unsigned,
                "exposed_routes": exposed_rts,
                "enabled_routes": enabled_rts,
                "is_exit_node": any(r in ("0.0.0.0/0", "::/0") for r in exposed_rts),
                "blocks_incoming_connections": self.blocks_incoming_connections,
                "client_connectivity": self.client_connectivity.model_dump()
                if self.client_connectivity
                else {},
                "posture_identity": self.posture_identity.model_dump()
                if self.posture_identity
                else {},
            },
        }

    def to_node_state_dict(
        self,
        node_id_override: Optional[str] = None,
        firewall_enabled: Optional[bool] = None,
        disk_encryption_enabled: Optional[bool] = None,
        screen_lock_enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Extracts initial posture and telemetry snapshot dict matching NodeState SQLAlchemy model."""
        is_online = self.check_is_online()
        expiry_dt = self.expires or self.key_expiry
        key_expired = False
        if expiry_dt and not self.key_expiry_disabled:
            now = datetime.now(timezone.utc)
            exp = expiry_dt if expiry_dt.tzinfo else expiry_dt.replace(tzinfo=timezone.utc)
            key_expired = exp < now

        ts_ver = self.get_node_ts_version_attribute() or self.client_version
        ts_auto_update = self.get_node_auto_update_attribute()
        ts_state_encrypted = self.get_node_state_encrypted_attribute()
        country = self.get_node_country_attribute()
        public_addr = self.get_node_public_address_attribute()
        effective_disk_encryption = (
            disk_encryption_enabled
            if disk_encryption_enabled is not None
            else ts_state_encrypted
        )
        exposed_rts = self.get_exposed_routes()
        enabled_rts = self.get_enabled_routes()

        return {
            "node_id": node_id_override or self.id,
            "is_online": is_online,
            "is_compliant": not key_expired,
            "compliance_status": "non_compliant" if key_expired else "compliant",
            "firewall_enabled": firewall_enabled,
            "disk_encryption_enabled": effective_disk_encryption,
            "screen_lock_enabled": screen_lock_enabled,
            "key_expired": key_expired,
            "os_version": self.os_version,
            "client_version": ts_ver,
            "latency_ms": self.latency_ms,
            "derp_region": self.derp_region,
            "posture_checks": {
                "node_ts_version": ts_ver,
                "ts_auto_update": ts_auto_update,
                "ts_state_encrypted": ts_state_encrypted,
                "ip:country": country,
                "ip:publicAddress": public_addr,
                "country": country,
                "public_address": public_addr,
                "tailnet_lock_key": self.get_tailnet_lock_key(),
                "tailnet_lock_error": self.get_tailnet_lock_error(),
                "is_locked_out": self.is_locked_out_status(),
                "is_quarantined": self.is_quarantined_status(),
                "is_signing_node": self.is_signing_node_status(),
                "is_unsigned": self.is_unsigned_status(),
                "key_expired": key_expired,
                "key_expiry_disabled": self.key_expiry_disabled,
                "key_expiry": expiry_dt.isoformat() if expiry_dt else None,
                "authorized": self.authorized,
                "update_available": self.update_available,
                "exposed_routes": exposed_rts,
                "is_exit_node": any(r in ("0.0.0.0/0", "::/0") for r in exposed_rts),
            },
            "telemetry_data": {
                "endpoints": self.endpoints,
                "derp_region": self.derp_region,
                "latency_ms": self.latency_ms,
                "node_ts_version": ts_ver,
                "ts_auto_update": ts_auto_update,
                "ts_state_encrypted": ts_state_encrypted,
                "country": country,
                "public_address": public_addr,
                "tailnet_lock_key": self.get_tailnet_lock_key(),
                "tailnet_lock_error": self.get_tailnet_lock_error(),
                "is_locked_out": self.is_locked_out_status(),
                "is_quarantined": self.is_quarantined_status(),
                "is_signing_node": self.is_signing_node_status(),
                "is_unsigned": self.is_unsigned_status(),
                "exposed_routes": exposed_rts,
                "enabled_routes": enabled_rts,
            },
        }


class TailscaleDevicesResponse(BaseModel):
    """Container schema for Tailscale devices list endpoint response."""

    devices: List[TailscaleDevice] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    def __iter__(self):
        return iter(self.devices)

    def __len__(self) -> int:
        return len(self.devices)

    def __getitem__(self, index: int) -> TailscaleDevice:
        return self.devices[index]