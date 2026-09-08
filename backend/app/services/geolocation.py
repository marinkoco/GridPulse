from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import logging
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.audit_log import AuditLog
from app.models.enums import (
    AuditSeverity,
    AuditEventType,
    ComplianceStatus,
    EventCategory,
)
from app.models.node import Node
from app.models.node_state import NodeState
from app.schemas.tailscale import TailscaleDevice, is_internal_ip

logger = logging.getLogger(__name__)

# Standardized Posture Attribute Keys in Tailscale
POSTURE_IP_COUNTRY_ATTR: str = "ip:country"
POSTURE_IP_PUBLIC_ADDRESS_ATTR: str = "ip:publicAddress"

# Physical and Travel Heuristics Defaults
DEFAULT_MAX_TRAVEL_SPEED_KMH: float = 800.0  # Commercial flight cruising speed ~800-900 km/h
DEFAULT_MIN_DISTANCE_KM: float = 100.0       # Minimum distance to disregard local IP/ISP reallocations
DEFAULT_MIN_TIME_SECONDS: float = 60.0       # 1 minute threshold for simultaneous session detection

# Comprehensive ISO 3166-1 alpha-2 Country Coordinates & Centroids (lat, lon, country_name)
COUNTRY_COORDINATES: Dict[str, Tuple[float, float, str]] = {
    "AD": (42.5462, 1.6016, "Andorra"),
    "AE": (23.4241, 53.8478, "United Arab Emirates"),
    "AF": (33.9391, 67.7100, "Afghanistan"),
    "AG": (17.0608, -61.7964, "Antigua and Barbuda"),
    "AL": (41.1533, 20.1683, "Albania"),
    "AM": (40.0691, 45.0382, "Armenia"),
    "AO": (-11.2027, 17.8739, "Angola"),
    "AR": (-38.4161, -63.6167, "Argentina"),
    "AT": (47.5162, 14.5501, "Austria"),
    "AU": (-25.2744, 133.7751, "Australia"),
    "AZ": (40.1431, 47.5769, "Azerbaijan"),
    "BA": (43.9159, 17.6791, "Bosnia and Herzegovina"),
    "BB": (13.1939, -59.5432, "Barbados"),
    "BD": (23.6850, 90.3563, "Bangladesh"),
    "BE": (50.5039, 4.4699, "Belgium"),
    "BF": (12.2383, -1.5616, "Burkina Faso"),
    "BG": (42.7339, 25.4858, "Bulgaria"),
    "BH": (26.0667, 50.5577, "Bahrain"),
    "BN": (4.5353, 114.7277, "Brunei"),
    "BO": (-16.2902, -63.5887, "Bolivia"),
    "BR": (-14.2350, -51.9253, "Brazil"),
    "BS": (25.0343, -77.3963, "Bahamas"),
    "BW": (-22.3285, 24.6849, "Botswana"),
    "BY": (53.7098, 27.9534, "Belarus"),
    "BZ": (17.1899, -88.4976, "Belize"),
    "CA": (56.1304, -106.3468, "Canada"),
    "CD": (-4.0383, 21.7587, "Democratic Republic of the Congo"),
    "CH": (46.8182, 8.2275, "Switzerland"),
    "CL": (-35.6751, -71.5430, "Chile"),
    "CM": (7.3697, 12.3547, "Cameroon"),
    "CN": (35.8617, 104.1954, "China"),
    "CO": (4.5709, -74.2973, "Colombia"),
    "CR": (9.7489, -83.7534, "Costa Rica"),
    "CU": (21.5218, -77.7812, "Cuba"),
    "CY": (35.1264, 33.4299, "Cyprus"),
    "CZ": (49.8175, 15.4730, "Czech Republic"),
    "DE": (51.1657, 10.4515, "Germany"),
    "DK": (56.2639, 9.5018, "Denmark"),
    "DO": (18.7357, -70.1627, "Dominican Republic"),
    "DZ": (28.0339, 1.6596, "Algeria"),
    "EC": (-1.8312, -78.1834, "Ecuador"),
    "EE": (58.5953, 25.0136, "Estonia"),
    "EG": (26.8206, 30.8025, "Egypt"),
    "ES": (40.4637, -3.7492, "Spain"),
    "ET": (9.1450, 40.4897, "Ethiopia"),
    "FI": (61.9241, 25.7482, "Finland"),
    "FR": (46.2276, 2.2137, "France"),
    "GB": (55.3781, -3.4360, "United Kingdom"),
    "GE": (42.3154, 43.3569, "Georgia"),
    "GH": (7.9465, -1.0232, "Ghana"),
    "GR": (39.0742, 21.8243, "Greece"),
    "GT": (15.7835, -90.2308, "Guatemala"),
    "HK": (22.3193, 114.1694, "Hong Kong"),
    "HR": (45.1000, 15.2000, "Croatia"),
    "HU": (47.1625, 19.5033, "Hungary"),
    "ID": (-0.7893, 113.9213, "Indonesia"),
    "IE": (53.1424, -7.6921, "Ireland"),
    "IL": (31.0461, 34.8516, "Israel"),
    "IN": (20.5937, 78.9629, "India"),
    "IQ": (33.2232, 43.6793, "Iraq"),
    "IR": (32.4279, 53.6880, "Iran"),
    "IS": (64.9631, -19.0208, "Iceland"),
    "IT": (41.8719, 12.5674, "Italy"),
    "JM": (18.1096, -77.2975, "Jamaica"),
    "JO": (30.5852, 36.2384, "Jordan"),
    "JP": (36.2048, 138.2529, "Japan"),
    "KE": (-0.0236, 37.9062, "Kenya"),
    "KR": (35.9078, 127.7669, "South Korea"),
    "KW": (29.3117, 47.4818, "Kuwait"),
    "KZ": (48.0196, 66.9237, "Kazakhstan"),
    "LB": (33.8547, 35.8623, "Lebanon"),
    "LK": (7.8731, 80.7718, "Sri Lanka"),
    "LT": (55.1694, 23.8813, "Lithuania"),
    "LU": (49.8153, 6.1296, "Luxembourg"),
    "LV": (56.8796, 24.6032, "Latvia"),
    "MA": (31.7917, -7.0926, "Morocco"),
    "MC": (43.7384, 7.4246, "Monaco"),
    "MD": (47.4116, 28.3699, "Moldova"),
    "ME": (42.7087, 19.3744, "Montenegro"),
    "MK": (41.6086, 21.7453, "North Macedonia"),
    "MT": (35.9375, 14.3754, "Malta"),
    "MX": (23.6345, -102.5528, "Mexico"),
    "MY": (4.2105, 101.9758, "Malaysia"),
    "NG": (9.0820, 8.6753, "Nigeria"),
    "NL": (52.1326, 5.2913, "Netherlands"),
    "NO": (60.4720, 8.4689, "Norway"),
    "NZ": (-40.9006, 174.8860, "New Zealand"),
    "OM": (21.5126, 55.9233, "Oman"),
    "PA": (8.5379, -80.7821, "Panama"),
    "PE": (-9.1900, -75.0152, "Peru"),
    "PH": (12.8797, 121.7740, "Philippines"),
    "PK": (30.3753, 69.3451, "Pakistan"),
    "PL": (51.9194, 19.1451, "Poland"),
    "PR": (18.2208, -66.5901, "Puerto Rico"),
    "PT": (39.3999, -8.2245, "Portugal"),
    "QA": (25.3548, 51.1839, "Qatar"),
    "RO": (45.9432, 24.9668, "Romania"),
    "RS": (44.0165, 21.0059, "Serbia"),
    "RU": (61.5240, 105.3188, "Russia"),
    "SA": (23.8859, 45.0792, "Saudi Arabia"),
    "SE": (60.1282, 18.6435, "Sweden"),
    "SG": (1.3521, 103.8198, "Singapore"),
    "SI": (46.1512, 14.9955, "Slovenia"),
    "SK": (48.6690, 19.6990, "Slovakia"),
    "TH": (15.8700, 100.9925, "Thailand"),
    "TR": (38.9637, 35.2433, "Turkey"),
    "TW": (23.6978, 120.9605, "Taiwan"),
    "UA": (48.3794, 31.1656, "Ukraine"),
    "US": (37.0902, -95.7129, "United States"),
    "UY": (-32.5228, -55.7658, "Uruguay"),
    "VE": (6.4238, -66.5897, "Venezuela"),
    "VN": (14.0583, 108.2772, "Vietnam"),
    "ZA": (-30.5595, 22.9375, "South Africa"),
}

# Common Country Name and Alpha-3 Aliases normalized to Alpha-2
COUNTRY_NAME_ALIASES: Dict[str, str] = {
    "usa": "US",
    "united states": "US",
    "united states of america": "US",
    "us": "US",
    "uk": "GB",
    "gbr": "GB",
    "united kingdom": "GB",
    "great britain": "GB",
    "deu": "DE",
    "germany": "DE",
    "deutschland": "DE",
    "fra": "FR",
    "france": "FR",
    "can": "CA",
    "canada": "CA",
    "jpn": "JP",
    "japan": "JP",
    "aus": "AU",
    "australia": "AU",
    "sgp": "SG",
    "singapore": "SG",
    "nld": "NL",
    "netherlands": "NL",
    "holland": "NL",
    "che": "CH",
    "switzerland": "CH",
    "swe": "SE",
    "sweden": "SE",
    "nor": "NO",
    "norway": "NO",
    "fin": "FI",
    "finland": "FI",
    "dnk": "DK",
    "denmark": "DK",
    "irl": "IE",
    "ireland": "IE",
    "esp": "ES",
    "spain": "ES",
    "ita": "IT",
    "italy": "IT",
    "pol": "PL",
    "poland": "PL",
    "bra": "BR",
    "brazil": "BR",
    "ind": "IN",
    "india": "IN",
    "chn": "CN",
    "china": "CN",
    "kor": "KR",
    "korea": "KR",
    "south korea": "KR",
    "nzl": "NZ",
    "new zealand": "NZ",
    "zaf": "ZA",
    "south africa": "ZA",
    "mex": "MX",
    "mexico": "MX",
    "arg": "AR",
    "argentina": "AR",
    "chl": "CL",
    "chile": "CL",
    "isr": "IL",
    "israel": "IL",
    "are": "AE",
    "uae": "AE",
    "sau": "SA",
    "saudi arabia": "SA",
    "tur": "TR",
    "turkey": "TR",
    "türkiye": "TR",
    "ukr": "UA",
    "ukraine": "UA",
    "rus": "RU",
    "russia": "RU",
}


def normalize_country_code(raw_country: Optional[str]) -> Optional[str]:
    """Normalizes country names, alpha-3 codes, or raw strings to canonical ISO 3166-1 alpha-2 uppercase code.

    Examples:
        - 'US' -> 'US'
        - 'us' -> 'US'
        - 'USA' -> 'US'
        - 'United States' -> 'US'
        - 'Germany' -> 'DE'
        - 'de' -> 'DE'
        - None -> None

    Args:
        raw_country: Raw country string from attributes or posture tags.

    Returns:
        Canonical 2-letter uppercase country code, or cleaned uppercase string if not in alias map.
    """
    if not raw_country:
        return None
    cleaned = str(raw_country).strip()
    if not cleaned:
        return None

    # Check exact match in COUNTRY_COORDINATES
    upper = cleaned.upper()
    if upper in COUNTRY_COORDINATES:
        return upper

    # Check case-insensitive alias map
    lower = cleaned.lower()
    if lower in COUNTRY_NAME_ALIASES:
        return COUNTRY_NAME_ALIASES[lower]

    if len(cleaned) == 2 and cleaned.isalpha():
        return upper

    return cleaned


def get_country_coordinates(country_str: Optional[str]) -> Optional[Tuple[float, float, str]]:
    """Retrieves approximate latitude, longitude centroid, and standard country name.

    Args:
        country_str: ISO-2 code, ISO-3 code, or country name.

    Returns:
        Tuple of (latitude, longitude, country_name) or None if country is unrecognized.
    """
    code = normalize_country_code(country_str)
    if not code:
        return None
    return COUNTRY_COORDINATES.get(code)


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates the great-circle distance between two points on the Earth in kilometers using the Haversine formula.

    Args:
        lat1: Latitude of point 1 in degrees.
        lon1: Longitude of point 1 in degrees.
        lat2: Latitude of point 2 in degrees.
        lon2: Longitude of point 2 in degrees.

    Returns:
        Distance in kilometers (rounded to 2 decimal places).
    """
    earth_radius_km = 6371.0088

    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    distance = earth_radius_km * c
    return round(distance, 2)


def calculate_travel_speed(distance_km: float, time_seconds: float) -> float:
    """Calculates travel speed in kilometers per hour given distance and elapsed time.

    Args:
        distance_km: Great circle distance in km.
        time_seconds: Elapsed duration in seconds.

    Returns:
        Speed in km/h. Returns infinity if elapsed time is zero or negative with positive distance.
    """
    if time_seconds <= 0:
        return float("inf") if distance_km > 0 else 0.0
    hours = time_seconds / 3600.0
    speed = distance_km / hours
    return round(speed, 2)


def format_time_delta_human(seconds: float) -> str:
    """Formats an elapsed time duration into a concise human-readable string."""
    secs = max(0.0, float(seconds))
    if secs < 60:
        return f"{int(secs)}s"
    mins = secs / 60.0
    if mins < 60:
        return f"{int(mins)}m {int(secs % 60)}s"
    hours = mins / 60.0
    if hours < 24:
        return f"{int(hours)}h {int(mins % 60)}m"
    days = hours / 24.0
    return f"{int(days)}d {int(hours % 24)}h"


def parse_node_country(device: TailscaleDevice) -> Optional[str]:
    """Extracts and normalizes the 'ip:country' posture attribute from a TailscaleDevice.

    Checks:
    1. device.get_node_country_attribute() method on schema.
    2. device.attributes for matching keys ('ip:country', 'ip_country', 'country', 'countryCode', etc.).
    3. device.tags for 'ip:country:<val>', 'country:<val>', 'tag:country:<val>'.

    Args:
        device: Validated TailscaleDevice model.

    Returns:
        Normalized 2-letter uppercase country code or string, or None if unknown.
    """
    if hasattr(device, "get_node_country_attribute"):
        val = device.get_node_country_attribute()
        if val:
            return normalize_country_code(val)

    if device.attributes:
        for k, v in device.attributes.items():
            k_norm = k.lower().replace(":", "_").replace("-", "_")
            if k_norm in (
                "ip_country",
                "ip_country_code",
                "country",
                "country_code",
                "countrycode",
            ) and v is not None:
                norm = normalize_country_code(str(v))
                if norm:
                    return norm

    for tag in device.tags:
        tag_lower = tag.lower().strip()
        if (
            tag_lower.startswith("ip:country:")
            or tag_lower.startswith("country:")
            or tag_lower.startswith("tag:country:")
            or tag_lower.startswith("tag:ip:country:")
        ):
            val_str = tag.split(":", 2)[-1].strip()
            norm = normalize_country_code(val_str)
            if norm:
                return norm

    return None


def parse_node_public_address(device: TailscaleDevice) -> Optional[str]:
    """Extracts the 'ip:publicAddress' posture attribute from a TailscaleDevice.

    Checks:
    1. device.get_node_public_address_attribute() method on schema.
    2. device.attributes for matching keys ('ip:publicAddress', 'ip_public_address', 'publicAddress', etc.).
    3. device.tags for 'ip:publicaddress:<val>', 'ip:public_address:<val>', 'public-ip:<val>'.
    4. Discovered network endpoints on device or client_connectivity, extracting IP without port.

    Args:
        device: Validated TailscaleDevice model.

    Returns:
        Public IP address string, or None if not reported.
    """
    if hasattr(device, "get_node_public_address_attribute"):
        val = device.get_node_public_address_attribute()
        if val:
            return val

    if device.attributes:
        for k, v in device.attributes.items():
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

    for tag in device.tags:
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

    # Fallback to endpoints
    all_endpoints = list(device.endpoints or [])
    if device.client_connectivity and device.client_connectivity.endpoints:
        all_endpoints.extend(device.client_connectivity.endpoints)

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


def create_location_snapshot(
    country: Optional[str],
    public_address: Optional[str],
    timestamp: datetime,
) -> Dict[str, Any]:
    """Creates a structured geolocation snapshot dictionary.

    Args:
        country: ISO country code or string.
        public_address: Public IP address.
        timestamp: Evaluation timestamp.

    Returns:
        Structured location snapshot.
    """
    coords = get_country_coordinates(country)
    return {
        "country": country,
        "country_name": coords[2] if coords else country,
        "public_address": public_address,
        "latitude": coords[0] if coords else None,
        "longitude": coords[1] if coords else None,
        "recorded_at": (
            timestamp.isoformat()
            if hasattr(timestamp, "isoformat")
            else str(timestamp)
        ),
    }


def detect_impossible_travel(
    current_loc: Dict[str, Any],
    previous_loc: Dict[str, Any],
    max_speed_kmh: float = DEFAULT_MAX_TRAVEL_SPEED_KMH,
    min_distance_km: float = DEFAULT_MIN_DISTANCE_KM,
    min_time_seconds: float = DEFAULT_MIN_TIME_SECONDS,
) -> Dict[str, Any]:
    """Evaluates two location observations to detect impossible physical travel anomalies.

    An impossible travel anomaly is triggered when:
    1. Distance between observations exceeds `min_distance_km`, AND the speed required
       to cover that distance exceeds `max_speed_kmh` (e.g. supersonic or flight > 800 km/h).
    2. Different countries are reported within an impossibly short time window (< `min_time_seconds`
       or under typical commercial flight limits), indicating concurrent multi-location access or proxy hopping.

    Args:
        current_loc: Current location snapshot with country, public_address, coords, and recorded_at.
        previous_loc: Previous location snapshot.
        max_speed_kmh: Maximum realistic travel speed threshold in km/h.
        min_distance_km: Minimum distance threshold in km.
        min_time_seconds: Minimum time threshold in seconds.

    Returns:
        Dictionary detailing whether impossible travel occurred, distance, time delta, speed, and reason.
    """
    if not previous_loc or not current_loc:
        return {
            "is_impossible_travel": False,
            "distance_km": 0.0,
            "time_delta_seconds": 0.0,
            "time_delta_human": "0s",
            "speed_kmh": 0.0,
            "threshold_speed_kmh": max_speed_kmh,
            "reason": None,
            "severity": "none",
        }

    curr_country = current_loc.get("country")
    prev_country = previous_loc.get("country")
    curr_ip = current_loc.get("public_address")
    prev_ip = previous_loc.get("public_address")

    # If both country and IP are identical, no physical movement occurred
    if curr_country == prev_country and curr_ip == prev_ip:
        return {
            "is_impossible_travel": False,
            "distance_km": 0.0,
            "time_delta_seconds": 0.0,
            "time_delta_human": "0s",
            "speed_kmh": 0.0,
            "threshold_speed_kmh": max_speed_kmh,
            "reason": None,
            "severity": "none",
        }

    # Parse timestamps and compute elapsed duration
    curr_ts_raw = current_loc.get("recorded_at")
    prev_ts_raw = previous_loc.get("recorded_at")

    delta_seconds = 0.0
    if curr_ts_raw and prev_ts_raw:
        try:
            curr_dt = (
                datetime.fromisoformat(curr_ts_raw)
                if isinstance(curr_ts_raw, str)
                else curr_ts_raw
            )
            prev_dt = (
                datetime.fromisoformat(prev_ts_raw)
                if isinstance(prev_ts_raw, str)
                else prev_ts_raw
            )
            if curr_dt.tzinfo is None:
                curr_dt = curr_dt.replace(tzinfo=timezone.utc)
            if prev_dt.tzinfo is None:
                prev_dt = prev_dt.replace(tzinfo=timezone.utc)
            delta_seconds = max(0.0, (curr_dt - prev_dt).total_seconds())
        except Exception as e:
            logger.warning("Failed to parse timestamps for travel analysis: %s", e)
            delta_seconds = 0.0

    # Determine coordinates
    lat1 = previous_loc.get("latitude")
    lon1 = previous_loc.get("longitude")
    lat2 = current_loc.get("latitude")
    lon2 = current_loc.get("longitude")

    distance_km = 0.0
    has_coords = (
        lat1 is not None
        and lon1 is not None
        and lat2 is not None
        and lon2 is not None
    )

    if has_coords:
        distance_km = haversine_distance(float(lat1), float(lon1), float(lat2), float(lon2))
    elif curr_country and prev_country and curr_country != prev_country:
        # Fallback distance between different countries if centroid coordinates are missing
        distance_km = 500.0

    # Calculate travel speed
    speed_kmh = calculate_travel_speed(distance_km, delta_seconds)
    time_human = format_time_delta_human(delta_seconds)

    is_impossible = False
    reason: Optional[str] = None
    severity = "none"

    curr_cname = current_loc.get("country_name") or curr_country or "Unknown"
    prev_cname = previous_loc.get("country_name") or prev_country or "Unknown"

    # Evaluation Rule 1: High speed exceeding threshold
    if distance_km >= min_distance_km and speed_kmh > max_speed_kmh:
        is_impossible = True
        severity = AuditSeverity.CRITICAL.value
        reason = (
            f"Relocated from {prev_cname} to {curr_cname} covering {distance_km:.1f} km "
            f"in {time_human}, requiring an impossible speed of {speed_kmh:.1f} km/h "
            f"(threshold: {max_speed_kmh:.1f} km/h)."
        )

    # Evaluation Rule 2: Country change in near-instant duration (< min_time_seconds)
    elif curr_country and prev_country and curr_country != prev_country and delta_seconds < min_time_seconds:
        is_impossible = True
        severity = AuditSeverity.CRITICAL.value
        reason = (
            f"Instantaneous country transition from {prev_cname} to {curr_cname} "
            f"within {time_human} (< {int(min_time_seconds)}s threshold)."
        )

    return {
        "is_impossible_travel": is_impossible,
        "distance_km": distance_km,
        "time_delta_seconds": delta_seconds,
        "time_delta_human": time_human,
        "speed_kmh": speed_kmh,
        "threshold_speed_kmh": max_speed_kmh,
        "reason": reason,
        "severity": severity,
    }


def audit_node_geolocation(
    device: TailscaleDevice,
    existing_node: Optional[Node] = None,
    max_speed_kmh: Optional[float] = None,
    min_distance_km: Optional[float] = None,
    min_time_seconds: Optional[float] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Audits posture attributes `ip:country` and `ip:publicAddress` to track location and detect impossible travel.

    Extracts:
    1. `ip:country`: Device ISO-2 country code or country name.
    2. `ip:publicAddress`: Device public IP address.
    3. Evaluates geographic distance and velocity against prior telemetry to detect impossible travel events.
    4. Tracks state transitions and maintains historical location trail in node metadata.

    Args:
        device: Newly polled TailscaleDevice payload.
        existing_node: Optional existing Node ORM record for diffing.
        max_speed_kmh: Maximum allowed travel speed in km/h.
        min_distance_km: Minimum distance threshold in km.
        min_time_seconds: Minimum time threshold for instant country jump in seconds.
        now: Reference evaluation datetime.

    Returns:
        Structured geolocation report containing current location, analysis, violations, and alerts.
    """
    eval_now = now or datetime.now(timezone.utc)
    speed_threshold = (
        max_speed_kmh
        if max_speed_kmh is not None
        else getattr(settings, "IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD_KMH", DEFAULT_MAX_TRAVEL_SPEED_KMH)
    )
    dist_threshold = (
        min_distance_km
        if min_distance_km is not None
        else getattr(settings, "IMPOSSIBLE_TRAVEL_MIN_DISTANCE_KM", DEFAULT_MIN_DISTANCE_KM)
    )
    time_threshold = (
        min_time_seconds
        if min_time_seconds is not None
        else getattr(settings, "IMPOSSIBLE_TRAVEL_MIN_TIME_SECONDS", DEFAULT_MIN_TIME_SECONDS)
    )
    alert_country_change = getattr(settings, "GEOLOCATION_ALERT_ON_COUNTRY_CHANGE", False)

    # 1. Parse attributes
    country = parse_node_country(device)
    public_address = parse_node_public_address(device)
    current_loc = create_location_snapshot(country, public_address, eval_now)

    # 2. Extract previous location telemetry from existing node
    previous_loc: Optional[Dict[str, Any]] = None
    location_history: List[Dict[str, Any]] = []

    if existing_node and existing_node.telemetry_metadata:
        prev_geo = existing_node.telemetry_metadata.get("geolocation", {})
        if prev_geo and prev_geo.get("current_location"):
            previous_loc = prev_geo["current_location"]
        elif prev_geo and (prev_geo.get("country") or prev_geo.get("public_address")):
            previous_loc = {
                "country": prev_geo.get("country"),
                "country_name": prev_geo.get("country_name"),
                "public_address": prev_geo.get("public_address"),
                "latitude": prev_geo.get("latitude"),
                "longitude": prev_geo.get("longitude"),
                "recorded_at": prev_geo.get("audited_at")
                or (existing_node.last_seen.isoformat() if existing_node.last_seen else eval_now.isoformat()),
            }
        location_history = list(prev_geo.get("location_history") or [])

    # 3. Detect impossible travel anomalies
    travel_analysis = detect_impossible_travel(
        current_loc=current_loc,
        previous_loc=previous_loc or {},
        max_speed_kmh=speed_threshold,
        min_distance_km=dist_threshold,
        min_time_seconds=time_threshold,
    )

    is_impossible = travel_analysis["is_impossible_travel"]
    alerts: List[Dict[str, Any]] = []

    prev_country = previous_loc.get("country") if previous_loc else None
    prev_ip = previous_loc.get("public_address") if previous_loc else None
    curr_cname = current_loc.get("country_name") or country or "Unknown"
    prev_cname = previous_loc.get("country_name") if previous_loc else prev_country

    if is_impossible:
        alert_msg = (
            f"Impossible travel event detected for device '{device.hostname}': "
            f"{travel_analysis['reason']} "
            f"Previous location: {prev_cname} ({prev_ip}), "
            f"Current location: {curr_cname} ({public_address})."
        )
        alerts.append(
            {
                "title": f"Impossible travel detected for device '{device.hostname}'",
                "event_type": AuditEventType.IMPOSSIBLE_TRAVEL.value,
                "event_category": EventCategory.SECURITY.value,
                "severity": AuditSeverity.CRITICAL.value,
                "message": alert_msg,
                "details": {
                    "hostname": device.hostname,
                    "from_country": prev_country,
                    "from_country_name": prev_cname,
                    "from_ip": prev_ip,
                    "to_country": country,
                    "to_country_name": curr_cname,
                    "to_ip": public_address,
                    "distance_km": travel_analysis["distance_km"],
                    "time_delta_seconds": travel_analysis["time_delta_seconds"],
                    "time_delta_human": travel_analysis["time_delta_human"],
                    "speed_kmh": travel_analysis["speed_kmh"],
                    "speed_threshold_kmh": speed_threshold,
                    "reason": travel_analysis["reason"],
                },
            }
        )
    elif (
        alert_country_change
        and prev_country
        and country
        and prev_country != country
    ):
        alerts.append(
            {
                "title": f"Location changed for device '{device.hostname}'",
                "event_type": AuditEventType.LOCATION_CHANGED.value,
                "event_category": EventCategory.NETWORK.value,
                "severity": AuditSeverity.INFO.value,
                "message": (
                    f"Device '{device.hostname}' changed country from "
                    f"{prev_cname} to {curr_cname}."
                ),
                "details": {
                    "hostname": device.hostname,
                    "from_country": prev_country,
                    "to_country": country,
                    "distance_km": travel_analysis["distance_km"],
                    "time_delta_human": travel_analysis["time_delta_human"],
                },
            }
        )

    # 4. Update rolling location history (keep latest 20 snapshots)
    if country or public_address:
        latest_in_history = location_history[0] if location_history else None
        if not latest_in_history or (
            latest_in_history.get("country") != country
            or latest_in_history.get("public_address") != public_address
        ):
            location_history.insert(0, current_loc)
            location_history = location_history[:20]

    # 5. Build structured return report
    is_compliant = not is_impossible
    compliance_status = (
        ComplianceStatus.COMPLIANT.value
        if is_compliant
        else ComplianceStatus.NON_COMPLIANT.value
    )

    return {
        "is_compliant": is_compliant,
        "compliance_status": compliance_status,
        "is_impossible_travel": is_impossible,
        "country": country,
        "country_name": curr_cname,
        "public_address": public_address,
        "latitude": current_loc["latitude"],
        "longitude": current_loc["longitude"],
        "current_location": current_loc,
        "previous_location": previous_loc,
        "previous_country": prev_country,
        "previous_public_address": prev_ip,
        "distance_km": travel_analysis["distance_km"],
        "time_delta_seconds": travel_analysis["time_delta_seconds"],
        "time_delta_human": travel_analysis["time_delta_human"],
        "speed_kmh": travel_analysis["speed_kmh"],
        "speed_threshold_kmh": speed_threshold,
        "anomaly_reason": travel_analysis["reason"],
        "alerts": alerts,
        "location_history": location_history,
        "audited_at": eval_now.isoformat(),
    }


# ---------------------------------------------------------------------------
# Fleet-Wide Geolocation Aggregation & Query Functions
# ---------------------------------------------------------------------------


async def get_fleet_geolocation_overview(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Aggregates fleet geolocation data, country distribution, and active impossible travel alerts.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet domain filter.

    Returns:
        Aggregated fleet geolocation overview dictionary.
    """
    stmt = select(Node)
    if tailnet:
        stmt = stmt.where(Node.tailnet == tailnet)

    result = await session.execute(stmt)
    nodes = result.scalars().all()

    total_endpoints = len(nodes)
    endpoints_with_geo = 0
    country_counts: Dict[str, int] = {}
    country_names: Dict[str, str] = {}
    flagged_endpoints: List[Dict[str, Any]] = []

    for n in nodes:
        meta = n.telemetry_metadata or {}
        geo = meta.get("geolocation", {})
        country = geo.get("country") or meta.get("country")
        pub_ip = geo.get("public_address") or meta.get("public_address")

        if country or pub_ip:
            endpoints_with_geo += 1

        if country:
            country_counts[country] = country_counts.get(country, 0) + 1
            if country not in country_names:
                coords = get_country_coordinates(country)
                country_names[country] = coords[2] if coords else country

        if geo.get("is_impossible_travel"):
            flagged_endpoints.append(
                {
                    "id": n.id,
                    "node_id": n.node_id,
                    "hostname": n.hostname,
                    "name": n.name,
                    "user": n.user,
                    "country": country,
                    "country_name": geo.get("country_name"),
                    "public_address": pub_ip,
                    "distance_km": geo.get("distance_km"),
                    "speed_kmh": geo.get("speed_kmh"),
                    "anomaly_reason": geo.get("anomaly_reason"),
                    "audited_at": geo.get("audited_at"),
                }
            )

    sorted_distribution = dict(
        sorted(country_counts.items(), key=lambda item: item[1], reverse=True)
    )

    country_breakdown = [
        {
            "country_code": c_code,
            "country_name": country_names.get(c_code, c_code),
            "endpoint_count": count,
            "percentage": round((count / total_endpoints) * 100.0, 2)
            if total_endpoints > 0
            else 0.0,
        }
        for c_code, count in sorted_distribution.items()
    ]

    audit_stmt = select(AuditLog).where(
        AuditLog.event_type == AuditEventType.IMPOSSIBLE_TRAVEL.value
    )
    audit_res = await session.execute(audit_stmt)
    impossible_travel_events = audit_res.scalars().all()

    return {
        "total_endpoints": total_endpoints,
        "endpoints_with_geolocation": endpoints_with_geo,
        "unique_countries_count": len(country_counts),
        "country_distribution": sorted_distribution,
        "country_breakdown": country_breakdown,
        "impossible_travel_events_count": len(impossible_travel_events),
        "flagged_endpoints_count": len(flagged_endpoints),
        "flagged_endpoints": flagged_endpoints,
        "audited_at": datetime.now(timezone.utc).isoformat(),
    }


async def get_fleet_impossible_travel_events(
    session: AsyncSession,
    tailnet: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Retrieves logged impossible travel events from fleet audit logs.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet domain filter.
        limit: Max events to return (1-500).

    Returns:
        Structured list of impossible travel audit events with node details.
    """
    stmt = (
        select(AuditLog)
        .where(AuditLog.event_type == AuditEventType.IMPOSSIBLE_TRAVEL.value)
        .order_by(desc(AuditLog.created_at))
        .limit(min(max(1, limit), 500))
    )
    result = await session.execute(stmt)
    logs = result.scalars().all()

    events: List[Dict[str, Any]] = []
    for log in logs:
        details = log.details or {}
        events.append(
            {
                "id": log.id,
                "node_id": log.node_id,
                "event_type": log.event_type,
                "severity": log.severity,
                "action": log.action,
                "actor": log.actor,
                "message": log.message,
                "hostname": details.get("hostname"),
                "from_country": details.get("from_country"),
                "from_country_name": details.get("from_country_name"),
                "from_ip": details.get("from_ip"),
                "to_country": details.get("to_country"),
                "to_country_name": details.get("to_country_name"),
                "to_ip": details.get("to_ip"),
                "distance_km": details.get("distance_km"),
                "time_delta_human": details.get("time_delta_human"),
                "speed_kmh": details.get("speed_kmh"),
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
        )

    return {
        "total_events": len(events),
        "events": events,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }


async def get_node_geolocation_audit(
    session: AsyncSession,
    node_id: str,
) -> Dict[str, Any]:
    """Retrieves detailed geolocation tracking and movement audit for a specific node.

    Args:
        session: Active SQLAlchemy AsyncSession.
        node_id: Target node identifier (Node.id or Node.node_id).

    Returns:
        Node geolocation audit dictionary, or not_found error.
    """
    stmt = select(Node).where((Node.id == node_id) | (Node.node_id == node_id))
    result = await session.execute(stmt)
    node = result.scalar_one_or_none()

    if not node:
        return {"error": "node_not_found", "node_id": node_id}

    meta = node.telemetry_metadata or {}
    geo = meta.get("geolocation", {})
    country = geo.get("country") or meta.get("country")
    pub_ip = geo.get("public_address") or meta.get("public_address")

    audit_stmt = (
        select(AuditLog)
        .where(
            (AuditLog.node_id == node.id)
            & (AuditLog.event_type == AuditEventType.IMPOSSIBLE_TRAVEL.value)
        )
        .order_by(desc(AuditLog.created_at))
        .limit(20)
    )
    audit_res = await session.execute(audit_stmt)
    audit_logs = audit_res.scalars().all()

    travel_events = [
        {
            "id": log.id,
            "severity": log.severity,
            "message": log.message,
            "details": log.details,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in audit_logs
    ]

    coords = get_country_coordinates(country)
    country_name = geo.get("country_name") or (coords[2] if coords else country)

    return {
        "id": node.id,
        "node_id": node.node_id,
        "hostname": node.hostname,
        "name": node.name,
        "user": node.user,
        "os": node.os,
        "is_online": node.is_online,
        "country": country,
        "country_name": country_name,
        "public_address": pub_ip,
        "latitude": geo.get("latitude") or (coords[0] if coords else None),
        "longitude": geo.get("longitude") or (coords[1] if coords else None),
        "is_impossible_travel": geo.get("is_impossible_travel", False),
        "anomaly_reason": geo.get("anomaly_reason"),
        "location_history": geo.get("location_history", []),
        "travel_events_count": len(travel_events),
        "travel_events": travel_events,
        "audited_at": geo.get("audited_at"),
    }
