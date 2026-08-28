"""
Server-Side Request Forgery (SSRF) Protection (Phase 10).
Prevents attackers from using the reverse proxy to pivot into internal cloud metadata,
local loopback services, or unauthorized private network segments.
"""

import ipaddress
import socket
from urllib.parse import urlparse
from app.config import settings

# Cloud metadata and link-local address spaces
FORBIDDEN_CIDRS = [
    ipaddress.ip_network("169.254.169.254/32"),  # AWS/GCP/Azure Metadata IP
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
]

PRIVATE_CIDRS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


class SSRFException(Exception):
    """Raised when an upstream URL violates SSRF security boundaries."""
    pass


def validate_upstream_url_safety(target_url: str) -> bool:
    """
    Validates that target_url does not target forbidden metadata endpoints
    or unauthorized internal network IP spaces.
    """
    if not settings.SSRF_PROTECTION_ENABLED:
        return True

    parsed = urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        raise SSRFException("Invalid URL: missing host")

    # Explicit allowlist check for legitimate development/docker hostnames
    if hostname in settings.ALLOWED_UPSTREAM_HOSTS:
        return True

    # Resolve IP address
    try:
        ip_str = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_str)
    except socket.gaierror:
        raise SSRFException(f"Failed to resolve upstream hostname '{hostname}'")

    # 1. Reject Cloud Metadata and Link-Local strictly
    for cidr in FORBIDDEN_CIDRS:
        if ip_obj in cidr:
            raise SSRFException(f"SSRF Blocked: Target '{ip_str}' is within forbidden network {cidr}")

    # 2. Check private CIDRs unless explicitly allowed
    for cidr in PRIVATE_CIDRS:
        if ip_obj in cidr:
            if hostname not in settings.ALLOWED_UPSTREAM_HOSTS and str(ip_obj) not in settings.ALLOWED_UPSTREAM_HOSTS:
                raise SSRFException(f"SSRF Blocked: Unauthorized private network target '{ip_str}' ({cidr})")

    return True
