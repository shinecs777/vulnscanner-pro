"""Input validation and SSRF defenses for user-supplied scan targets."""

import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit

from config import Config


class ValidationError(ValueError):
    """Raised when a user-supplied value is unsafe or malformed."""


_SHELL_META = re.compile(r"[;&|`$><\n\r\x00]")

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

_NUMERIC_HOST_RE = re.compile(
    r"^(0x[0-9a-fA-F]+|[0-9]+)(\.(0x[0-9a-fA-F]+|[0-9]+)){0,3}$"
)

_ALLOWED_SCHEMES = {"http", "https"}


def _require_string(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{label} must be a string.")
    stripped = value.strip()
    if not stripped:
        raise ValidationError(f"{label} must not be empty.")
    if _SHELL_META.search(stripped):
        raise ValidationError(
            "Target contains disallowed shell metacharacters."
        )
    return stripped


def _parse_ip_literal(host: str) -> ipaddress._BaseAddress | None:
    """Parse standard and legacy numeric IPv4 forms into an address object."""
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]

    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass

    if _NUMERIC_HOST_RE.match(candidate):
        try:
            packed = socket.inet_aton(candidate)
        except OSError:
            return None
        return ipaddress.IPv4Address(packed)

    return None


def _reject_ip(
    ip: ipaddress._BaseAddress | str, *, allow_private: bool = False
) -> None:
    """Reject addresses that must never be contacted by a scanner or the app."""
    if not isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip = ipaddress.ip_address(str(ip).split("%", 1)[0])

    if ip.is_loopback:
        raise ValidationError(f"Loopback addresses are not allowed: {ip}")
    if ip.is_link_local:
        raise ValidationError(f"Link-local addresses are not allowed: {ip}")
    if ip.is_multicast:
        raise ValidationError(f"Multicast addresses are not allowed: {ip}")
    if ip.is_unspecified:
        raise ValidationError(f"Unspecified addresses are not allowed: {ip}")
    if ip.is_reserved:
        raise ValidationError(f"Reserved addresses are not allowed: {ip}")
    if ip.is_private and Config.BLOCK_PRIVATE_RANGES and not allow_private:
        raise ValidationError(f"Private addresses are not allowed: {ip}")


def validate_ip(target: str) -> str:
    """Validate a single IP address or CIDR range.

    Private ranges are permitted because authorized internal assessments need
    them; loopback, link-local, multicast, reserved, and unspecified ranges
    are always rejected.
    """
    value = _require_string(target, "Target")

    if "/" in value:
        if value.count("/") != 1:
            raise ValidationError(f"Invalid CIDR range: {value}")
        address_part, prefix_part = value.split("/", 1)
        address = _parse_ip_literal(address_part)
        if address is None:
            raise ValidationError(f"Invalid IP address or CIDR: {value}")
        try:
            network = ipaddress.ip_network(f"{address}/{prefix_part}", strict=False)
        except ValueError as exc:
            raise ValidationError(f"Invalid CIDR range: {value}") from exc
        _reject_ip(network.network_address, allow_private=True)
        return str(network)

    address = _parse_ip_literal(value)
    if address is None:
        raise ValidationError(f"Invalid IP address: {value}")
    _reject_ip(address, allow_private=True)
    return str(address)


def validate_url(target: str) -> str:
    """Validate an HTTP(S) URL and defend against SSRF and parser bypasses."""
    value = _require_string(target, "Target")

    if "://" not in value:
        value = f"https://{value}"

    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ValidationError(f"Malformed URL: {value}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValidationError("Only http and https URLs are allowed.")

    if parsed.username or parsed.password:
        raise ValidationError("URLs with embedded credentials are not allowed.")

    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValidationError(f"Malformed URL port: {value}") from exc

    if not host:
        raise ValidationError("URL must include a hostname.")

    host = host.lower()
    host_normalized = host.rstrip(".")
    if not host_normalized:
        raise ValidationError("URL must include a hostname.")

    if host_normalized in Config.BLOCKED_HOSTS:
        raise ValidationError(f"Target host is blocked: {host_normalized}")

    if host_normalized.endswith(".local") or host_normalized.endswith(".internal"):
        raise ValidationError(
            f"Target host uses a blocked internal suffix: {host_normalized}"
        )

    literal = _parse_ip_literal(host_normalized)
    if literal is not None:
        _reject_ip(literal)
        return urlunsplit(
            (scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment)
        )

    if not _HOSTNAME_RE.match(host_normalized):
        raise ValidationError(f"Invalid hostname: {host_normalized}")

    try:
        address_info = socket.getaddrinfo(
            host_normalized,
            port or (443 if scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValidationError(
            f"Could not resolve target host: {host_normalized}"
        ) from exc

    resolved = {item[4][0] for item in address_info}
    if not resolved:
        raise ValidationError(f"Could not resolve target host: {host_normalized}")

    for address in resolved:
        _reject_ip(address)

    return urlunsplit(
        (scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment)
    )


def validate_scan_request(scan_type: str, target: str) -> str:
    """Validate a scan request according to its declared scan type."""
    if not isinstance(scan_type, str):
        raise ValidationError("scan_type must be a string.")

    normalized = scan_type.strip().lower()
    if normalized == "network":
        return validate_ip(target)
    if normalized == "web":
        return validate_url(target)
    raise ValidationError(f"Unsupported scan_type: {scan_type!r}")
