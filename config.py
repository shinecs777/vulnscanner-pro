"""Application configuration for VulnScanner Pro.

Every setting is read from the environment with a safe fallback. No secrets
are committed to source control.
"""

import os
import secrets


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_set(name: str, default: set[str]) -> set[str]:
    raw = os.environ.get(name)
    if raw is None:
        return set(default)
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


class Config:
    """Single source of truth for runtime configuration."""

    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    DATABASE = os.environ.get("DATABASE", "scans.db")

    NMAP_PATH = os.environ.get(
        "NMAP_PATH", r"C:\Program Files (x86)\Nmap\nmap.exe"
    )
    NMAP_TIMEOUT = _env_int("NMAP_TIMEOUT", 300)

    NVD_API_URL = os.environ.get(
        "NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
    NVD_RATE_LIMIT_NO_KEY = _env_int("NVD_RATE_LIMIT_NO_KEY", 6)
    NVD_CACHE_TTL_DAYS = _env_int("NVD_CACHE_TTL_DAYS", 7)

    WEB_TIMEOUT = _env_int("WEB_TIMEOUT", 10)
    WEB_MAX_REDIRECTS = 3
    WEB_USER_AGENT = "VulnScanner-Pro/0.1 (authorized-assessment)"
    BLOCKED_HOSTS = _env_set(
        "BLOCKED_HOSTS",
        {
            "localhost",
            "localhost.localdomain",
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "169.254.169.254",
            "169.254.170.2",
            "100.100.100.200",
            "metadata.google.internal",
            "metadata.goog",
            "instance-data",
        },
    )
    BLOCK_PRIVATE_RANGES = _env_bool("BLOCK_PRIVATE_RANGES", True)

    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
    LOG_FILE = os.environ.get("LOG_FILE", "logs/app.log")
    DEBUG = _env_bool("DEBUG", False)
