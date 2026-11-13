"""Tests for input validation and SSRF defenses."""

import socket

import pytest

from config import Config
from core.validator import (
    ValidationError,
    validate_ip,
    validate_scan_request,
    validate_url,
)


class TestValidateIP:
    @pytest.mark.parametrize(
        "target",
        ["10.0.0.5", "172.16.5.4", "192.168.1.10", "10.20.0.0/16"],
    )
    def test_accepts_private_ipv4(self, target):
        assert validate_ip(target)

    def test_accepts_public_ipv4(self):
        assert validate_ip("8.8.8.8") == "8.8.8.8"

    @pytest.mark.parametrize("target", ["127.0.0.1", "127.10.20.30", "::1"])
    def test_rejects_loopback(self, target):
        with pytest.raises(ValidationError):
            validate_ip(target)

    @pytest.mark.parametrize(
        "target",
        ["10.0.0.1; rm -rf /", "10.0.0.1 | whoami", "10.0.0.1`id`"],
    )
    def test_rejects_shell_metachar(self, target):
        with pytest.raises(ValidationError):
            validate_ip(target)

    @pytest.mark.parametrize(
        "target",
        ["2130706433", "0x7f000001", "0177.0.0.1"],
    )
    def test_rejects_octal_ip_bypass(self, target):
        with pytest.raises(ValidationError):
            validate_ip(target)

    @pytest.mark.parametrize(
        "target",
        ["169.254.169.254", "224.0.0.1", "240.0.0.1", "0.0.0.0"],
    )
    def test_rejects_unsafe_special_ranges(self, target):
        with pytest.raises(ValidationError):
            validate_ip(target)

    def test_rejects_malformed_ip(self):
        with pytest.raises(ValidationError):
            validate_ip("not-an-ip")


class TestValidateURL:
    def test_accepts_public_url(self, monkeypatch):
        def fake_getaddrinfo(host, port, **kwargs):
            assert host == "example.com"
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", port),
                )
            ]

        monkeypatch.setattr(
            "core.validator.socket.getaddrinfo", fake_getaddrinfo
        )
        assert validate_url("example.com") == "https://example.com"

    def test_accepts_public_ip_url(self):
        assert validate_url("https://8.8.8.8/path") == "https://8.8.8.8/path"

    @pytest.mark.parametrize(
        "target",
        ["127.0.0.1", "http://127.0.0.1/admin", "http://[::1]:8080/"],
    )
    def test_rejects_loopback(self, target):
        with pytest.raises(ValidationError):
            validate_url(target)

    @pytest.mark.parametrize(
        "target",
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ],
    )
    def test_rejects_cloud_metadata(self, target):
        with pytest.raises(ValidationError):
            validate_url(target)

    @pytest.mark.parametrize(
        "target",
        ["http://printer.local/", "https://service.internal/status"],
    )
    def test_rejects_internal_suffix(self, target):
        with pytest.raises(ValidationError):
            validate_url(target)

    @pytest.mark.parametrize(
        "target",
        ["file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO"],
    )
    def test_rejects_bad_scheme(self, target):
        with pytest.raises(ValidationError):
            validate_url(target)

    def test_rejects_octal_ip_bypass(self):
        with pytest.raises(ValidationError):
            validate_url("http://2130706433/")

    @pytest.mark.parametrize(
        "target",
        ["https://example.com;id", "https://example.com|cat", "example.com`id`"],
    )
    def test_rejects_shell_metachar(self, target):
        with pytest.raises(ValidationError):
            validate_url(target)

    def test_rejects_private_ip_when_blocked(self, monkeypatch):
        monkeypatch.setattr(Config, "BLOCK_PRIVATE_RANGES", True)
        with pytest.raises(ValidationError):
            validate_url("http://10.0.0.1/")

    def test_rejects_unresolvable_host(self, monkeypatch):
        def fake_getaddrinfo(host, port, **kwargs):
            raise socket.gaierror("name resolution failed")

        monkeypatch.setattr(
            "core.validator.socket.getaddrinfo", fake_getaddrinfo
        )
        with pytest.raises(ValidationError):
            validate_url("https://does-not-resolve.invalid/")


class TestValidateScanRequest:
    def test_dispatches_network(self):
        assert validate_scan_request("network", "10.0.0.5") == "10.0.0.5"

    def test_dispatches_web(self, monkeypatch):
        def fake_getaddrinfo(host, port, **kwargs):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", port),
                )
            ]

        monkeypatch.setattr(
            "core.validator.socket.getaddrinfo", fake_getaddrinfo
        )
        assert validate_scan_request("web", "https://example.com")

    def test_rejects_unknown_scan_type(self):
        with pytest.raises(ValidationError):
            validate_scan_request("smtp", "example.com")

    def test_rejects_shell_metachar_via_dispatch(self):
        with pytest.raises(ValidationError):
            validate_scan_request("web", "example.com; whoami")
