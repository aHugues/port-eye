"""Test functions for the Scanner class."""

from port_eye.scanner import Scanner
import ipaddress
import pytest

def test_wrong_format():
    """Test that a wrong format for a host is detected."""
    with pytest.raises(TypeError):
        wrong_host = "fake"
        Scanner(wrong_host)


def test_correct_format():
    """Test that the create of a scanner works."""
    host = ipaddress.ip_address(u"192.168.0.1")
    scanner = Scanner(host)
    assert scanner.host == host


def test_detection_private_host():
    """Check the detection of private/public hosts."""
    private_host = ipaddress.ip_address(u"192.168.0.1")
    public_host = ipaddress.ip_address(u"216.58.201.238")
    private_ipv6 = ipaddress.ip_address(u"fe80::a00:27ff:fe8f:ec03")
    public_ipv6 = ipaddress.ip_address(u"2a00:1450:4007:80a::200e")

    scanner_private_ipv4 = Scanner(private_host)
    scanner_public_ipv4 = Scanner(public_host)
    scanner_private_ipv6 = Scanner(private_ipv6)
    scanner_public_ipv6 = Scanner(public_ipv6)

    assert scanner_private_ipv4.is_local() is True
    assert scanner_public_ipv4.is_local() is False
    assert scanner_private_ipv6.is_local() is True
    assert scanner_public_ipv6.is_local() is False