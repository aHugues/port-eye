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
