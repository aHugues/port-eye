"""Test the mock nmap API."""

import pytest
from port_eye.mock_nmap import MockPortScanner

def test_ping_blocked():
    """Test non-detection of hosts when ping blocked."""
    host = u"82.64.28.100"
    scanner = MockPortScanner()
    assert scanner.reachable(host) is False


def test_ping_sudo():
    """Test detection of hosts when ping skipped."""
    host = u"82.64.28.100"
    scanner = MockPortScanner()
    assert scanner.reachable(host, sudo=True) is True


def test_port_range():
    """Test that only allowed ports can be used."""
    host = 'localhost'
    scanner = MockPortScanner()
    with pytest.raises(KeyError):
        scanner.build_tcp_result(42)


def test_additionnal_info_removal():
    """Test that additionnal info are removed when skipping ping."""
    host = 'localhost'
    scanner = MockPortScanner()

    result = scanner.build_tcp_result(22, True)
    assert result['product'] == ''
    assert result['version'] == ''
    assert result['extrainfo'] == ''
    assert result['cpe'] == ''
    assert result['conf'] == '3'
