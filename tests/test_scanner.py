"""Test functions for the Scanner class."""

from port_eye.scanner import Scanner
from port_eye.report import PortReport, HostReport
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
    assert scanner.raw_host == host
    assert scanner.host == u"192.168.0.1"


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


def test_reachable():
    """Check the detection of reachable hosts."""
    reachable_hosts = [
        ipaddress.ip_address(u"127.0.0.1"),
        ipaddress.ip_address(u"92.222.10.88"),
        # ipaddress.ip_address(u"2a00:1450:4007:80a::200e")
    ]
    unreachable_hosts = [
        ipaddress.ip_address(u"192.0.2.1")
    ]

    for host in reachable_hosts:
        scanner = Scanner(host)
        assert scanner.is_reachable() is True

    for host in unreachable_hosts:
        scanner = Scanner(host)
        assert scanner.is_reachable() is False


def test_protocol_verification():
    """Test that only acceptable protocols types are accepted."""

    host = ipaddress.ip_address('127.0.0.1')
    scanner = Scanner(host)

    scanner.perform_scan()

    scanner.extract_ports('tcp')
    scanner.extract_ports('udp')
    scanner.extract_ports('TCP')
    scanner.extract_ports('UDP')

    with pytest.raises(ValueError):
        scanner.extract_ports('http')

    with pytest.raises(ValueError):
        scanner.extract_ports('ssl')


def test_ports_scanning():
    """Test the scanning of ports.

    Test is ran on a machine with at least ports 22/80/443 opened.
    """
    host = ipaddress.ip_address('92.222.10.88')
    scanner = Scanner(host)

    assert scanner.is_local() is False
    assert scanner.is_reachable() is True

    scanner.perform_scan()
    ports = scanner.extract_ports('tcp')

    assert len(ports) >= 3
    for port in ports:
        assert type(port) == PortReport

    expected_ports = [22, 80, 443]
    port_numbers = [port.port_number for port in ports]
    for expected_port in expected_ports:
        assert expected_port in port_numbers


def test_host_scanning():
    """Test the report extraction from a complete host."""

    host = ipaddress.ip_address('92.222.10.88')
    scanner = Scanner(host)
    scanner.perform_scan()

    report = scanner.extract_host_report()
    assert type(report) == HostReport

    assert report.hostname == 'valinor.aurelienhugues.com'
    assert report.ip == '92.222.10.88'
    assert report.mac == ''
    assert report.state == 'up'
    assert len(report.ports) >= 3

    for port in report.ports:
        assert type(port) == PortReport

    expected_ports = [22, 80, 443]
    port_numbers = [port.port_number for port in report.ports]
    for expected_port in expected_ports:
        assert expected_port in port_numbers
