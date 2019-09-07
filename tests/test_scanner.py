"""Test functions for the Scanner class."""

import sys
import pytest
import ipaddress
from port_eye.scanner import Scanner, ScannerHandler
from port_eye.report import PortReport, HostReport, Report
import threading

if sys.version_info[0] == 2: # pragma: no cover
    from Queue import Queue
else:
    from queue import Queue


def test_import():
    """Test that the correct version of queue/Queue is imported."""


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

# This test is disabled because of lack of support from TravisCI
# def test_reachable_ipv6():
    # """Check the detection of reachable hosts while IPV6."""
    # reachable_host = ipaddress.ip_address(
        # u"2a01:e0a:129:5ed0:211:32ff:fea8:97e")
    # scanner = Scanner(reachable_host, True)
    # assert scanner.is_reachable() is True


def test_protocol_verification():
    """Test that only acceptable protocols types are accepted."""

    host = ipaddress.ip_address(u'127.0.0.1')
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
    host = ipaddress.ip_address(u'92.222.10.88')
    scanner = Scanner(host)

    assert scanner.is_local() is False
    assert scanner.is_reachable() is True

    scanner.perform_scan()
    ports = scanner.extract_ports('tcp')

    assert len(ports) >= 3
    for port in ports:
        assert port.__class__ == PortReport

    expected_ports = [22, 80, 443]
    port_numbers = [port.port_number for port in ports]
    for expected_port in expected_ports:
        assert expected_port in port_numbers


def test_host_scanning():
    """Test the report extraction from a complete host."""

    host = ipaddress.ip_address(u'92.222.10.88')
    scanner = Scanner(host)
    scanner.perform_scan()

    report = scanner.extract_host_report()
    assert report.__class__ == HostReport

    assert report.hostname == 'valinor.aurelienhugues.com'
    assert report.ip == '92.222.10.88'
    assert report.mac == ''
    assert report.state == 'up'
    assert len(report.ports) >= 3

    for port in report.ports:
        assert port.__class__ == PortReport

    expected_ports = [22, 80, 443]
    port_numbers = [port.port_number for port in report.ports]
    for expected_port in expected_ports:
        assert expected_port in port_numbers

# This test is disabled because of lack of support from TravisCI
# def test_host_scanning_ipv6():
#     """Test the report extraction from an IPV6 host."""

#     host = ipaddress.ip_address(u"::1")
#     scanner = Scanner(host, True)
#     scanner.perform_scan()

#     report = scanner.extract_host_report()
#     assert report.__class__ == HostReport

#     assert report.hostname == 'localhost'
#     assert report.ip == '::1'
#     assert report.state == 'up'
#     assert len(report.ports) >= 0


def test_scanner_handler_creation():
    """Test the creation of a ScannerHandler object."""
    ipv4_hosts = [
        ipaddress.ip_address(u"127.0.0.1"),
        ipaddress.ip_address(u"92.222.10.88"),
    ]
    ipv6_hosts = [
        ipaddress.ip_address(u"::1")
    ]
    cidr_blocks = [
        ipaddress.ip_network(u"192.168.0.1/32")
    ]

    scanner_handler = ScannerHandler(ipv4_hosts, ipv6_hosts, cidr_blocks)

    assert len(scanner_handler.ipv4_hosts) == 2
    assert len(scanner_handler.ipv6_hosts) == 1
    assert len(scanner_handler.cidr_blocks) == 1

    for host in scanner_handler.ipv4_hosts:
        assert host.__class__ == ipaddress.IPv4Address
    for host in scanner_handler.ipv6_hosts:
        assert host.__class__ == ipaddress.IPv6Address
    for host in scanner_handler.cidr_blocks:
        assert host.__class__ == ipaddress.IPv4Network
    
    assert len(scanner_handler.scanners) == 4
    for scanner in scanner_handler.scanners:
        assert scanner.__class__ == Scanner


def test_scan_handling():
    """Test that scanning is performed without issue."""
    ipv4_hosts = [
        ipaddress.ip_address(u"127.0.0.1"),
        ipaddress.ip_address(u"192.0.2.1")
    ]
    scanner_handler = ScannerHandler(ipv4_hosts, [], [])
    hosts_queue = Queue()

    scanner_handler.run_scan(scanner_handler.scanners[0], hosts_queue)

    assert hosts_queue.qsize() == 1
    assert hosts_queue.get().__class__ == HostReport


def test_running_scans():
    """Test running full scans."""
    ipv4_hosts = [
        ipaddress.ip_address(u"127.0.0.1")
    ]
    # ipv6_hosts = [
        # ipaddress.ip_address(u"::1")
    # ]

    scanner_handler = ScannerHandler(ipv4_hosts, [], [])
    report = scanner_handler.run_scans()

    assert report.__class__ == Report
    assert report.nb_hosts == 1
    assert report.up == 1
    assert type(report.duration) == str
    assert "127.0.0.1" in [x.ip for x in report.results]
    # assert "::1" in [x.ip for x in report.results]