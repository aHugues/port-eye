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
    host = "localhost"
    scanner = MockPortScanner()
    with pytest.raises(KeyError):
        scanner.build_tcp_result(42)


def test_additionnal_info_removal():
    """Test that additionnal info are removed when skipping ping."""
    host = "localhost"
    scanner = MockPortScanner()

    result = scanner.build_tcp_result(22, True)
    assert result["product"] == ""
    assert result["version"] == ""
    assert result["extrainfo"] == ""
    assert result["cpe"] == ""
    assert result["conf"] == "3"


def test_is_vulnerable():
    """Test if host/port combination is correctly detected as vulnerable."""
    host1 = u"92.222.10.88"
    host2 = u"82.64.28.100"

    scanner = MockPortScanner()

    assert scanner.is_vulnerable(host1, 22) is False
    assert scanner.is_vulnerable(host1, 443) is True
    assert scanner.is_vulnerable(host2, 22) is False
    assert scanner.is_vulnerable(host2, 443) is False


def test_build_vuln_result_not_vulnerable():
    """Test building the vuln result when not vulnerable."""
    scanner = MockPortScanner()
    result = scanner.build_vuln_result(-1)

    assert "clamav-exec" in result
    assert "ERROR" in result["clamav-exec"]
    assert "Script execution failed" in result["clamav-exec"]


def test_build_vuln_result_not_present():
    """Test building the vuln result when port is not in dict."""
    scanner = MockPortScanner()
    result = scanner.build_vuln_result(42)

    assert "clamav-exec" in result
    assert "ERROR" in result["clamav-exec"]
    assert "Script execution failed" in result["clamav-exec"]


def test_build_vuln_result_vulnerable():
    """Test building the vuln result when port is vulnerable."""
    scanner = MockPortScanner()
    result = scanner.build_vuln_result(443)

    assert "http-aspnet-debug" in result
    assert "http-slowloris-check" in result
    assert "sslv2-drown" in result

    assert "ERROR" in result["http-aspnet-debug"]
    assert "Script execution failed" in result["http-aspnet-debug"]
    assert result["sslv2-drown"] == "\n"
    assert "CVE-2007-6750" in result["http-slowloris-check"]
    assert "Disclosure date: 2009-09-17" in result["http-slowloris-check"]


def test_build_result_vulnerable():
    """Test building the result for a vulnerable host."""
    host = u"92.222.10.88"

    scanner = MockPortScanner()
    result = scanner.build_result_vulnerable(host)

    scan_result = result["scan"]

    ports = [22, 80, 443]
    for port in ports:
        assert "script" in scan_result[host]["tcp"][port]

    assert "http-slowloris-check" in scan_result[host]["tcp"][443]["script"]
    assert "clamav-exec" in scan_result[host]["tcp"][22]["script"]


def test_scan_vuln():
    """Test scanning for vulnerabilities."""
    host = u"92.222.10.88"
    arguments = "--script vuln"

    scanner = MockPortScanner()
    result = scanner.scan(host, arguments=arguments)

    scan_result = result["scan"]

    ports = [22, 80, 443]
    for port in ports:
        assert "script" in scan_result[host]["tcp"][port]

    assert "http-slowloris-check" in scan_result[host]["tcp"][443]["script"]
    assert "clamav-exec" in scan_result[host]["tcp"][22]["script"]
