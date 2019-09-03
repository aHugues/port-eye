"""Tests the classes necessary to generate reports."""

from port_eye.report import Vulnerability, PortReport, HostReport, Report


def test_create_vulnerability():
    """Test creation of a Vulnerability object."""

    vulnerability = Vulnerability('ssh', 'CVE-4815162342', 'Sample CVE', 'no')

    assert vulnerability.service == 'ssh'
    assert vulnerability.cve == 'CVE-4815162342'
    assert vulnerability.description == 'Sample CVE'
    assert vulnerability.link == 'no'


def test_create_port_report():
    """Test create of a PortReport object."""

    vulnerability1 = Vulnerability('ssh', 'CVE-4815162342', 'Sample CVE', 'no')
    vulnerability2 = Vulnerability('ftp', 'CVE-69420', 'Sample CVE 2', 'yes') 
    vulnerabilities = [vulnerability1, vulnerability2]

    port_report = PortReport(
        22, 'up', True, False, 'ftp', '2.43.21', vulnerabilities)
    
    assert port_report.port_number == 22
    assert port_report.state == 'up'
    assert port_report.tcp is True 
    assert port_report.udp is False 
    assert port_report.service == 'ftp'
    assert port_report.version == '2.43.21'
    assert len(port_report.vulnerabilities) == 2
    
