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
    """Test creation of a PortReport object."""

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


def test_create_host_report():
    """test creation of a full HostReport."""

    vulnerability1 = Vulnerability('ssh', 'CVE-4815162342', 'Sample CVE', 'no')
    vulnerability2 = Vulnerability('ftp', 'CVE-69420', 'Sample CVE 2', 'yes')
    vulnerability3 = Vulnerability('apache', 'CVE-133742', 'CVE 3', 'yes')

    vulnerabilities1 = [vulnerability1, vulnerability2]
    vulnerabilities2 = [vulnerability3]

    port_report1 = PortReport(
        22, 'up', True, False, 'ftp', '2.43.21', vulnerabilities1)
    port_report2 = PortReport(
        80, 'up', True, False, 'http', '1.0', vulnerabilities2)

    ports_report = [port_report1, port_report2]

    host_report = HostReport(
        '192.168.0.42',
        'hostname1',
        'ff:ff:ff:ff:ff:ff',
        'up',
        ports_report,
        42.1337)

    assert host_report.ip == '192.168.0.42'
    assert host_report.hostname == 'hostname1'
    assert host_report.mac == 'ff:ff:ff:ff:ff:ff'
    assert host_report.state == 'up'
    assert host_report.duration == '42s'
    assert len(host_report.ports) == 2
    assert len(host_report.ports[0].vulnerabilities) == 2
    assert len(host_report.ports[1].vulnerabilities) == 1


def test_create_report():
    """Test creation of a full report."""

    # Host 1
    vulnerability1 = Vulnerability('ssh', 'CVE-4815162342', 'Sample CVE', 'no')
    vulnerability2 = Vulnerability('ftp', 'CVE-69420', 'Sample CVE 2', 'yes')
    vulnerability3 = Vulnerability('apache', 'CVE-133742', 'CVE 3', 'yes')

    vulnerabilities1 = [vulnerability1, vulnerability2]
    vulnerabilities2 = [vulnerability3]

    port_report1 = PortReport(
        22, 'up', True, False, 'ftp', '2.43.21', vulnerabilities1)
    port_report2 = PortReport(
        80, 'up', True, False, 'http', '1.0', vulnerabilities2)

    ports_report1 = [port_report1, port_report2]

    host_report1 = HostReport(
        '192.168.0.42',
        'hostname1',
        'ff:ff:ff:ff:ff:ff',
        'up',
        ports_report1,
        42)

    # Host 2
    vulnerability4 = Vulnerability('ssh', 'CVE-4815162342', 'Sample CVE', 'no')
    vulnerability5 = Vulnerability('ftp', 'CVE-69420', 'Sample CVE 2', 'yes')
    vulnerability6 = Vulnerability('apache', 'CVE-133742', 'CVE 3', 'yes')

    vulnerabilities3 = [vulnerability4]
    vulnerabilities4 = [vulnerability5, vulnerability6]

    port_report3 = PortReport(
        22, 'up', True, False, 'ftp', '2.43.21', vulnerabilities3)
    port_report4 = PortReport(
        80, 'up', True, False, 'http', '1.0', vulnerabilities4)

    ports_report2 = [port_report3, port_report4]

    host_report2 = HostReport(
        '192.168.0.4',
        'hostname2',
        'ff:ff:ff:ff:ff:ff',
        'up',
        ports_report2,
        43)

    host_report3 = HostReport('192.168.0.5', 'hostname3', '', 'down', None, 12)

    report = Report(42, [host_report1, host_report2, host_report3])

    assert report.nb_hosts == 3
    assert report.up == 2
    assert report.duration == "42s"


def test_str_port_report():
    """Test the str function for PortReport."""

    port_report_1 = PortReport(
        22, 'up', True, False, 'ssh', '1.2.3', []
    )
    port_report_2 = PortReport(
        123, 'up', False, True, '', '', []
    )

    assert str(port_report_1) == "[TCP] Port 22 (up): ssh - Version 1.2.3"
    assert str(port_report_2) == "[UDP] Port 123 (up): Unknown"


def test_str_host_report():
    """Test the str function for HostReport."""

    port_report_1 = PortReport(
        22, 'up', True, False, 'ssh', '1.2.3', []
    )
    port_report_2 = PortReport(
        123, 'up', False, True, '', '', []
    )

    host_report = HostReport(
        '127.0.0.1', 'localhost', 'ff:ff:ff', 'up',
        [port_report_1, port_report_2],
        421.69
    )

    result_lines = str(host_report).split('\n')
    assert result_lines[0] == "HostReport 127.0.0.1 - up"
    assert result_lines[1] == "\tHostname: localhost"
    assert result_lines[2] == "\tMAC Address: ff:ff:ff (7m1s)"
    assert result_lines[3] == "\tPorts:"
    assert result_lines[4] == "\t\t- [TCP] Port 22 (up): ssh - Version 1.2.3"
    assert result_lines[5] == "\t\t- [UDP] Port 123 (up): Unknown"


def test_str_full_report():
    """Test the str function for Report."""

    port_report_1 = PortReport(
        22, 'up', True, False, 'ssh', '1.2.3', []
    )
    port_report_2 = PortReport(
        123, 'up', False, True, '', '', []
    )

    host_report = HostReport(
        '127.0.0.1', 'localhost', 'ff:ff:ff', 'up',
        [port_report_1, port_report_2],
        421.69
    )

    full_report = Report(421.69, [host_report])

    result_lines = str(full_report).split('\n')
    assert result_lines[0] == "Scanning report"
    assert result_lines[1] == "================"
    assert result_lines[4] == "1 Hosts scanned in 7m1s"
    assert result_lines[5] == "1 Hosts up"
    assert result_lines[8] == "* HostReport 127.0.0.1 - up"
    assert result_lines[9] == "\tHostname: localhost"
    assert result_lines[10] == "\tMAC Address: ff:ff:ff (7m1s)"
    assert result_lines[11] == "\tPorts:"
    assert result_lines[12] == "\t\t- [TCP] Port 22 (up): ssh - Version 1.2.3"
    assert result_lines[13] == "\t\t- [UDP] Port 123 (up): Unknown"