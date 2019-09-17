"""Test functions from the utils module."""

import pytest
from ipaddress import IPv4Address, IPv6Address, IPv4Network, ip_network

from port_eye.utils import read_input_file
from port_eye.utils import parse_duration_from_seconds
from port_eye.utils import get_hosts_from_cidr
from port_eye.utils import build_hosts_dict
from port_eye.utils import parse_vuln_report


def test_duration_parsing():
    """Test that the duration is correctly parsed."""

    # Test that a negative value is correctly caught
    with pytest.raises(ValueError):
        parse_duration_from_seconds(-2)
    
    # Test values lower than a minute
    assert parse_duration_from_seconds(0) == "0s"
    assert parse_duration_from_seconds(42) == "42s"

    # Test values lower than an hour
    assert parse_duration_from_seconds(60) == "1m0s"
    assert parse_duration_from_seconds(80) == "1m20s"
    assert parse_duration_from_seconds(124) == "2m4s"

    # Test values higher than an hour
    assert parse_duration_from_seconds(3784) == "1h3m4s"
    assert parse_duration_from_seconds(3642) == "1h0m42s"


def test_hosts_from_cidr():
    """Test getting list of hosts from a cidr block."""

    block = ip_network(u'192.168.0.0/24')

    hosts = get_hosts_from_cidr(block)

    for host in hosts:
        assert host.__class__ == IPv4Address
    
    assert len(hosts) == 254
    assert str(hosts[0]) == "192.168.0.1"
    assert str(hosts[-1]) == "192.168.0.254"


def test_parsing_list_hosts():
    """Test getting hosts from a simple list."""

    ipv4 = [
        u'192.168.0.4',
        u'127.0.0.1',
        u'88.222.10.4'
    ]

    ipv6 = [
        u'2a01:e0a:129:5ed0:211:32ff:fe2d:68da',
        u'::1'
    ]

    ipv4_net = [
        u'192.168.0.0/20'
    ]

    ipv6_net = [
        u"2a01:0e0a:0129:5ed0:0211:32ff:fe2d:6800/120"
    ]

    invalid = [
        u'toto',
        u'265.444.22.3'
    ]

    hosts = ipv4 + ipv6 + ipv4_net + ipv6_net + invalid 

    result = build_hosts_dict(hosts)

    assert len(result['ipv4_hosts']) == 3
    assert len(result['ipv6_hosts']) == 2
    assert len(result['ipv4_networks']) == 1
    assert len(result['ipv6_networks']) == 1
    assert len(result['ignored']) == 2


def test_parsing_vuln_report():
    """Test parsing of vuln report from scripts."""

    script1 = 'ERROR: Script execution failed (use -d to debug)'
    script2 = (
        "\n  VULNERABLE:\n  Slowloris DOS attack\n    State: LIKELY "
        "VULNERABLE\n    IDs:  CVE:CVE-2007-6750\n      Slowloris tries to "
        "keep many connections to the target web server open and hold\n      "
        "them open as long as possible.  It accomplishes this by opening "
        "connections to\n      the target web server and sending a partial "
        "request. By doing so, it starves\n      the http server's resources "
        "causing Denial Of Service.\n      \n    Disclosure date: 2009-09-17\n"
        "    References:\n      "
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750\n      "
        "http://ha.ckers.org/slowloris/\n"
    )
    script3 = "No reply from server (TIMEOUT)"
    script4 = "\n"

    invalid_scripts = [script1, script3, script4]

    service = 'http-server'

    for script in invalid_scripts:
        report, valid = parse_vuln_report(script, service)
        assert len(report) == 0
        assert valid is False

    report2, valid2 = parse_vuln_report(script2, service)
    assert len(report2) == 1
    assert valid2 is True
    assert report2[0].__class__ == dict
    assert report2[0]['service'] == service
    assert report2[0]['CVE'] == "CVE-2007-6750"
    assert report2[0]['description'] == "Slowloris DOS attack"
    assert report2[0]['link'] == \
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750"
