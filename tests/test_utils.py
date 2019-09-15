"""Test functions from the utils module."""

import pytest
from ipaddress import IPv4Address, IPv6Address, IPv4Network, ip_network

from port_eye.utils import read_input_file
from port_eye.utils import parse_duration_from_seconds
from port_eye.utils import get_hosts_from_cidr
from port_eye.utils import build_hosts_dict


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

