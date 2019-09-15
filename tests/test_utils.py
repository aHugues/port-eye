"""Test functions from the utils module."""

import pytest
from ipaddress import IPv4Address, IPv6Address, IPv4Network, ip_network

from port_eye.utils import read_input_file_json
from port_eye.utils import read_input_file_txt
from port_eye.utils import parse_input_file
from port_eye.utils import parse_duration_from_seconds
from port_eye.utils import get_hosts_from_cidr


def test_reading_json_file():
    """Test reading an input JSON file."""
    content = read_input_file_json("tests/json_test.json")
    assert 'ipv4' in content
    assert 'cidr' in content
    assert 'ipv6' in content
    assert 'ipv8' not in content


def test_reading_json_file_errored():
    """Test reading an input JSON file even with incorrect data format."""
    content = read_input_file_json("tests/json_test_error.json")
    assert 'ipv4' in content
    assert 'cidr' in content
    assert 'ipv6' in content
    assert 'ipv8' not in content


def test_reading_txt_file():
    """NOT YET IMPLEMENTED, test reading an input TXT file."""
    content = read_input_file_txt("fake_filepath")
    assert content == "Not done yet"


def test_parsing_with_error():
    """Test that format error are caught when parsing."""
    content = read_input_file_json("tests/json_test_error.json")
    with pytest.raises(ValueError):
        parse_input_file(content)


def test_correct_parsing_normal():
    """Test that content are correctly parsed."""
    content = read_input_file_json("tests/json_test.json")
    parsed_content = parse_input_file(content)

    # Test that all content is present
    assert "ipv4" in parsed_content
    assert "ipv6" in parsed_content
    assert "cidr" in parsed_content

    # Test that the elements in dict have the correct format
    for host in parsed_content["ipv4"]:
        assert type(host) == IPv4Address
    for host in parsed_content["ipv6"]:
        assert type(host) == IPv6Address
    for network in parsed_content["cidr"]:
        assert type(network) == IPv4Network


def test_file_parsing_no_ipv4():
    """Test that content is parsed when no IPV4 is present."""
    content = read_input_file_json("tests/json_test.json")
    new_content = {
        'ipv6': content['ipv6'],
        'cidr': content['cidr']
    }

    parsed_content = parse_input_file(new_content)

    assert parsed_content["ipv4"] == []
    for host in parsed_content["ipv6"]:
        assert type(host) == IPv6Address
    for network in parsed_content["cidr"]:
        assert type(network) == IPv4Network


def test_file_parsing_no_ipv6():
    """Test that content is parsed when no IPV6 is present."""
    content = read_input_file_json("tests/json_test.json")
    new_content = {
        'ipv4': content['ipv4'],
        'cidr': content['cidr']
    }

    parsed_content = parse_input_file(new_content)
    assert parsed_content["ipv6"] == []
    for host in parsed_content["ipv4"]:
        assert type(host) == IPv4Address
    for network in parsed_content["cidr"]:
        assert type(network) == IPv4Network


def test_file_parsing_no_cidr():
    """Test that content is parsed when no CIDR block is present."""
    content = read_input_file_json("tests/json_test.json")
    new_content = {
        'ipv4': content['ipv4'],
        'ipv6': content['ipv6']
    }

    parsed_content = parse_input_file(new_content)
    assert parsed_content["cidr"] == []
    for host in parsed_content["ipv4"]:
        assert type(host) == IPv4Address
    for network in parsed_content["ipv6"]:
        assert type(network) == IPv6Address


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

