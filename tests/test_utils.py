"""Test functions from the utils module."""

import pytest
from ipaddress import IPv4Address, IPv6Address, IPv4Network

from port_eye.utils import read_input_file_json
from port_eye.utils import read_input_file_txt
from port_eye.utils import parse_input_file
from port_eye.utils import parse_duration_from_seconds


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


def test_correct_parsing():
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


