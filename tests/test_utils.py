"""Test functions from the utils module."""

import pytest
from ipaddress import IPv4Address, IPv6Address, IPv4Network

from port_eye.utils import read_input_file_json
from port_eye.utils import read_input_file_txt
from port_eye.utils import parse_input_file


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


