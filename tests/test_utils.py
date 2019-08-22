import pytest

from port_eye.utils import read_input_file_json
from port_eye.utils import read_input_file_txt
from port_eye.utils import parse_input_file


def test_reading_json_file():
    content = read_input_file_json("tests/json_test.json")
    assert 'ipv4' in content
    assert 'cidr' in content
    assert 'ipv6' in content
    assert 'ipv8' not in content


def test_reading_json_file_errored():
    content = read_input_file_json("tests/json_test_error.json")
    assert 'ipv4' in content
    assert 'cidr' in content
    assert 'ipv6' in content
    assert 'ipv8' not in content


def test_reading_txt_file():
    content = read_input_file_txt("fake_filepath")
    assert content == "Not done yet"


def test_parsing_with_error():
    content = read_input_file_json("tests/json_test_error.json")
    with pytest.raises(ValueError):
        parse_input_file(content)
