"""Utils function to help run the program."""

import json
import ipaddress


def read_input_file_json(filepath):
    """Read the content from the provided JSON file.

    # Arguments
    filepath (str): Path of the JSON file to read.

    # Returns
    content (dict): Dict object containing the hosts and cidr to be scanned.
    """
    with open(filepath, 'r') as json_file:
        content = json.load(json_file)
        return content


def read_input_file_txt(filepath):
    """Read the content from the provided txt file.

    # Arguments
    filepath (str): Path of the txt file to read.

    # Returns
    content (dict): Dict object containing the hosts and cidr to be scanned.
    """
    return "Not done yet"


def parse_input_file(file_content):
    """Parse the content read from file or CLI into correct IP format.

    Read the provided dictionnary and return a dictionnary composed of
    `ip_address` and `ip_network` objects from the `ipaddress` library. A
    `ValueError` exception is raised when a value has not a correct ipv4/ipv6
    or CIDR format.

    # Arguments
    file_content (dict): Dict containing the hosts and cidr to be scanned.

    # Returns:
    parsed_content (dict): Dict composed of parsed objects to be scanned.
    """
    if 'ipv4' in file_content:
        parsed_ipv4 = [
            ipaddress.ip_address(host) for host in file_content['ipv4']]
    else:
        parsed_ipv4 = []
    if 'ipv6' in file_content:
        parsed_ipv6 = [
            ipaddress.ip_address(host) for host in file_content['ipv6']]
    else:
        parsed_ipv6 = []
    if 'cidr' in file_content:
        parsed_cidr = [
            ipaddress.ip_network(host) for host in file_content['cidr']]
    else:
        parsed_cidr = []
    return {
        'ipv4': parsed_ipv4,
        'ipv6': parsed_ipv6,
        'cidr': parsed_cidr,
    }
