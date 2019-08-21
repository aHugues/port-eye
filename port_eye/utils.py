import json
import ipaddress

def read_input_file_json(filepath):
    with open(filepath, 'r') as json_file:
        content = json.load(json_file)
        return content

def read_input_file_txt(filepath):
    return "Not done yet"

def parse_input_file(file_content):
    if 'ipv4' in file_content:
        parsed_ipv4 = [ipaddress.ip_address(host) for host in file_content['ipv4']]
    else:
        parsed_ipv4 = []
    if 'ipv6' in file_content:
        parsed_ipv6 = [ipaddress.ip_address(host) for host in file_content['ipv6']]
    else:
        parsed_ipv6 = []
    if 'cidr' in file_content:
        parsed_cidr = [ipaddress.ip_network(host) for host in file_content['cidr']]
    else:
        parsed_cidr = []
    return {
        'ipv4': parsed_ipv4,
        'ipv6': parsed_ipv6,
        'cidr': parsed_cidr,
    }
