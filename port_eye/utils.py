"""Utils function to help run the program."""

import json
import ipaddress



def read_input_file(filepath):
    """Read the content from the provided txt file.

    Hosts should be put in the file on separated lines: each line contains 
    exactly one host.

    Parameters
    ----------
    filepath : str
        Path of the txt file to read.

    Returns
    -------
        content : dict
            Dict object containing the hosts and cidr to be scanned.
    
    See Also
    --------
    this_is_a_test: This is a test function.
    """
    lines = []
    with open(filepath, 'r') as inputfile:
        lines = inputfile.readlines()
    return [line.strip() for line in lines]


def build_hosts_dict(hosts):
    """Build the list of hosts as a dict with correct IP format from list.

    Read the input hosts as strings and returnes corresponding types as 
    ip_addresses or ip_networks as a dict. Invalid addresses are returned 

    ### Arguments
    - hosts (List of str): List of hosts to be parsed

    ### Returns
    - parsed_hosts (dict): Dict of the parsed hosts
    """

    ipv4_hosts = []
    ipv6_hosts = []
    ipv4_networks = []
    ipv6_networks = []
    ignored = []

    for host in hosts:
        try:
            parsed_host = ipaddress.ip_address(host)
            if parsed_host.__class__ == ipaddress.IPv4Address:
                ipv4_hosts.append(parsed_host)
            else:
                ipv6_hosts.append(parsed_host)
        except ValueError:
            try:
                parsed_network = ipaddress.ip_network(host)
                if parsed_network.__class__ == ipaddress.IPv4Network:
                    ipv4_networks.append(parsed_network)
                else:
                    ipv6_networks.append(parsed_network)
            except ValueError:
                ignored.append(host)
    
    return {
        'ipv4_hosts': ipv4_hosts,
        'ipv6_hosts': ipv6_hosts,
        'ipv4_networks': ipv4_networks,
        'ipv6_networks': ipv6_networks,
        'ignored': ignored
    }


def parse_duration_from_seconds(raw_duration):
    """Return a string in the xxHyyMzzs format from a number of seconds.
    
    ### Arguments
    - raw_duration (float): Number of seconds in the duration
    
    ### Returns
    - duration (str): String representing the full duration in H/M/s
    """

    if raw_duration < 0:
        raise ValueError("Duration should be positive.")
    else:
        seconds = int(raw_duration % 60)
        minutes = int(((raw_duration - seconds) / 60) % 60)
        hours = int((raw_duration - seconds - (minutes * 60)) / 3600)

        result = "{}s".format(seconds)
        if minutes > 0 or hours > 0:
            result = "{}m".format(minutes) + result
        if hours > 0:
            result = "{}h".format(hours) + result

        return result


def get_hosts_from_cidr(cidr_block):
    """Get the list of hosts inside a cidr block.
    
    # Arguments
    cidr_block (IPV4Network): CIDR block to analyze.
    
    # Returns
    hosts (List of IPV4Hosts): List of hosts in the network.
    """
    return list(cidr_block.hosts())