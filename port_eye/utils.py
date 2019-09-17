"""Utils function to help run the program."""

import json
import ipaddress
import sys
import re


def read_input_file(filepath):
    """Read the content from the provided txt file.

    Hosts should be put in the file on separated lines: each line contains
    exactly one host.

    Example:
        127.0.0.1
        92.88.222.10
        8.8.8.8
        192.168.0.0/30
        ::1

    Args:
        filepath : A string representing the path of the file to read.

    Returns:
        A list containing the list of hosts from the input file as strings.

    """
    lines = []
    with open(filepath, "r") as inputfile:
        lines = inputfile.readlines()

    if sys.version_info[0] == 2:  # pragma: no cover
        lines = [line.decode("utf-8") for line in lines]

    return [line.strip() for line in lines]


def build_hosts_dict(hosts):
    """Build the list of hosts as a dict with correct IP format from list.

    Read the input hosts as strings and returnes corresponding types as
    ip_addresses or ip_networks as a dict. Invalid addresses are returned.

    Args:
        hosts: List of strings representing the hosts to be analyzed.

    Returns:
        Dictionnary containing the parsed hosts. The result has the following
        format:

        {'ipv4_hosts': [...],
         'ipv6_hosts': [...],
         'ipv4_networks': [...],
         'ipv6_networks': [...],
         'ignored': [...]}

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
        except ValueError as e:
            print(e)
            try:
                parsed_network = ipaddress.ip_network(host)
                if parsed_network.__class__ == ipaddress.IPv4Network:
                    ipv4_networks.append(parsed_network)
                else:
                    ipv6_networks.append(parsed_network)
            except ValueError:
                print(host)
                ignored.append(host)

    return {
        "ipv4_hosts": ipv4_hosts,
        "ipv6_hosts": ipv6_hosts,
        "ipv4_networks": ipv4_networks,
        "ipv6_networks": ipv6_networks,
        "ignored": ignored,
    }


def parse_duration_from_seconds(raw_duration):
    """Return a string in the xxHyyMzzs format from a number of seconds.

    Args:
        raw_duration: Float representing the number of seconds in the duration.

    Returns:
        String representing the full duration in H/M/s.

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

    Args:
        cidr_block: IPV4Network or IPV6Network object to analyze.

    Returns:
        List of hosts (IPV4Address or IPV6Address) in the network.

    """
    return list(cidr_block.hosts())


def parse_vuln_report(raw_report, service):
    """Parse a vuln report as raw string into a usable format.

    Args:
        raw_report: String representing the raw report from nmap

    Returns:
        Tuple representing the list of vulnerabilities and a boolean indicating
        whether vulnerabilities were found.

        Tuple has the format (parsed_report, valid) where parsed_report is
        a list of dicts representing vulnerabilities and valid is a bool having
        True if vulnerabilities were found.

        each dict in parsed_report has the following format:

        {'service': 'nginx', 'CVE': 'CVE-2017-1052',
         'description': 'DDOS attack', 'link': 'https://....'}

    """
    # Check if value corresponds to an error
    error_messages = [
        "No reply from server (TIMEOUT)",
        "ERROR:",
        "Script execution failed",
    ]

    for error_message in error_messages:
        if error_message in raw_report or len(raw_report) < 5:
            return ([], False)

    # If result is valid, parse into the correct format.
    vulns = []

    cve_regex = r"CVE:(CVE-\d{4}-\d{4})"
    names_regex = r"VULNERABLE:\n(.+)"
    cves = re.findall(cve_regex, raw_report)
    names = re.findall(names_regex, raw_report)

    for i in range(len(cves)):
        cve = cves[i].strip()
        link = "https://cve.mitre.org/cgi-bin/cvename.cgi?name={}".format(cve)
        name = names[i].strip()
        vulns.append(
            {"service": service, "CVE": cve, "description": name, "link": link}
        )

    return (vulns, True)


def parse_vuln_reports(full_report, service):
    """Parse a list of vuln reports and return them all into dicts.

    Args:
        raw_report: String representing the raw report from nmap

    Returns:
        Tuple representing the list of vulnerabilities and a boolean indicating
        whether vulnerabilities were found.

        Tuple has the format (parsed_report, valid) where parsed_report is
        a list of dicts representing vulnerabilities and valid is a bool having
        True if vulnerabilities were found.

        each dict in parsed_report has the following format:

        {'service': 'nginx', 'CVE': 'CVE-2017-1052',
         'description': 'DDOS attack', 'link': 'https://....'}

    """
    all_valid = False
    reports = []
    for report in full_report:
        (report, valid) = parse_vuln_report(report, service)
        all_valid = valid or all_valid
        if valid:
            reports += report
    return (reports, all_valid)
