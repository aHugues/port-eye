"""Entrypoint for the application."""

import click
import ipaddress
from .utils import read_input_file_json
from .utils import parse_input_file
from .scanner import Scanner
from .export import Export
from .report import Report


def run_scans(host, output):
    """Run scans for a single host."""

    scanner = Scanner(host)
    if (scanner.is_reachable()):
        scanner.perform_scan()
        (result, duration) = scanner.extract_host_report()
        full_report = Report(duration, [result])
        export = Export()
        export.render(full_report, output)
        print(result)
    else:
        print("Host unreachable")


@click.command()
@click.option(
    '--ipv4', '-h4',
    multiple=True,
    type=str,
    help="IPV4 address of host to check")
@click.option(
    '--ipv6', '-h6',
    multiple=True,
    type=str,
    help="IPV6 address of host to check")
@click.option(
    '--cidr', '-c',
    multiple=True,
    type=str,
    help="CIDR block of hosts to check")
@click.option(
    '--file', '-f',
    type=click.Path(exists=True),
    help="File containing the hosts to check")
@click.option(
    '--verbose', '-v',
    is_flag=True,
    help="Display verbose logging in the terminal",)
@click.option(
    '--output', '-o',
    type=click.Path(exists=False),
    help="Output HTML file into which the results must be stored")
def main(ipv4, ipv6, cidr, file, verbose, output):
    """Run the main application from arguments provided in the CLI."""
    parsed_ipv4 = [ipaddress.ip_address(address) for address in ipv4]
    parsed_ipv6 = [ipaddress.ip_address(address) for address in ipv6]
    parsed_cidr = [ipaddress.ip_network(address) for address in cidr]

    if file is not None:
        file_extension = file.split('.')[-1]
        if file_extension == 'json':
            content = read_input_file_json(file)
        else:
            print("Not available yet")
            content = {}
        parsed_file = parse_input_file(content)
    
    for host in parsed_ipv4:
        run_scans(host, output)


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
