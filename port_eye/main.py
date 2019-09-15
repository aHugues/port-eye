"""Entrypoint for the application."""

import click
import ipaddress
import logging
from .utils import read_input_file_json
from .utils import parse_input_file
from .utils import build_hosts_dict
from .scanner import Scanner, ScannerHandler
from .export import Export
from .report import Report

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


def run_scans(output, ipv4_hosts, ipv6_hosts, cidr_blocks, mock=False):
    """Run scans for all the hosts."""

    logging.info("Starting scans")
    handler = ScannerHandler(ipv4_hosts, ipv6_hosts, cidr_blocks, mock=mock)
    report = handler.run_scans()
    logging.info("Scans completed, starting exporting...")
    export = Export()
    export.render(report, output)
    logging.info("Done.")


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option(
    '--target', '-t', 'targets',
    multiple=True,
    type=str,
    help="Target host (IPV4, IPV6 or CIDR")
@click.option(
    '--file', '-f',
    type=click.Path(exists=True),
    help="File containing the hosts to check")
@click.option(
    '--logging', '-l', 'log_level',
    type=click.Choice(['debug', 'info', 'warning', 'error']),
    default='warning',
    help="Select logging level in the terminal",)
@click.option(
    '--mock', '-m',
    is_flag=True,
    help="Use mock API instead of really running nmap")
@click.option(
    '--output', '-o',
    type=click.Path(exists=False), required=True,
    help="Output HTML file into which the results must be stored")
def main(targets, file, log_level, mock, output):
    """Run the main application from arguments provided in the CLI."""
    # Set logging level
    level = getattr(logging, log_level.upper())
    logging.basicConfig(level=level)

    hosts_dict = build_hosts_dict(targets)

    parsed_ipv4 = hosts_dict['ipv4_hosts']
    logging.debug("Found {} IPV4 from CLI.".format(len(parsed_ipv4)))

    parsed_ipv6 = hosts_dict['ipv6_hosts']
    logging.debug("Found {} IPV6 from CLI.".format(len(parsed_ipv6)))

    parsed_cidr = hosts_dict['ipv4_networks']
    logging.debug("Found {} CIDR from CLI.".format(len(parsed_cidr)))

    if file is not None:
        file_extension = file.split('.')[-1]
        if file_extension == 'json':
            logging.debug("Reading input JSON file.")
            content = read_input_file_json(file)
        else:
            content = {}
            click.echo("Unsupported input file type", err=True)
            ctx = click.get_current_context()
            ctx.exit(2)

        parsed_file = parse_input_file(content)
    
        parsed_ipv4 += parsed_file['ipv4']
        parsed_ipv6 += parsed_file['ipv6']
        parsed_cidr += parsed_file['cidr']
    
    if len(parsed_ipv4 + parsed_ipv6 + parsed_cidr) > 0:
        logging.debug("Running for {} IPV4, {} IPV6 and {} CIDR blocks.".format(
            len(parsed_ipv4), len(parsed_ipv6), len(parsed_cidr)
        ))
        run_scans(output, parsed_ipv4, parsed_ipv6, parsed_cidr, mock)
    else:
        logging.debug("No input host found, exiting with help.")
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        ctx.exit()


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter # pragma: no cover
