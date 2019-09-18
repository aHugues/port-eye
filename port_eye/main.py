#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
main.py - 2019.09.17.

This is the entrypoint for the entire tool. When calling the `port-eye`
executable from the CLI, the method `main` from this file is called with
corresponding arguments and options.

Author:
    Aurélien Hugues - me@aurelienhugues.com

License:
    MIT

MIT License

Copyright (c) 2019 Aurélien Hugues

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""

import click
import ipaddress
import logging
from .utils import read_input_file
from .utils import build_hosts_dict
from .scanner import Scanner, ScannerHandler
from .export import Export
from .report import Report

# Allow using the -h argument to call the help function
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


def run_scans(
    output,
    ipv4_hosts,
    ipv6_hosts,
    ipv4_networks,
    ipv6_networks,
    mock=False,
    sudo=False,
):
    """Run scans for all the hosts and save the output as HTML.

    Args:
        output: String representing the path of the file into which report
            should be saved.
        ipv4_hosts: List of IPV4 hosts as IPV4Host objects.
        ipv6_hosts: List of IPV6 hosts as IPV6Host objects.
        ipv4_networks: List of IPV4 networks as IPV4Network objects.
        ipv6_networks: List of IPV6 networks as IPV6Network objects.
        mock: Boolean to use the mock nmap API. When True, a fake nmap API is
            used for testing purposes. Default to False.
        sudo: Boolean to run scans as a privileged user. Default to False.

    """
    logging.info("Starting scans")
    handler = ScannerHandler(
        ipv4_hosts,
        ipv6_hosts,
        ipv4_networks,
        ipv6_networks,
        mock=mock,
        sudo=sudo,
    )
    report = handler.run_scans()
    logging.info("Scans completed, starting exporting...")
    export = Export()
    export.render(report, output)
    logging.info("Done.")


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option(
    "--target",
    "-t",
    "targets",
    multiple=True,
    type=str,
    help="Target host (IPV4, IPV6 or CIDR",
)
@click.option(
    "--file",
    "-f",
    type=click.Path(exists=True),
    help="File containing the hosts to check",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(exists=False),
    required=True,
    help="Output HTML file into which the results must be stored",
)
@click.option(
    "--sudo",
    "-s",
    is_flag=True,
    help="Run nmap as privileged user for more accurate scanning",
)
@click.option(
    "--debug",
    "-d",
    is_flag=True,
    help="Display debug information to the terminal",
)
@click.option(
    "--mock",
    "-m",
    is_flag=True,
    help="Use mock API instead of really running nmap",
)
def main(targets, file, output, sudo, debug, mock):
    """Run the main application from arguments provided in the CLI."""
    # Set logging level
    log_level = "debug" if debug else "critical"
    level = getattr(logging, log_level.upper())
    logging.basicConfig(level=level)

    file_content = []

    if file is not None:
        file_content = read_input_file(file)

    hosts_dict = build_hosts_dict(list(targets) + file_content)

    parsed_ipv4 = hosts_dict["ipv4_hosts"]
    parsed_ipv6 = hosts_dict["ipv6_hosts"]
    parsed_ipv4_networks = hosts_dict["ipv4_networks"]
    parsed_ipv6_networks = hosts_dict["ipv6_networks"]

    if (
        len(
            parsed_ipv4
            + parsed_ipv6
            + parsed_ipv4_networks
            + parsed_ipv6_networks
        )
        > 0
    ):
        run_scans(
            output,
            parsed_ipv4,
            parsed_ipv6,
            parsed_ipv4_networks,
            parsed_ipv6_networks,
            mock,
            sudo,
        )
    else:
        ctx = click.get_current_context()
        print("No input host found, exiting...")
        ctx.exit()


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter # pragma: no cover
