#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
mock_nmap.py - 2019.09.17.

This file provides a fake API reproducing the behavior of python-nmap but not
using nmap. This is used only for testing purposes in order to improve testing
speed and reproductibility.

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

import sys
import logging
from nmap import PortScannerHostDict


class MockPortScanner:
    """MockPortScanner allows to use a mock version of nmap from Python."""

    def __init__(self):
        """Initialize MockPortScanner module."""
        logging.debug("Creating MockPortScanner")
        self._scan_result = {}

    def __getitem__(self, host):
        """Allow to get information from a host as if the Scanner as in a dict.

        This methods allows the user to treat the Scanner as a dictionary and
        access results for a host with scanner[host].

        """
        if sys.version_info[0] == 2:  # pragma: no cover
            assert type(host) in (
                str,
                unicode,
            ), "Wrong type for [host], should be a string [was {0}]".format(
                type(host)
            )
        else:  # pragma: no cover
            assert (
                type(host) is str
            ), "Wrong type for [host], should be a string [was {0}]".format(
                type(host)
            )
        return self._scan_result["scan"][host]

    def build_global_test_info(
        self, host, skip_ping=False, ipv6=False, reachable=True
    ):
        """Build the command_line and scanstats parts of the response.

        Args:
            host: Host to scan
            skip_ping: bool for skipping ping (default to False)
            ipv6: bool for creating request for ipv6 host (default to False)
            reachable: bool to set the host state (default to True)

        Returns:
            Dictionnary containing the global results for scan with the
            following format:

            {
                "command_line": "nmap -Pn 127.0.0.1",
                "scanstats": {
                    "timestr": "Sun Sep  8 10:21:46 2019",
                    "elapsed": 10.7,
                    "uphosts": "2",
                    "downhosts": "1",
                    "totalhosts": "3",
                },
            }

        """
        ip_argument = "6" if ipv6 else ""
        skip_argument = "Pn" if skip_ping else "sV"
        command_line = "nmap -oX -{} -{} {}".format(
            ip_argument, skip_argument, host
        )
        elapsed = "10.7" if skip_ping else "4.2"
        downhosts = "0" if reachable else "1"
        uphosts = "1" if reachable else "0"

        return {
            "command_line": command_line,
            "scanstats": {
                "timestr": "Sun Sep  8 10:21:46 2019",
                "elapsed": elapsed,
                "uphosts": uphosts,
                "downhosts": downhosts,
                "totalhosts": int(uphosts) + int(downhosts),
            },
        }

    def reachable(self, host, sudo=False):
        """Test if the host should be reachable.

        Some hosts are typically unreachable when not using nmap as a
        privileged user, this behavior is simulated by having some hosts only
        be reachable when sudo is set to True.

        Args:
            host: string representing the host to test.
            sudo: bool for running as privileged user, default to False.

        Returns:
            True when the host is reachable with provided parameters.

        """
        reachable_full = [
            "127.0.0.1",
            "::1",
            "92.222.10.88",
            "2a01:e0a:129:5ed0:211:32ff:fe2d:68da",
        ]
        reachable_sudo = ["82.64.28.100"]

        if sudo:
            return host in (reachable_full + reachable_sudo)
        else:
            return host in reachable_full

    def build_tcp_result(self, port, skip_ping=False):
        """Build the result for a port.

        Build and returns a dict containing the scan results for a port. Due to
        the nature of this module, only ports 22, 80 and 443 are considered.

        A skip_ping option is available to simulate results when skipping ping
        requests. In this case less results are available.

        Args:
            port: An integer representing the port to scan (22, 80 or 443).
            skip_ping: A bool to allow skipping ping requests (default False).

        Returns:
            A dict representing the scanning results for the port. Example:

            {
                "state": "open",
                "reason": "syn-ack",
                "name": "ssh",
                "product": "OpenSSH",
                "version": "7.6p1 Ubuntu 4ubuntu0.3",
                "extrainfo": "Ubuntu Linux; protocol 2.0",
                "conf": "10",
                "cpe": "cpe:/o:linux:linux_kernel",
            }

        Raises:
            KeyError: Provided port is not in the correct range.

        """
        if port not in [22, 80, 443]:
            raise KeyError("Port not in range (22, 80, 443)")

        else:
            additionnal_infos = ["product", "version", "extrainfo", "cpe"]
            ports_result = {
                22: {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "7.6p1 Ubuntu 4ubuntu0.3",
                    "extrainfo": "Ubuntu Linux; protocol 2.0",
                    "conf": "10",
                    "cpe": "cpe:/o:linux:linux_kernel",
                },
                80: {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "http",
                    "product": "nginx",
                    "version": "",
                    "extrainfo": "",
                    "conf": "10",
                    "cpe": "cpe:/a:igor_sysoev:nginx",
                },
                443: {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "http",
                    "product": "nginx",
                    "version": "",
                    "extrainfo": "",
                    "conf": "10",
                    "cpe": "cpe:/a:igor_sysoev:nginx",
                },
            }

            # Remove additionnal info if ping is skipped
            if skip_ping:
                for info in additionnal_infos:
                    ports_result[port][info] = ""
                ports_result[port]["conf"] = "3"

            return ports_result[port]

    def get_hostname(self, host):
        """Return the hostname for an ip.

        Args:
            host: A string representing the IP Address of the host.

        Raises:
            KeyError: Raised when the provided IP has no associated hostname.

        """
        hostnames = {
            "127.0.0.1": "localhost",
            "92.222.10.88": "example.com",
            "::1": "localhost",
            "2a01:e0a:129:5ed0:211:32ff:fe2d:68da": "acme.me",
            "82.64.28.100": "acne.bad",
        }
        return hostnames[host]

    def is_vulnerable(self, host, port):
        """Return True if a vulnerability exists for the host.

        Args:
            host: A string representing the IP Address of the host.

        """
        return host in ["92.222.10.88"] and port in [443]

    def build_vuln_result(self, port):
        """Return a Dict containing the vulnerability informations.

        Return a dict containing the vulnerabilities found on the port given in
        parameters.

        Params:
            port: An int representing the port to be scanned.

        Returns:
            A dict containing the raw vulnerabilities found for a given host.
            The key represents the name of the script used and the value is a
            raw string representing the output from the nmap script.

        """
        vuln_result = {
            443: {
                "http-aspnet-debug": (
                    "ERROR: Script execution failed (use -d to debug)"
                ),
                "http-slowloris-check": (
                    "\n  VULNERABLE:\n  Slowloris DOS "
                    "attack\n    State: LIKELY VULNERABLE\n    IDs:  "
                    "CVE:CVE-2007-6750\n      Slowloris tries to keep many "
                    "connections to the target web server open and hold\n     "
                    " them open as long as possible.  It accomplishes this by "
                    "opening connections to\n      the target web server and  "
                    "sending a partial request. By doing so, it starves\n     "
                    "the http server's resources causing Denial Of Service.\n "
                    "     \n    Disclosure date: 2009-09-17\n    References:\n"
                    "      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"
                    "2007-6750\n      http://ha.ckers.org/slowloris/\n"
                ),
                "sslv2-drown": "\n",
            },
            -1: {
                "clamav-exec": (
                    "ERROR: Script execution failed (use -d to debug)"
                )
            },
        }
        if port not in vuln_result:
            return vuln_result[-1]
        return vuln_result[port]
    
    def has_mac(self, host):
        """Return True if the given IP address is associated to a MAC."""
        return host == '127.0.0.1'

    def build_osmatch(self):
        """Return a dict corresponding to the operating system match.

        Returns:
            A dict containing the name of the OS and the accuracy on its
            prediction (between 0 and 100)

            Example:
            {
                "name": "Linux 3.7 - 3.10",
                "accuracy": "100"
            }

        """
        osmatch_dict = [
            {"name": "linux 3.7 - 3.10", "accuracy": "100"},
            {"name": "linux 3.4 - 3.6", "accuracy": "95"},
        ]
        return osmatch_dict

    def build_result_ipv4(
        self,
        host,
        ports,
        skip_ping=False,
        ipv="ipv4",
        sudo=False,
        osmatch=False,
    ):
        """Build the returned dict for ipv4 hosts.

        If the skip_ping argument is set to True, results are sure to be
        computed, but the result will have less information.

        Args:
            host: Host to scan.
            ports: List of ports to scan (must be in range (22, 80, 443)).
            skip_ping: Bool for skipping ping (default to False).
            ipv: Str indicating qui IPversion is used (default ipv4).
            sudo: Bool to run as privileged user.
            osmatch: Bool to match the target OS.

        Returns:
            A dict containing the results for the given host. Results for each
            port are described in build_tcp_result. Example:
            {
                "scan:" {
                    "hostnames": [{"name": 'host', 'type': 'client}, {...}],
                    "addresses": {"ipv4": "127.0.0.1"},
                    "status": {"state": "up", "reason": "conn-refused"},
                    "osmatch": {...},
                    "tcp": {
                        443: {...},
                        22: {...}
                    }
                },
                "nmap": {...}
            }

        """
        global_infos = self.build_global_test_info(host, skip_ping)
        tcp_dict = {}
        hostname = self.get_hostname(host)
        for port in ports:
            tcp_dict[port] = self.build_tcp_result(port, skip_ping)

        host_dict = {
            "hostnames": [{"name": hostname, "type": "PTR"}],
            "addresses": {ipv: host},
            "status": {"state": "up", "reason": "conn-refused"},
            "tcp": tcp_dict,
        }

        if self.has_mac(host):
            host_dict['addresses']['mac'] = "9C:B6:D0:B7:7B:9F"

        if osmatch:
            host_dict["osmatch"] = self.build_osmatch()

        result = {
            "nmap": global_infos,
            "scan": {host: PortScannerHostDict(host_dict)},
        }
        return result

    def build_result_vulnerable(
        self,
        host,
        ports,
        skip_ping=False,
        ipv="ipv4",
        sudo=False,
        osmatch=False,
    ):
        """Build the returned dict for a vulnerable host.

        Results are the normal results returned by build_result_ipv4 with added
        data from found vulnerabilities.

        Args:
            host: Host to scan.
            ports: List of ports to scan (must be in range (22, 80, 443)).
            skip_ping: Bool for skipping ping (default to False).
            ipv: Str indicating qui IPversion is used (default ipv4).
            sudo: Bool to run as privileged user.
            osmatch: Bool to match the target OS.

        Returns:
            A dict representing the scan information including vulnerabilities.

        """
        ports = [22, 80, 443]
        result = self.build_result_ipv4(
            host, ports, skip_ping, sudo=sudo, osmatch=osmatch
        )

        for port in ports:
            if self.is_vulnerable(host, port):
                port_report = self.build_vuln_result(port)
            else:
                port_report = self.build_vuln_result(-1)
            result["scan"][host]["tcp"][port]["script"] = port_report

        return result

    def build_result_unreachable(self, host, skip_ping=False):
        """Build the returned dict for an unreachable host.

        Args:
            host: A string representing the host to scan.
            skip_ping: bool for skipping ping (default to False)

        Returns:
            A dict representing the scan information for the host.

        """
        global_infos = self.build_global_test_info(
            host, skip_ping, reachable=False
        )

        result = {"nmap": global_infos, "scan": {}}

        return result

    def scanstats(self):
        """Return scanstats structure.

        {
            'uphosts': '3',
            'timestr': 'Thu Jun  3 21:45:07 2010',
            'downhosts': '253',
            'totalhosts': '256',
            'elapsed': '5.79'
        }

        Raises:
            may raise AssertionError exception if called before scanning

        """
        assert (
            "nmap" in self._scan_result
        ), "Do a scan before trying to get result !"
        assert (
            "scanstats" in self._scan_result["nmap"]
        ), "Do a scan before trying to get result !"

        return self._scan_result["nmap"]["scanstats"]

    def scan(self, hosts="127.0.0.1", ports=None, arguments="-sV", sudo=False):
        """Scan given hosts.

        Results are returned as a dictionnary that will always return the
        same results.

        Args:
            hosts: string for hosts as nmap use it 'scanme.nmap.org' or
                '198.116.0-255.1-127' or '216.163.128.20/20'
            ports: string for ports as nmap use it '22,53,110,143-4564'
            arguments: string of arguments for nmap '-sU -sX -sC'
            sudo: launch nmap with sudo if True (this has no effect here)

        Returns:
            A dict representing the scan information for the host.

        """
        if sys.version_info[0] == 2:  # pragma: no cover
            assert type(hosts) in (
                str,
                unicode,
            ), "Wrong type for [hosts], should be a string [was {0}]".format(
                type(hosts)
            )  # noqa
            assert type(ports) in (
                str,
                unicode,
                type(None),
            ), "Wrong type for [ports], should be string [was {0}]".format(
                type(ports)
            )  # noqa
            assert type(arguments) in (
                str,
                unicode,
            ), "Wrong type for [arguments], should be string [was {0}]".format(
                type(arguments)
            )  # noqa
        else:  # pragma: no cover
            assert (
                type(hosts) is str
            ), "Wrong type for [hosts], should be string [was {0}]".format(
                type(hosts)
            )  # noqa
            assert type(ports) in (
                str,
                type(None),
            ), "Wrong type for [ports], should be string [was {0}]".format(
                type(ports)
            )  # noqa
            assert (
                type(arguments) is str
            ), "Wrong type for [arguments], should be string [was {0}]".format(
                type(arguments)
            )  # noqa

        skip_ping = "Pn" in arguments
        ipv = "ipv6" if "6" in arguments else "ipv4"

        osmatch = "-O" in arguments

        ports = [22] if hosts == "127.0.0.1" else [22, 80, 443]

        if "--script vuln" in arguments and self.reachable(
            hosts, sudo or skip_ping
        ):
            result = self.build_result_vulnerable(
                hosts, ports, skip_ping, ipv=ipv, osmatch=osmatch, sudo=sudo
            )
        else:
            if self.reachable(hosts, sudo or skip_ping):
                result = self.build_result_ipv4(
                    hosts,
                    ports,
                    skip_ping,
                    ipv=ipv,
                    osmatch=osmatch,
                    sudo=sudo,
                )
            else:
                result = self.build_result_unreachable(hosts, skip_ping)

        self._scan_result = result
        return result
