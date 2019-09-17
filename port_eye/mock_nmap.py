"""Mock nmap scanner to be used for unit testing in the CI process."""

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
        """Return a host detail."""
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

        :param host: scanned host
        :param skip_ping: bool for skipping ping (default to False)
        :param ipv6: bool for creating request for ipv6 host (default to False)
        :param reachable: bool to set the host state (default to True)

        :returns global_result as dictionnary
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
                "totalhosts": "1",
            },
        }

    def reachable(self, host, sudo=False):
        """Test if the host should be reachable.

        :param host: host to test
        :param sudo: bool for running as privileged user
        
        :returns reachable as bool
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

        :param port: scanned port
        :param skip_ping: bool for skipping ping (default to False)

        :returns port_result as dictionnary
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
        """Return the hostname for an ip."""
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
        
        :param host: host to test
        
        :returns: is_vulnerable as bool
        """
        return host in ["92.222.10.88"] and port in [443]

    def build_vuln_result(self, port):
        """Build the raw result for vulnerabilities for a vulnerable host.

        :param port: port to scan


        :returns: result as dict
        """
        vuln_result = {
            443: {
                "http-aspnet-debug": "ERROR: Script execution failed (use -d to debug)",
                "http-slowloris-check": (
                    "\n  VULNERABLE:\n  Slowloris DOS "
                    "attack\n    State: LIKELY VULNERABLE\n    IDs:  "
                    "CVE:CVE-2007-6750\n      Slowloris tries to keep many "
                    "connections to the target web server open and hold\n      "
                    "them open as long as possible.  It accomplishes this by "
                    "opening connections to\n      the target web server and "
                    "sending a partial request. By doing so, it starves\n      "
                    "the http server's resources causing Denial Of Service.\n  "
                    "    \n    Disclosure date: 2009-09-17\n    References:\n  "
                    "    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750\n"
                    "      http://ha.ckers.org/slowloris/\n"
                ),
                "sslv2-drown": "\n",
            },
            -1: {
                "clamav-exec": "ERROR: Script execution failed (use -d to debug)"
            },
        }
        if port not in vuln_result:
            return vuln_result[-1]
        return vuln_result[port]

    def build_osmatch(self):
        """Build the dict for osmatch."""
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
        """Build the returned dict for ipv4 hosts

        If the skip_ping argument is set to True, results are sure to be 
        computed, but the result will have less information.

        :param host: host to scan
        :param ports: list of ports to scan (must be in range (22, 80, 443))
        :param skip_ping: bool for skipping ping (default to False)
        :param ipv: str indicating qui IPversion is used (default ipv4)
        :param sudo: bool to run as privileged user

        :returns: scan_result as dictionnary
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

        if osmatch:
            host_dict["osmatch"] = self.build_osmatch()

        result = {
            "nmap": global_infos,
            "scan": {host: PortScannerHostDict(host_dict)},
        }
        return result

    def build_result_vulnerable(self, host):
        """Build the returned dict for a vulnerable host

        :param host: host to scan

        :returns: scan_result as dictionnary
        """
        ports = [22, 80, 443]
        result = self.build_result_ipv4(host, ports)

        for port in ports:
            if self.is_vulnerable(host, port):
                port_report = self.build_vuln_result(port)
            else:
                port_report = self.build_vuln_result(-1)
            result["scan"][host]["tcp"][port]["script"] = port_report

        return result

    def build_result_unreachable(self, host, skip_ping=False):
        """Build the returned dict for an unreachable host

        :param host: host to scan
        :param skip_ping: bool for skipping ping (default to False)

        :returns: scan_result as dictionnary
        """
        global_infos = self.build_global_test_info(
            host, skip_ping, reachable=False
        )

        result = {"nmap": global_infos, "scan": {}}

        return result

    def scanstats(self):
        """
        returns scanstats structure
        {'uphosts': '3', 'timestr': 'Thu Jun  3 21:45:07 2010', 'downhosts': '253', 'totalhosts': '256', 'elapsed': '5.79'}

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
        """Scan given hosts

        Results are returned as a dictionnary that will always return the 
        same results.

        :param hosts: string for hosts as nmap use it 'scanme.nmap.org' or 
            '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as nmap use it '22,53,110,143-4564'
        :param arguments: string of arguments for nmap '-sU -sX -sC'
        :param sudo: launch nmap with sudo if True (this has no effect here)

        :returns: scan_result as dictionnary
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
            ), "Wrong type for [ports], should be a string [was {0}]".format(
                type(ports)
            )  # noqa
            assert type(arguments) in (
                str,
                unicode,
            ), "Wrong type for [arguments], should be a string [was {0}]".format(
                type(arguments)
            )  # noqa
        else:  # pragma: no cover
            assert (
                type(hosts) is str
            ), "Wrong type for [hosts], should be a string [was {0}]".format(
                type(hosts)
            )  # noqa
            assert type(ports) in (
                str,
                type(None),
            ), "Wrong type for [ports], should be a string [was {0}]".format(
                type(ports)
            )  # noqa
            assert (
                type(arguments) is str
            ), "Wrong type for [arguments], should be a string [was {0}]".format(
                type(arguments)
            )  # noqa

        skip_ping = "Pn" in arguments
        ipv = "ipv6" if "6" in arguments else "ipv4"

        osmatch = "-O" in arguments

        ports = [22] if hosts == "127.0.0.1" else [22, 80, 443]

        if "--script vuln" in arguments and self.reachable(hosts, sudo):
            result = self.build_result_vulnerable(hosts)
        else:
            if self.reachable(hosts, sudo):
                result = self.build_result_ipv4(
                    hosts, ports, skip_ping, ipv=ipv, osmatch=osmatch
                )
            else:
                result = self.build_result_unreachable(hosts, skip_ping)

        self._scan_result = result
        return result
