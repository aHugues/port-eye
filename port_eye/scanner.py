#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
scanner - 2019.09.17.

This file provides a wrapper around nmap to handle all the scanning operations
at a higher level, including testing for vulnerabilities, extracting relevant
information, and returning the result in a usable format.

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

import ipaddress
import nmap
from .mock_nmap import MockPortScanner
from .report import PortReport, HostReport, Report, Vulnerability
from .utils import get_hosts_from_cidr, parse_vuln_reports
import sys
import time
import threading
import logging
from blessings import Terminal

if sys.version_info[0] == 2:  # pragma: no cover
    from Queue import Queue
else:  # pragma: no cover
    from queue import Queue


class Scanner:
    """Handle the scanning operations.

    Attributes:
        host: A string representing the target host IP address.
        raw_host: A IPV4Address or IPV6Address representing the target.
        scanner: A nmap scanner or a MockNmapScanner depending on the
            parameters.
        vulnerabilities: A list of dict representing found vulnerabilities.
        reachable: A boolean indicating if the host is reachable.
        is_ipv6: A boolean indicating if the host is using an IPV6 address.
        sudo: Boolean to run scans as a privileged user. Default to False.

    """

    def __init__(self, host, is_ipv6=False, mock=False, sudo=False):
        """Init a Scanner.

        Args:
            host: An IPV4Address or IPV6Address representing the target.
            is_ipv6: A boolean indicating if the target is using IPV6, default
                to False
            mock: A boolean indicating if the scanner should use a fake API
                instead of using nmap to perform the scans. Default to False.
            sudo: Boolean to run scans as a privileged user. Default to False.

        """
        logging.debug("Creating Scanner for host {}".format(host))
        self.raw_host = host
        self.host = str(host)
        if mock:
            self.scanner = MockPortScanner()
        else:
            self.scanner = nmap.PortScanner()
        self.vulnerabilities = {}
        self.reachable = False
        self.is_ipv6 = is_ipv6
        self.sudo = sudo

        if type(host) not in [
            ipaddress.IPv4Address,
            ipaddress.IPv6Address,
            ipaddress.IPv4Network,
            ipaddress.IPv6Network,
        ]:
            raise TypeError("Invalid type for host")

    def run_ping_test(self):
        """Run a simple ping test to check is the host is reachable.
        
        Returns:
            True if the ping test is successful.

        """
        logging.debug("Testing if host {} is reachable...".format(self.host))
        argument = "-sn --host-timeout 10s"
        if self.is_ipv6:
            argument += " -6"
        self.scanner.scan(self.host, arguments=argument, sudo=self.sudo)
        try:
            self.reachable = True
            logging.debug("Test finished for Host {}".format(self.host))
            return self.scanner[self.host].state() == "up"
        except KeyError:
            self.reachable = False
            logging.debug("Host {} is unreachable".format(self.host))
            return False

    def is_local(self):
        """Return True if the host has a private IP."""
        return self.raw_host.is_private

    def perform_scan(self, skip_ping=False):
        """Perform nmap scanning on selected host.

        Args:
            skip_ping: A bool indicating if the ping request are to be skipped.
                This is usually useless when running as privileged user, but
                can solve hosts inacurrately detected as down when running as
                unprivileged user. Less information is however gathered.
        
        More information can be gathered when scanner is ran as sudo: host
        detection can only be performed as a privileged user, and some ping
        requests can be blocked when using as unprivileged user.

        """
        arguments = "-Pn --script vuln" if skip_ping else "-sV --script vuln"
        if self.sudo:
            arguments += " -O"
        if self.is_ipv6:
            arguments += " -6"
        self.scanner.scan(self.host, arguments=arguments, sudo=self.sudo)

    def find_vulnerabilities(self):
        """Extract vulnerabilities from scan."""
        try:
            scripts_results = self.scanner[self.host]
            for port in scripts_results["tcp"]:
                vulns_report = scripts_results["tcp"][port]["script"]
                raw_vulnerabilities = [
                    vulns_report[key] for key in vulns_report
                ]
                vulnerabilities = []
                (vulnerabilities_dict, vulnerable) = parse_vuln_reports(
                    raw_vulnerabilities,
                    scripts_results["tcp"][port]["product"],
                )
                if vulnerable:
                    for vulnerability_dict in vulnerabilities_dict:
                        vulnerability = Vulnerability(
                            vulnerability_dict["service"],
                            vulnerability_dict["CVE"],
                            vulnerability_dict["description"],
                            vulnerability_dict["link"],
                        )
                        vulnerabilities.append(vulnerability)
                self.vulnerabilities[port] = vulnerabilities
        except KeyError:
            pass

    def extract_ports(self, protocol):
        """Extract the scanned ports from the host.

        Args:
            protocol: A string representing the protocol to use (tcp or udp).

        Returns:
            A list of PortReport objects representing the ports scanned for the
            host using the provided protocol.

        """
        lowered_protocol = protocol.lower()
        if lowered_protocol not in ["tcp", "udp"]:
            raise ValueError("Protocol should be 'tcp' or 'udp'")

        ports = []
        try:
            ports_list = list(self.scanner[self.host][lowered_protocol])
            for port in ports_list:
                port_details = self.scanner[self.host][lowered_protocol][port]
                if port in self.vulnerabilities:
                    port_vulns = self.vulnerabilities[port]
                else:
                    port_vulns = []
                reported_port = PortReport(
                    port,
                    port_details["state"],
                    lowered_protocol == "tcp",
                    lowered_protocol == "udp",
                    port_details["product"],
                    port_details["version"],
                    port_vulns,
                )
                ports.append(reported_port)

        except KeyError:
            pass

        finally:
            return ports

    def extract_host_report(self, reachable=True):
        """Extract the complete report from the host.

        If the host is down, it must be put in the arguments as it allows the
        scanner not to look for unexisting information.

        Args:
            reachable: A boolean indicating if the host is up or down.

        """
        duration = float(self.scanner.scanstats()["elapsed"])

        if (
            reachable
            and self.scanner[self.host]["status"]["reason"] != "user-set"
        ):
            hostname = self.scanner[self.host]["hostnames"][0]["name"]
            if 'mac' in self.scanner[self.host]['addresses']:
                mac = self.scanner[self.host]['addresses']['mac']
            else:
                mac = ''
            state = "up"
            ports = self.extract_ports("tcp") + self.extract_ports("udp")
            operating_system = ""
            operating_system_accuracy = ""

            if (
                "osmatch" in self.scanner[self.host]
                and len(self.scanner[self.host]["osmatch"]) > 0
            ):
                operating_system_dict = self.scanner[self.host]["osmatch"]
                operating_system = operating_system_dict[0]["name"]
                operating_system_accuracy = operating_system_dict[0][
                    "accuracy"
                ]

        else:
            hostname = ""
            mac = ""
            state = "down"
            ports = []
            operating_system = ""
            operating_system_accuracy = ""

        host_report = HostReport(
            self.host,
            hostname,
            mac,
            state,
            ports,
            duration,
            operating_system,
            operating_system_accuracy,
        )

        return host_report


class ScannerHandler:
    """Handle the scanning for several targeted hosts.

    This class allows several scans to be ran concurrently in order to improve
    the scanning spee.

    Attributes:
        ipv4_hosts: A list of IPV4Address representing IPV4 hosts
        ipv6_hosts: A list of IPV6Address representing IPV6 hosts
        ipv4_networks: A list of IPV4Network representing IPV4 networks
        ipv6_networks: A list of IPV6Network representing IPV6 networks
        mock: Boolean to use the mock nmap API. When True, a fake nmap API is
            used for testing purposes. Default to False.
        sudo: Boolean to run scans as a privileged user. Default to False.

    """

    def __init__(
        self,
        ipv4_hosts,
        ipv6_hosts,
        ipv4_networks,
        ipv6_networks,
        mock=False,
        sudo=False,
    ):
        """Init a ScannerHandler."""
        self.ipv4_hosts = ipv4_hosts
        self.ipv6_hosts = ipv6_hosts
        self.ipv4_networks = ipv4_networks
        self.ipv6_networks = ipv6_networks
        self.term = Terminal()

        self.scanners = []
        for host in self.ipv4_hosts:
            self.scanners.append(Scanner(host, mock=mock, sudo=sudo))
        for host in self.ipv6_hosts:
            self.scanners.append(Scanner(host, True, mock=mock, sudo=sudo))
        for block in self.ipv4_networks:
            hosts = get_hosts_from_cidr(block)
            self.scanners += [
                Scanner(host, mock=mock, sudo=sudo) for host in hosts
            ]
        for block in self.ipv6_networks:
            hosts = get_hosts_from_cidr(block)
            self.scanners += [
                Scanner(host, True, mock=mock, sudo=sudo) for host in hosts
            ]

        logging.debug("Created {} scanners".format(len(self.scanners)))
    
    def build_detail_result(self, term, report):
        """Build the logging results for a completed scanner."""
        base = term.green('[complete]') + '\t-\t' + report.ip
        line1 = '\t'
        if report.hostname != "":
            line1 += "hostname: {}".format(report.hostname)
        if report.hostname != "" and report.mac != "":
            line1 += " - "
        if report.mac != "":
            line1 += "MAC: {}".format(report.mac)
        line2 = "\t\t\t\t\t{} ports up: ({})".format(
                        len(report.ports),
                        ", ".join([str(port.port_number) for port in report.ports])
                    )
        return (base + line1, line2)

    def run_scan(self, scanner, queue, lock, term):
        """Run scanning for a scanner and store the result in the queue.

        Args:
            scanner: A Scanner to be ran.
            queue: A Queue in which all results are stored.
            lock: A Lock object to access the terminal.
            term: A Terminal into which displaying the results.

        """
        logging.debug("Starting scan for host {}".format(scanner.host))

        lock.acquire()
        print(term.blue('[Scanning]') + '\t-\t' + scanner.host)
        lock.release()

        # The host does not block ping requests
        if scanner.run_ping_test():
            scanner.perform_scan()
            scanner.find_vulnerabilities()
            report = scanner.extract_host_report()
            result = "\t\t{} ports up: ({})".format(
                len(report.ports),
                ", ".join([str(port.port_number) for port in report.ports])
            )
            (line1, line2) = self.build_detail_result(term, report)
            lock.acquire()
            print(line1)
            print(line2)
            lock.release()
            queue.put(report)

        # The host does block ping requests or is down
        else:
            # We know the host is down because ping request as privileged user 
            # do not pass
            if scanner.sudo:
                report = scanner.extract_host_report(False)
                queue.put(report)
                lock.acquire()
                print(term.red('[Unreachable]') + '\t-\t' + scanner.host)
                lock.release()
            
            # We are not sure whether the host is down or requests are blocked.
            else:
                scanner.perform_scan(True)
                scanner.find_vulnerabilities()
                try:
                    report = scanner.extract_host_report()
                    (line1, line2) = self.build_detail_result(term, report)
                    lock.acquire()
                    print(line1)
                    print(line2)
                    lock.release()
                except KeyError:
                    report = scanner.extract_host_report(False)
                    lock.acquire()
                    print(term.red('[Unreachable]') + '\t-\t' + scanner.host)
                    lock.release()
                finally:
                    queue.put(report)



    def run_scans(self):
        """Handle the entire scanning process and return the final report."""
        hosts_queue = Queue()
        threads = []
        lock = threading.Lock()

        # Move 2 spaces down to make space for display
        print(self.term.move_down)

        # Display waiting status for all hosts
        for scanner in self.scanners:
            print(self.term.cyan('[Waiting]') + '\t-\t' + scanner.host)
        
        # Move 2 spaces down to make space for further display
        print(self.term.move_down)

        # Start time measurement
        if sys.version_info[0] == 2:  # pragma: no cover
            start_time = time.clock()
        else:  # pragma: no cover
            start_time = time.perf_counter()

        logging.debug("Starting scans")

        for scanner in self.scanners:
            worker = threading.Thread(
                target=self.run_scan, args=(scanner, hosts_queue, lock, self.term),
            )
            threads.append(worker)
            worker.start()

        for worker in threads:
            worker.join()

        if sys.version_info[0] == 2:  # pragma: no cover
            duration = time.clock() - start_time
        else:  # pragma: no cover
            duration = time.perf_counter() - start_time

        print("\n\nAll scans completed in {}s".format(int(duration)))

        results = []
        while not hosts_queue.empty():
            results.append(hosts_queue.get())

        final_report = Report(duration, results)
        return final_report
