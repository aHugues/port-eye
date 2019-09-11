"""Class to handle the scan of target hosts."""

import ipaddress
import nmap
from .mock_nmap import MockPortScanner
from .report import PortReport, HostReport, Report
import sys
import time
import threading
import logging

if sys.version_info[0] == 2: # pragma: no cover
    from Queue import Queue
else: # pragma: no cover
    from queue import Queue



class Scanner():

    def __init__(self, host, is_ipv6=False, mock=False):

        logging.debug("Creating Scanner for host {}".format(host))
        self.raw_host = host
        self.host = str(host)
        if mock:
            self.scanner = MockPortScanner()
        else:
            self.scanner = nmap.PortScanner()
        self.full_scan_available = False
        self.reachable = False
        self.is_ipv6 = is_ipv6

        if type(host) not in [
            ipaddress.IPv4Address,
            ipaddress.IPv6Address,
            ipaddress.IPv4Network,
            ipaddress.IPv6Network
        ]:
            raise TypeError("Invalid type for host")

    def is_reachable(self):
        """Check if the target can be reached."""
        logging.debug("Testing if host {} is reachable...".format(self.host))
        argument = '-sn --host-timeout 10s'
        if self.is_ipv6:
            argument += ' -6'
        self.scanner.scan(self.host, arguments=argument)
        try:
            self.reachable = True
            logging.debug("Host {} is reachable".format(self.host))
            return self.scanner[self.host].state() == 'up'
        except KeyError:
            self.reachable = False
            logging.debug("Host {} is unreachable".format(self.host))
            return False

    def is_local(self):
        """Check if the target is in local network."""
        return self.raw_host.is_private

    def perform_scan(self, ping_skip=False):
        """Perform nmap scanning on selected host.
        
        # Arguments
        # ping_skip (Bool) default False: Skip ping if they are blocked.
        """
        arguments = '-Pn' if ping_skip else '-sV'
        if self.is_ipv6:
            arguments += ' -6'
        self.scanner.scan(self.host, arguments=arguments, sudo=False)


    def extract_ports(self, protocol):
        """Extract the scanned port from the host.

        # Arguments
        protocol (str): Protocol to use (tcp or udp)
        """

        lowered_protocol = protocol.lower()
        if lowered_protocol not in ['tcp', 'udp']:
            raise ValueError("Protocol should be 'tcp' or 'udp'")

        ports = []
        try:
            ports_list = list(self.scanner[self.host][lowered_protocol])
            for port in ports_list:
                port_details = self.scanner[self.host][lowered_protocol][port]
                reported_port = PortReport(
                    port,
                    port_details['state'],
                    lowered_protocol == 'tcp',
                    lowered_protocol == 'udp',
                    port_details['product'],
                    port_details['version'],
                    []
                )
                ports.append(reported_port)

        except KeyError:
            pass

        finally:
            return ports

    def extract_host_report(self):
        """Extract the complete report from the host."""

        duration = float(self.scanner.scanstats()['elapsed'])
        hostname = self.scanner[self.host]['hostnames'][0]['name']
        mac = ''
        state = 'up'
        ports = self.extract_ports('tcp') + self.extract_ports('udp')

        host_report = HostReport(
            self.host,
            hostname,
            mac,
            state,
            ports, duration
        )

        return host_report



class ScannerHandler():

    def __init__(self, ipv4_hosts, ipv6_hosts, cidr_blocks, mock=False):
        self.ipv4_hosts = ipv4_hosts
        self.ipv6_hosts = ipv6_hosts
        self.cidr_blocks = cidr_blocks

        self.scanners = []
        for host in (self.ipv4_hosts + self.cidr_blocks):
            self.scanners.append(Scanner(host, mock=mock))
        for host in self.ipv6_hosts:
            self.scanners.append(Scanner(host, True, mock=mock))
        
        logging.debug("Created {} scanners".format(len(self.scanners)))
    
    def run_scan(self, scanner, queue):
        logging.debug("Starting scan for host {}".format(scanner.host))
        scanner.perform_scan()
        try:
            report = scanner.extract_host_report()
            logging.debug("Found result for host {}".format(scanner.host))
            queue.put(report)
        except KeyError:
            try:
                logging.debug(
                    "No result found for host {}... Trying with -Pn".format(
                        scanner.host))
                scanner.perform_scan(True)
                report = scanner.extract_host_report()
                logging.debug("Found result for host {}".format(scanner.host))
                queue.put(report)
            except KeyError:
                logging.debug("No result for host {}".format(scanner.host))

    def run_scans(self):
        hosts_queue = Queue()
        threads = []

        # Start time measurement
        if sys.version_info[0] == 2: # pragma: no cover
            start_time = time.clock()
        else: # pragma: no cover
            start_time = time.perf_counter()
        
        logging.debug("Starting scans")

        for scanner in self.scanners:
            worker = threading.Thread(
                target=self.run_scan, args=(scanner, hosts_queue))
            threads.append(worker)
            worker.start()
        
        for worker in threads:
            worker.join()

        logging.debug("All scans completed")
        
        if sys.version_info[0] == 2: # pragma: no cover
            duration = time.clock() - start_time 
        else: # pragma: no cover
            duration = time.perf_counter() - start_time

        results = []
        while not hosts_queue.empty():
            results.append(hosts_queue.get())

        logging.debug("Generating report.")
        
        final_report = Report(duration, results)
        return final_report

