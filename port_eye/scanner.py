"""Class to handle the scan of target hosts."""

import ipaddress
import nmap
from .mock_nmap import MockPortScanner
from .report import PortReport, HostReport, Report
import sys
import time
import threading

if sys.version_info[0] == 2: # pragma: no cover
    from Queue import Queue
else:
    from queue import Queue



class Scanner():

    def __init__(self, host, is_ipv6=False, mock=False):
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
        argument = '-sn --host-timeout 10s'
        if self.is_ipv6:
            argument += ' -6'
        self.scanner.scan(self.host, arguments=argument)
        try:
            return self.scanner[self.host].state() == 'up'
            self.reachable = True
        except KeyError:
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
    
    def run_scan(self, scanner, queue):
        scanner.perform_scan()
        try:
            report = scanner.extract_host_report()
            queue.put(report)
        except KeyError:
            try:
                scanner.perform_scan(True)
                report = scanner.extract_host_report()
                queue.put(report)
            except KeyError:
                pass

    def run_scans(self):
        hosts_queue = Queue()
        threads = []

        # Start time measurement
        if sys.version_info[0] == 2: # pragma: no cover
            start_time = time.clock()
        else:
            start_time = time.perf_counter()

        for scanner in self.scanners:
            worker = threading.Thread(
                target=self.run_scan, args=(scanner, hosts_queue))
            threads.append(worker)
            worker.start()
        
        for worker in threads:
            worker.join()
        
        if sys.version_info[0] == 2:
            duration = time.clock() - start_time # pragma: no cover
        else:
            duration = time.perf_counter() - start_time

        results = []
        while not hosts_queue.empty():
            results.append(hosts_queue.get())
        
        final_report = Report(duration, results)
        return final_report

