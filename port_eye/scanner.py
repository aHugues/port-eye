"""Class to handle the scan of target hosts."""

import ipaddress
import nmap
from .report import PortReport, HostReport, Report


class Scanner():

    def __init__(self, host, is_ipv6=False):
        self.raw_host = host
        if host == 'localhost':
            self.host = '127.0.0.1'
        else:
            self.host = str(host)
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
        self.scanner.scan(self.host, arguments='-sn --host-timeout 10s')
        try:
            self.reachable = True
            return self.scanner[self.host].state() == 'up'
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
            ports
        )

        return (host_report, duration)



class ScannerHandler():

    def __init__(self, ipv4_hosts, ipv6_hosts, cidr_blocks):
        self.ipv4_hosts = ipv4_hosts
        self.ipv6_hosts = ipv6_hosts
        self.cidr_blocks = cidr_blocks

        self.scanners = []
        for host in (self.ipv4_hosts + self.cidr_blocks):
            self.scanners.append(Scanner(host))
        for host in self.ipv6_hosts:
            self.scanners.append(Scanner(host, True))
    

    def run_scans(self):
        results = []
        for scanner in self.scanners:
            scanner.perform_scan()
            try:
                (report, duration) = scanner.extract_host_report()
            except KeyError:
                scanner.perform_scan(True)
                (report, duration) = scanner.extract_host_report()
            finally:
                results.append(report)
        final_report = Report(1337, results)
        return final_report

