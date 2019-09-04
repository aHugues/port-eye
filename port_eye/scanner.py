"""Class to handle the scan of target hosts."""

import ipaddress
import nmap
from .report import PortReport


class Scanner():

    def __init__(self, host):
        self.raw_host = host
        if host == 'localhost':
            self.host = '127.0.0.1'
        else:
            self.host = str(host)
        self.scanner = nmap.PortScanner()
        self.full_scan_available = False
        self.reachable = False

        if type(host) not in [
            ipaddress.IPv4Address,
            ipaddress.IPv6Address,
            ipaddress.IPv4Network,
            ipaddress.IPv6Network
        ]:
            raise TypeError("Invalid type for host")

    def is_reachable(self):
        """Check if the target can be reached."""
        self.scanner.scan(self.host, arguments='-sn --host-timeout 10s')
        try:
            self.reachable = True
            return self.scanner[self.host].state() == 'up'
        except KeyError:
            return False

    def is_local(self):
        """Check if the target is in local network."""
        return self.raw_host.is_private

    def perform_scan(self):
        """Perform nmap scanning on selected host."""
        self.scanner.scan(self.host, sudo=True)

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
