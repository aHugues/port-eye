"""Class to handle the scan of target hosts."""

import ipaddress
import nmap

class Scanner():

    def __init__(self, host):
        self.raw_host = host
        self.host = str(host)
        self.scanner = nmap.PortScanner()

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
        return self.scanner[self.host].state() == 'up'

    

    def is_local(self):
        """Check if the target is in local network."""
        return self.raw_host.is_private
