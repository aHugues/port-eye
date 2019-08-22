"""Class to handle the scan of target hosts."""

import ipaddress

class Scanner():

    def __init__(self, host):
        self.host = host

        if type(host) not in [
            ipaddress.IPv4Address,
            ipaddress.IPv6Address,
            ipaddress.IPv4Network,
            ipaddress.IPv6Network
        ]:
            raise TypeError("Invalid type for host")
