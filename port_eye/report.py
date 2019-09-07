"""Handle complete data for report."""


class Vulnerability:
    """Represent a vulnerability.

    # Attributes
    service (str): Affected service
    CVE (str): ID of the vulnerability
    description (str): Descripton of the CVE
    link (str): URL of the CVE
    """

    def __init__(self, service, cve, description, link):
        """Create a new Vulnerability object."""
        self.service = service
        self.cve = cve
        self.description = description
        self.link = link


class PortReport:
    """Represent the detailed results for a port.

    # Attributes
    port_number (int): Port number
    state (str): State of the port (open/closed/filtered)
    tcp (Bool): Is the port opened for TCP
    udp (Bool): Is the port opened for UDP
    service (str): Service used on this port
    version (str): Version used by the service
    vulnerabilities (List of Vulnerability) List of identified vulnerabilities
    """

    def __init__(self,
                 port_number, state, tcp, udp,
                 service, version, vulnerabilities):
        self.port_number = port_number
        self.state = state
        self.tcp = tcp
        self.udp = udp
        self.service = service
        self.version = version
        self.vulnerabilities = vulnerabilities
    
    def __str__(self):
        port_type = 'TCP' if self.tcp else 'UDP'
        returned_string = "[{}] Port {} ({}):  ".format(
            port_type, self.port_number, self.state)
        service = 'Unknown' if self.service == '' else self.service
        returned_string += service
        if self.version != '':
            returned_string += ' - Version {}'.format(self.version)
        return returned_string


class HostReport:
    """Represent the detailed results for a single host from a report.

    # Attributes
    ip (str): IP address of the host
    hostname (str): Hostname of the scanned host
    mac (str): MAC address of the host
    state (str): State of the host (up or down)
    ports (List of PortReport): List of scanned ports
    duration (float): Test duration for the scan
    """

    def __init__(self, ip, hostname, mac, state, ports, duration):
        self.ip = ip
        self.hostname = hostname
        self.mac = mac
        self.state = state
        self.ports = ports
        self.duration = duration
    
    def __str__(self):
        returned_string = "HostReport {} - {}".format(self.ip, self.state)
        returned_string += "\n\tHostname: {}".format(self.hostname)
        if self.mac != '':
            returned_string += "\n\tMAC Address: {}".format(self.mac)
        returned_string += " ({}s)".format(self.duration)
        returned_string += "\n\tPorts:"
        for port in self.ports:
            returned_string += "\n\t\t- {}".format(str(port))
        return returned_string


class Report:
    """Represent the results from a report.

    # Attributes
    duration (float): Test complete duration in seconds.
    nb_hosts (int): Total number of scanned hosts.
    up (int): Total number of scanned hosts with state 'up'.
    results (List of HostReport): Detailed report for scanned hosts
    """

    def __init__(self, duration, results):
        nb_hosts = len(results)
        up = len([x for x in results if x.state == 'up'])
        self.nb_hosts = nb_hosts
        self.up = up
        self.results = results
        self.duration = duration
    
    def __str__(self):
        returned_string = "Scanning report\n================\n\n\n"
        returned_string += "{} Hosts scanned in {}s".format(
            self.nb_hosts, self.duration)
        returned_string += "\n{} Hosts up\n\n".format(self.up)
        for host in self.results:
            returned_string += "\n* {}".format(str(host))

