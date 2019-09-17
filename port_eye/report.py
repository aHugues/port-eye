#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
report.py - 2019.09.17.

This file contains the classes used to store report data in an ordered and easy
to use format for the rest of the tool, including the exporting to HTML.

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

from .utils import parse_duration_from_seconds


class Vulnerability:
    """Represent a vulnerability.

    Attributes:
        service: A string representing the affected service.
        cve: A string representing the ID of the vulnerability, example:
            CVE-2017-1245.
        description: A string giving a short descripton of the vulnerability.
        link: A string representing a link to the vulnerability reference.

    """

    def __init__(self, service, cve, description, link):
        """Create a new Vulnerability object."""
        self.service = service
        self.cve = cve
        self.description = description
        self.link = link


class PortReport:
    """Represent the detailed results for a port.

    Attributes:
        port_number: An integer representing the port number.
        state: A string representing the state of the port
            (open/closed/filtered).
        tcp: A bool set to True if the port uses the TCP protocol.
        udp: A bool set to True if the port uses the UDP protocol.
        service: A string representing the service used on this port.
        version: A string representing the version used by the service.
        vulnerabilities: A list of identified vulnerabilities.

    """

    def __init__(
        self, port_number, state, tcp, udp, service, version, vulnerabilities
    ):
        """Build a PortReport object."""
        self.port_number = port_number
        self.state = state
        self.tcp = tcp
        self.udp = udp
        self.service = service
        self.version = version
        self.vulnerabilities = vulnerabilities

    def __str__(self):
        """Return a string representation of the Report."""
        port_type = "TCP" if self.tcp else "UDP"
        returned_string = "[{}] Port {} ({}): ".format(
            port_type, self.port_number, self.state
        )
        service = "Unknown" if self.service == "" else self.service
        returned_string += service
        if self.version != "":
            returned_string += " - Version {}".format(self.version)
        return returned_string


class HostReport:
    """Represent the detailed results for a single host from a report.

    Attributes:
        ip: A string representing the IP address of the host.
        hostname: A string representing the hostname of the scanned host.
        mac: A string representing the MAC address of the host.
        state: A string representing the state of the host ('up' or 'down').
        ports: List of PortReport for the list of scanned ports.
        duration: A float representing the number of seconds in the scan.

    """

    def __init__(
        self,
        ip,
        hostname,
        mac,
        state,
        ports,
        duration,
        operating_system,
        operating_system_accuracy,
    ):
        """Init a HostReport."""
        self.ip = ip
        self.hostname = hostname
        self.mac = mac
        self.state = state
        self.ports = ports
        self.duration = parse_duration_from_seconds(duration)
        self.operating_system = operating_system
        self.operating_system_accuracy = operating_system_accuracy

    def __str__(self):
        """Return a string representation of the HostReport."""
        returned_string = "HostReport {} - {}".format(self.ip, self.state)
        returned_string += "\n\tHostname: {}".format(self.hostname)
        if self.mac != "":
            returned_string += "\n\tMAC Address: {}".format(self.mac)
        returned_string += " ({})".format(self.duration)
        returned_string += "\n\tPorts:"
        for port in self.ports:
            returned_string += "\n\t\t- {}".format(str(port))
        return returned_string


class Report:
    """Represent the results from a report.

    Attributes:
        duration: A float representing the complete test duration in seconds.
        nb_hosts: An int representing the total number of scanned hosts.
        up: An int representing the total number of scanned hosts with
            state 'up'.
        results: A list of HostReport representing the detailed report for
            scanned hosts

    """

    def __init__(self, duration, results):
        """Init a Report."""
        nb_hosts = len(results)
        up = len([x for x in results if x.state == "up"])
        self.nb_hosts = nb_hosts
        self.up = up
        self.results = results
        self.duration = parse_duration_from_seconds(duration)

    def __str__(self):
        """Return a string representation of the Report."""
        returned_string = "Scanning report\n================\n\n\n"
        returned_string += "{} Hosts scanned in {}".format(
            self.nb_hosts, self.duration
        )
        returned_string += "\n{} Hosts up\n\n".format(self.up)
        for host in self.results:
            returned_string += "\n* {}".format(str(host))
        return returned_string
