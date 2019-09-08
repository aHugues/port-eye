"""Mock nmap scanner to be used for unit testing in the CI process."""

import sys

class MockPortScanner():
    """MockPortScanner allows to use a mock version of nmap from Python."""

    def __init__(self):
        """Initialize MockPortScanner module."""
        pass 

    def build_global_test_info(self, host, skip_ping=False, ipv6=False):
        """Build the command_line and scanstats parts of the response.

        :param host: scanned host
        :param skip_ping: bool for skipping ping (default to False)
        :param ipv6: bool for creating request for ipv6 host (default to False)

        :returns global_result as dictionnary
        """
        ip_argument = '6' if ipv6 else ''
        skip_argument = 'Pn' if skip_ping else 'sV'
        command_line = 'nmap -oX -{} -{} {}'.format(
            ip_argument,
            skip_argument,
            host
        )
        elapsed = '10.7' if skip_ping else '4.2'
        return {
            'command_line': command_line,
            'scanstats': {
                'timestr': 'Sun Sep  8 10:21:46 2019',
                'elapsed': elapsed,
                'uphosts': '1',
                'downhosts': '0',
                'totalhosts': '1',
            }
        }
    
    def build_tcp_result(self, port, skip_ping=False):
        """Build the result for a port.

        :param port: scanned port
        :param skip_ping: bool for skipping ping (default to False)

        :returns port_result as dictionnary
        """

        if port not in [22, 80, 443]:
            raise KeyError('Port not in range (22, 80, 443)')

        else:
            additionnal_infos = ['product', 'version', 'extrainfo', 'cpe']
            ports_result = {
                22: {
                    'state': 'open',
                    'reason': 'syn-ack',
                    'name': 'ssh',
                    'product': 'OpenSSH',
                    'version': '7.6p1 Ubuntu 4ubuntu0.3',
                    'extrainfo': 'Ubuntu Linux; protocol 2.0',
                    'conf': '10',
                    'cpe': 'cpe:/o:linux:linux_kernel'
                },
                80: {
                    'state': 'open',
                    'reason': 'syn-ack',
                    'name': 'http',
                    'product': 'nginx',
                    'version': '',
                    'extrainfo': '',
                    'conf': '10',
                    'cpe': 'cpe:/a:igor_sysoev:nginx'
                },
                443: {
                    'state': 'open',
                    'reason': 'syn-ack',
                    'name': 'http',
                    'product': 'nginx',
                    'version': '',
                    'extrainfo': '',
                    'conf': '10',
                    'cpe': 'cpe:/a:igor_sysoev:nginx'
                }
            }

            # Remove additionnal info if ping is skipped
            if skip_ping:
                for info in additionnal_infos:
                    ports_result[port][info] = ''
                ports_result[port]['conf'] = '3'
            
            return ports_result[port]
    
    def build_result_ipv4(self, ports, skip_ping=False):
        """Build the returned dict for ipv4 hosts

        If the skip_ping argument is set to True, results are sure to be 
        computed, but the result will have less information.

        :param ports: list of ports to scan (must be in range (22, 80, 443))
        :param skip_ping: bool for skipping ping (default to False)

        :returns: scan_result as dictionnary
        """
        global_infos = self.build_global_test_info('127.0.0.1', skip_ping)
        tcp_dict = {}
        for port in ports:
            tcp_dict[port] = self.build_tcp_result(port, skip_ping)

        result = {
            'nmap': global_infos,
            'scan': {
                '127.0.0.1': {
                    'hostnames': [{'name': 'localhost', 'type': 'PTR'}],
                    'addresses': {'ipv4': '127.0.0.1'},
                    'status': {'state': 'up', 'reason': 'conn-refused'},
                    'tcp': tcp_dict
                }
            }
        }
        return result

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
        if sys.version_info[0]==2:
            assert type(hosts) in (str, unicode), 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))  # noqa
            assert type(ports) in (str, unicode, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))  # noqa
            assert type(arguments) in (str, unicode), 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))  # noqa
        else:
            assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))  # noqa
            assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))  # noqa
            assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))  # noqa

        skip_ping = "-Pn" in arguments
        is_ipv6 = "6" in arguments

        ports = [22] if hosts == '127.0.0.1' else [22, 80, 443]
        if is_ipv6:
            return None
        
        return self.build_result_ipv4(ports, skip_ping)

