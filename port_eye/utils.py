class FormatError(Exception):
    pass


def parse_ipv4_hosts(hosts_list):
    for host in hosts_list:
        try:
            numbers = host.split('.')
            assert len(numbers) == 4
            for number in numbers:
                assert int(number) < 256
                assert int(number) >= 0
        except:
            raise FormatError(f'Wrong format for IPV4 ({host})')
    return list(hosts_list)