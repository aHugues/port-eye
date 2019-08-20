import click
import ipaddress

@click.command()
@click.option('--ipv4', '-h4', multiple=True, type=str, help="IPV4 address of host to check")
@click.option('--ipv6', '-h6', multiple=True, type=str, help="IPV6 address of host to check")
@click.option('--cidr', '-c', multiple=True, type=str, help="CIDR block of hosts to check")
@click.option('--file', '-f', type=click.Path(exists=True), help="File containing the hosts to check")
def main(ipv4, ipv6, cidr, file):
    parsed_ipv4 = [ipaddress.ip_address(address) for address in ipv4]
    parsed_ipv6 = [ipaddress.ip_address(address) for address in ipv6]
    print("test")


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
