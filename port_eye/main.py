import click


@click.command()
@click.option('--host', multiple=True, type=str, help="Host to check")
@click.option('--file', '-f', type=click.Path(exists=True), help="File containing the hosts to check")
def main(host, file):
    print(host)
    print(file)
    print("test")


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
