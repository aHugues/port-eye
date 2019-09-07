import click 
from click.testing import CliRunner

from port_eye.main import main

def test_main():
    """Test that the main function is running."""
    runner = CliRunner()
    result = runner.invoke(main)
    assert result.exit_code == 0
    assert "Run the main application from arguments provided in the CLI." in \
        result.output
    assert "--help" in result.output
