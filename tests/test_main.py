import click 
from os import path, remove
from click.testing import CliRunner
from port_eye.main import main

def test_main():
    """Test that the main function is running."""
    runner = CliRunner()
    result = runner.invoke(main, ['--help'])
    assert result.exit_code == 0
    assert "Run the main application from arguments provided in the CLI." in \
        result.output
    assert "--help" in result.output

def test_main_errored():
    """Test that running the application without parameter returns an error."""
    runner = CliRunner()
    result = runner.invoke(main)
    assert result.exit_code == 2
    assert "Missing option" in result.output
    assert "Usage: main [OPTIONS]" in result.output

def test_main_file_input():
    """Test inputing a file to the main function."""
    runner = CliRunner()
    export_path = "tests/file_test.html"
    result = runner.invoke(main,
        ['--mock', '--file', 'tests/json_test.json', '-o', export_path])
    assert result.exit_code == 0
    assert path.exists(export_path)
    remove(export_path)
    assert not path.exists(export_path)