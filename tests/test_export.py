"""Test functions from the exporting module."""

import pytest
from os import path, remove
from jinja2.environment import Template
from port_eye.export import Export
from port_eye.report import PortReport, HostReport, Report


def test_creation():
    """Test creation of an Export object."""
    export = Export()
    assert type(export.template) == Template


def test_loading_style():
    """Test that loading of style happens with no issue."""
    export = Export()
    export.load_style()

    # Should only happen when no issue arise. 
    assert True


def test_rendering():
    """Test that the rendering of report results is working."""
    export = Export()

    port_report_1 = PortReport(
        22, 'up', True, False, 'ssh', '1.2.3', []
    )
    port_report_2 = PortReport(
        123, 'up', False, True, '', '', []
    )

    host_report = HostReport(
        '127.0.0.1', 'localhost', 'ff:ff:ff', 'up',
        [port_report_1, port_report_2],
        421.69,
        'linux 3.7 - 3.10', '100'
    )

    full_report = Report(421.69, [host_report])

    export_path = "tests/export_test.html"
    export.render(full_report, export_path)
    assert path.exists(export_path)
    remove(export_path)
    assert not path.exists(export_path)
