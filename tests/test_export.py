"""Test functions from the exporting module."""

import pytest
from os import path, remove
from jinja2.environment import Template
from port_eye.export import Export
from port_eye.report import Report


def test_creation():
    """Test creation of an Export object."""
    export = Export()
    assert type(export.template) == Template


# def test_rendering():
#     """Test that the rendering of report results is working."""
#     export = Export()
#     report = Report(12, None)
#     export_path = "tests/export_test.html"
#     export.render(report, export_path)

#     assert path.exists(export_path)
#     remove(export_path)
#     assert not path.exists(export_path)




