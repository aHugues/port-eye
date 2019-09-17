#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
export.py - 2019.09.17.

This module handles the exporting from reports to HTML files.

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

from jinja2 import Environment, PackageLoader
from jinja2 import ChoiceLoader, select_autoescape, FileSystemLoader
import datetime


class Export:
    """Handle the exporting from report to HTML.

    Attributes:
        env: The Jinja environment to correctly load templates.
        template: The Jinja HTML template used for exporting.

    """

    def __init__(self):
        """Create a new Export element.

        This method automatically loads the necessary template from files
        included in the package.

        """
        loader1 = PackageLoader("port_eye", "templates")
        loader2 = FileSystemLoader("./templates/", "port_eye/templates/")
        loader = ChoiceLoader([loader1, loader2])
        self.env = Environment(
            loader=loader, autoescape=select_autoescape(["html"])
        )
        self.template = self.env.get_template("export.html.j2")

    def load_style(self):
        """Load CSS style file and return it as string."""
        style_template = self.env.get_template("style.css")
        return style_template.render()

    def render(self, report, path):
        """Render the result report into the given path as an HTML file.

        Args:
            report: A Report object providing results to store.
            path: A string representing the path of the output html file.

        """
        style = self.load_style()
        today_date = datetime.datetime.now().strftime("%Y-%m-%d (%H:%M)")

        with open(path, "w") as outfile:
            outfile.write(
                self.template.render(
                    style=style, report=report, date=today_date
                )
            )
