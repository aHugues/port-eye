"""Export functions to HTML."""

from jinja2 import Environment, PackageLoader, select_autoescape
import datetime


class Export:

    def __init__(self):
        """Create a new Export element."""
        self.env = Environment(
            loader=PackageLoader('port_eye', 'templates'),
            autoescape=select_autoescape(['html'])
        )
        self.template = self.env.get_template('export.html.j2')

    def load_style(self):
        """Load style file and return it as string."""
        style_template = self.env.get_template('style.css')
        return style_template.render()

    def render(self, report, path):
        """Render the result report into the given path as an HTML file.

        # Arguments
        report (Report): Report object providing results to store
        path (str): Path of the output html file
        """

        style = self.load_style()
        today_date = datetime.datetime.now().strftime('%Y-%m-%d (%H:%M)')
        new_report = report
        new_report.date = today_date

        with open(path, 'w') as outfile:
            outfile.write(self.template.render(
                style=style,
                report=report
            ))
