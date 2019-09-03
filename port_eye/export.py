"""Export functions to HTML."""

from jinja2 import Environment, PackageLoader, select_autoescape
import datetime

class Export():

    def __init__(self):
        self.env = Environment(
            loader=PackageLoader('port_eye', 'templates'),
            autoescape=select_autoescape(['html'])
        )
        self.template = self.env.get_template('export.html.j2')
    
    def load_style(self):
        style_template = self.env.get_template('style.css')
        return style_template.render()

    def render(self):
        style = self.load_style()
        today_date = datetime.datetime.now().strftime('%Y-%m-%d (%H:%M)')
        duration = 13

        hosts_status = [
            {'ip': '192.168.0.1', 'status': 'up'},
            {'ip': '192.168.0.1', 'status': 'up'},
            {'ip': '192.168.0.1', 'status': 'up'},
            {'ip': '192.168.0.1', 'status': 'down'},
            {'ip': '192.168.0.1', 'status': 'up'},
            {'ip': '192.168.0.1', 'status': 'up'},
            {'ip': '192.168.0.1', 'status': 'up'},
            {'ip': '192.168.0.1', 'status': 'down'},
            {'ip': '192.168.0.1', 'status': 'up'},
            {'ip': '192.168.0.1', 'status': 'up'},
            {'ip': '192.168.0.1', 'status': 'up'},
            {'ip': '192.168.0.1', 'status': 'up'},
        ]

        with open('export.html', 'w') as outfile:
            outfile.write(self.template.render(
                style=style,
                date=today_date,
                duration=duration,
                hosts_status=hosts_status
            ))