import os
from jinja2 import Environment, FileSystemLoader

from app.i18n import LABELS

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")
_env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)


def render_html_report(report: dict, lang: str = "en") -> str:
    lang = lang if lang in LABELS else "en"
    template = _env.get_template("report.html.j2")
    return template.render(report=report, lang=lang, t=LABELS[lang])
