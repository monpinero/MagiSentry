"""Minimal i18n loader. Adding a new language = drop a JSON file in locales/."""
import json
from pathlib import Path

_LOCALES = Path(__file__).parent / "locales"


class Translator:
    def __init__(self, lang: str = "en"):
        self.lang = lang
        self._en = self._load("en")
        self._cur = self._load(lang) if lang != "en" else self._en

    @staticmethod
    def _load(lang: str) -> dict:
        path = _LOCALES / f"{lang}.json"
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def t(self, key: str, **kwargs) -> str:
        template = self._cur.get(key) or self._en.get(key) or key
        try:
            return template.format(**kwargs) if kwargs else template
        except (KeyError, IndexError):
            return template
