"""Presentation-only translations. API payloads and persisted settings stay unchanged."""
from contextvars import ContextVar
from functools import lru_cache
from http.cookies import SimpleCookie
from pathlib import Path
import json
import re

LANGUAGE = ContextVar('ui_language', default='en')
CATALOG = json.loads(Path(__file__).with_name('ui_catalog.js').read_text(encoding='utf-8').split('=', 1)[1].strip().rstrip(';'))
SEGMENT = re.compile(r'[А-Яа-яЁё][А-Яа-яЁё\s.,:;!?()«»—–…/+-]*')
PHRASES = re.compile(r'(?<![А-Яа-яЁё])(?:' + '|'.join(re.escape(key) for key in sorted(CATALOG, key=len, reverse=True)) + r')(?![А-Яа-яЁё])')


def select_language(cookie=''):
    values = SimpleCookie()
    try:
        values.load(cookie)
        language = values['ui_language'].value if 'ui_language' in values else 'en'
    except Exception:
        language = 'en'
    LANGUAGE.set(language if language in ('en', 'ru') else 'en')


def _segments(value):
    def replace(match):
        raw = match.group()
        key = raw.rstrip()
        translated = CATALOG.get(key)
        if translated is None:
            translated = PHRASES.sub(lambda item: CATALOG[item.group()], key)
        return translated + raw[len(key):]
    return SEGMENT.sub(replace, value)


@lru_cache(maxsize=1)
def _exact_translations():
    # Correct word order around technical names without splitting adjacent phrases.
    pairs = {_segments(key): value for key, value in CATALOG.items() if re.search(r'[A-Za-z0-9]', key)}
    pattern = re.compile('|'.join(re.escape(key) for key in sorted(pairs, key=len, reverse=True)) or r'(?!)')
    return pattern, pairs


def text(value):
    """Translate static template fragments before inserting user values."""
    if LANGUAGE.get() == 'ru' or not isinstance(value, str):
        return value
    pattern, pairs = _exact_translations()
    return pattern.sub(lambda match: pairs[match.group()], _segments(value))


def localize_script(source):
    """Localize presentation code, including messages received from unchanged APIs."""
    tokens = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|//[^\n]*|/\*.*?\*/|(?P<message>\b(?:data|job|j|e|error|result)\.message\b|\bjob\.(?:label|subject|change_text)\b|\bdata\.status\b|\bitem\.(?:error|via)\b)''', re.S)
    return tokens.sub(lambda match: 'window.uiText(' + match.group() + ')' if match['message'] else match.group(), source)


def localize_page_scripts(page):
    def script(match):
        opening, code = match[1], match[2]
        if 'application/json' in opening or 'window.uiCatalog =' in code:
            return match[0]
        return opening + localize_script(code) + '</script>'
    return re.sub(r'(<script\b[^>]*>)(.*?)</script>', script, page, flags=re.S | re.I)


def asset(path):
    return text(Path(path).read_text(encoding='utf-8'))


def message(value):
    """Keep quoted user names intact in server-provided status messages."""
    parts = re.split(r'(«[^»]*»)', str(value))
    return ''.join(part if index % 2 else text(part + '«')[:-1] if index + 1 < len(parts) else text(part)
                   for index, part in enumerate(parts))


def bootstrap():
    catalog = Path(__file__).with_name('ui_catalog.js').read_text(encoding='utf-8')
    script = Path(__file__).with_suffix('.js').read_text(encoding='utf-8')
    return '<script>' + catalog + '\n' + script + '</script>'


def language_button():
    english = LANGUAGE.get() == 'en'
    title = 'Switch to Russian' if english else 'Переключить на английский'
    target = 'RU' if english else 'EN'
    return ('<button type="button" id="ui-language-toggle" title="' + title +
            '" aria-label="' + title + '" style="display:inline-flex;align-items:center;gap:6px">'
            '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            'stroke-width="1.7" aria-hidden="true" focusable="false">'
            '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/>'
            '<path d="M3 12h18M5 7h14M5 17h14"/></svg><span>' + target + '</span></button>')
