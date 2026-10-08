"""Consistent, readable status output for CLI commands."""
import json
import os
import re
import sys


def color_enabled():
    return sys.stdout.isatty() and os.environ.get('TERM') != 'dumb' and not os.environ.get('NO_COLOR')


def print_status(status, color=None):
    if isinstance(status, str):
        status = {'state': 'stopped'} if status == 'stopped' else json.loads(status)
    text = json.dumps(status, ensure_ascii=False, indent=2)
    use_color = color_enabled() if color is None else color
    if use_color:
        def highlight(match):
            token, colon = match.group(1), match.group(2) or ''
            code = '1;35' if colon else ('90' if token == 'null' else '32')
            return f'\033[{code}m{token}\033[0m{colon}'
        text = re.sub(r'("(?:[^"\\]|\\.)*"|\bnull\b)(\s*:)?', highlight, text)
    print(text)
