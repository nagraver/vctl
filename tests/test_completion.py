"""Exercise zsh completion branches without changing the user's shell or profile."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from vless_client.cli import parser, run

ROOT = Path(__file__).resolve().parent.parent


@unittest.skipUnless(shutil.which('zsh'), 'zsh unavailable')
class CompletionTests(unittest.TestCase):
    def complete(self, words):
        script = '''
compadd() { print -rl -- "$@"; }
_describe() { print -rl -- "${commands[@]}"; }
_files() { print -- FILES; }
completion_file=$1
shift
words=("$@")
CURRENT=${#words}
PREFIX=${words[-1]}
function exercise_completion { source "$completion_file"; }
exercise_completion
'''
        result = subprocess.run(['zsh', '-f', '-c', script, 'test', str(ROOT / 'vless_client/completions/_vctl'), *words], capture_output=True, text=True)
        self.assertEqual(result.stderr, '')
        return result.stdout.splitlines()

    def test_new_commands_and_arguments(self):
        for words, expected in [
            ([''], 'preset:Manage routing presets'),
            (['rule', 'add', ''], 'geoip'),
            (['rule', 'add', ''], 'geosite'),
            (['rule', 'add', ''], 'process'),
            (['rule', 'add', ''], 'path'),
            (['rule', 'add', 'path', ''], 'FILES'),
            (['rule', 'add', 'process', 'curl', ''], 'direct'),
            (['preset', ''], 'enable'),
            (['preset', 'add', 'work', ''], 'builtin:ads'),
            (['preset', 'add', 'work', './work.json', '--'], '--interval'),
            (['geodata', ''], 'update'),
            (['geodata', 'update', '--'], '--geosite-url'),
            (['dns', 'set', '--'], '--direct'),
            (['dns', 'set', '--strategy', ''], 'UseIPv4'),
        ]:
            with self.subTest(words=words):
                self.assertIn(expected, self.complete(['vctl', *words]))

    def test_preset_names_respect_profile_and_spaces(self):
        with tempfile.TemporaryDirectory(prefix='vctl-completion-') as d:
            Path(d, 'state.json').write_text(json.dumps({'presets': {'Work rules': {}, 'ads': {}}}))
            for home_args in [['--home', d], ['--home=' + d]]:
                for action in ['show', 'update', 'remove', 'enable', 'disable']:
                    matches = self.complete([str(ROOT / 'vctl'), *home_args, 'preset', action, ''])
                    self.assertIn('Work rules', matches)
                    self.assertIn('ads', matches)

    def test_values_do_not_create_missing_profile(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / 'missing'
            with contextlib.redirect_stdout(io.StringIO()) as output:
                run(parser().parse_args(['--home', str(home), 'completion', 'zsh', '--values', 'preset']))
            self.assertEqual(output.getvalue(), '')
            self.assertFalse(home.exists())
