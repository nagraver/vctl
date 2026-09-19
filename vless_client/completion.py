"""Expose the same static completion file used by zsh autoload."""
from pathlib import Path

ZSH = (Path(__file__).resolve().parent / 'completions' / '_vctl').read_text()
