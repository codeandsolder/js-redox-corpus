from __future__ import annotations
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
JS_REDOX_ROOT = Path(os.environ.get("JS_REDOX_ROOT", REPO_ROOT.parent / "js-redox")).expanduser().resolve()
CORPUS_ROOT = Path(os.environ.get("JS_REDOX_CORPUS_ROOT", REPO_ROOT / "work/scum-corpus-20261007")).expanduser().resolve()
