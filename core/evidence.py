"""
Evidence capture: persist RunResult objects to the local ``runs/`` directory.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .models import RunResult, ScanStatus

# Allow override via environment variable
RUNS_DIR = Path(os.getenv("RUNS_DIR", "runs"))


def _run_dir(run_id: str) -> Path:
    return RUNS_DIR / run_id


def _json_path(run_id: str) -> Path:
    return _run_dir(run_id) / "result.json"


# ── Write helpers ─────────────────────────────────────────────────────────────

def save_run(result: RunResult) -> Path:
    """Persist *result* to ``runs/<run_id>/result.json``.  Returns the run directory."""
    run_dir = _run_dir(result.run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    with open(_json_path(result.run_id), "w", encoding="utf-8") as fh:
        fh.write(result.model_dump_json(indent=2))
    return run_dir


def save_report(run_id: str, markdown: str, report_filename: str = "report.md") -> Path:
    """Write a Markdown report alongside the JSON artefact."""
    run_dir = _run_dir(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / report_filename
    path.write_text(markdown, encoding="utf-8")
    return path


# ── Read helpers ──────────────────────────────────────────────────────────────

def load_run(run_id: str) -> RunResult:
    """Load a previously saved RunResult by run_id."""
    path = _json_path(run_id)
    if not path.exists():
        raise FileNotFoundError(f"No run found for id '{run_id}' at {path}")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return RunResult(**data)


def list_runs() -> List[str]:
    """Return a list of all run IDs (directory names inside RUNS_DIR)."""
    if not RUNS_DIR.exists():
        return []
    dirs = [d for d in RUNS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
    # Sort by directory modification time so the most recent runs appear first
    dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    return [d.name for d in dirs]


def get_run_report_path(run_id: str, report_filename: str = "report.md") -> Optional[Path]:
    """Return the path to the report file if it exists, else None."""
    path = _run_dir(run_id) / report_filename
    return path if path.exists() else None
