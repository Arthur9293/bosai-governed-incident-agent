from __future__ import annotations

import argparse
import shutil
from pathlib import Path

RUNTIME_NAME = "BosaiIncidentAgent"

PYPROJECT = """\
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "bosai-agentcore-runtime"
version = "0.1.0"
requires-python = ">=3.14,<3.15"
dependencies = [
  "strands-agents>=1.0.0,<2.0.0",
  "bedrock-agentcore>=1.20.0,<1.21.0",
]

[tool.setuptools.packages.find]
where = ["."]
include = ["bosai_incident_agent*"]
"""

MAIN = """\
from bosai_incident_agent.agentcore_entrypoint import app

if __name__ == "__main__":
    app.run()
"""


def prepare(output_root: Path) -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    destination = output_root / RUNTIME_NAME

    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)

    source_package = repo_root / "src" / "bosai_incident_agent"
    shutil.copytree(
        source_package,
        destination / "bosai_incident_agent",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )

    (destination / "main.py").write_text(MAIN)
    (destination / "pyproject.toml").write_text(PYPROJECT)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", default=".agentcore-build")
    args = parser.parse_args()

    destination = prepare(Path(args.output_root))
    print(f"AGENTCORE_CODEZIP_PREPARED={destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
