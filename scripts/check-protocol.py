#!/usr/bin/env python3
"""Regenerate the consumed DTO from its immutable canonical source; no Git clone."""
from pathlib import Path
import subprocess
import tempfile
from protocol_source import ROOT, source
FILES = ["package.json", "package-lock.json", "scripts/generate-dtos.mjs", "contracts/v2/control-plane.schema.json"]


with tempfile.TemporaryDirectory(prefix="nds-protocol-check-") as directory:
    directory = Path(directory)
    for name in FILES:
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source(name))
    subprocess.run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=directory, check=True, timeout=120, stdout=subprocess.DEVNULL)
    output = directory / "auth.rs"
    subprocess.run(["node", "scripts/generate-dtos.mjs", "rust", "auth", str(output)], cwd=directory, check=True, timeout=30)
    subprocess.run(["rustfmt", "--edition", "2024", str(output)], cwd=ROOT, check=True, timeout=20)
    assert output.read_bytes() == (ROOT / "src/protocol_v2.rs").read_bytes(), "protocol DTO drift: regenerate from the manifest's exact protocol commit, then rustfmt"
print("Canonical auth DTO regeneration passed.")
