#!/usr/bin/env python3
"""Regenerate the consumed DTO from its immutable canonical source; no Git clone."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "NDDev-OpenNetwork/nddev-device-sync-protocol"
matches = re.findall(r"^protocol_commit: ([a-f0-9]{40})$", (ROOT / "module.yaml").read_text(), re.MULTILINE)
assert len(matches) == 1, "module manifest must pin one full protocol commit"
COMMIT = matches[0]
FILES = ["package.json", "package-lock.json", "scripts/generate-dtos.mjs", "contracts/v2/control-plane.schema.json"]


def source(name):
    local = ROOT.parent / "nddev-device-sync-protocol"
    if local.is_dir():
        result = subprocess.run(["git", "-C", str(local), "show", f"{COMMIT}:{name}"], capture_output=True, env=os.environ | {"GIT_OPTIONAL_LOCKS": "0"}, timeout=10)
        if result.returncode == 0:
            return result.stdout
    url = f"https://raw.githubusercontent.com/{REPOSITORY}/{COMMIT}/{name}"
    with urllib.request.urlopen(url, timeout=20) as response:
        data = response.read(1024 * 1024 + 1)
    assert len(data) <= 1024 * 1024, "protocol source exceeded its bound"
    return data


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
