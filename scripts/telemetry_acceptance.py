"""Use the canonical pinned validator on real process output without retaining it."""
from pathlib import Path
import subprocess
import sys
from protocol_source import source


class TelemetryValidator:
    def __init__(self, directory):
        self.root = Path(directory) / "telemetry-contract"
        for name in ["requirements.lock", "scripts/validate.py", "scripts/validate-events.py", "contracts/v2/telemetry-event.schema.json"]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source(name))
        subprocess.run([sys.executable, "-m", "venv", str(self.root / ".venv")], check=True, timeout=30)
        self.python = self.root / ".venv/bin/python"
        subprocess.run([str(self.python), "-m", "pip", "install", "--disable-pip-version-check", "--require-hashes", "-r", str(self.root / "requirements.lock")], check=True, timeout=120, stdout=subprocess.DEVNULL)

    def __call__(self, logs):
        # The canonical validator reports counts/constraint names only. Process
        # output travels through stdin and is never written to a fixture file.
        result = subprocess.run([str(self.python), str(self.root / "scripts/validate-events.py")], input=logs, text=True, capture_output=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout.strip())
