import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.json"

with CONFIG_PATH.open(encoding="utf-8") as f:
    CONFIG = json.load(f)