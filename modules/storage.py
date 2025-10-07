# modules/storage.py
import json
import os
from pathlib import Path

STORAGE_DIR = Path("uploads/json_store")
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

def store_json(obj, name=None):
    """
    store JSON content; returns filename and path
    """
    if name is None:
        name = "content"
    safe_name = f"{name}.json"
    path = STORAGE_DIR / safe_name
    # ensure uniqueness
    i = 1
    while path.exists():
        path = STORAGE_DIR / f"{name}_{i}.json"
        i += 1
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
    return str(path)
