# modules/eml_parser_module.py
import datetime
import os
from eml_parser import EmlParser


def json_serial(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    return None


def parse_eml(file_path):
    """
    Parse an EML file and return a normalized Python dict with key fields and attachment metadata.
    """
    with open(file_path, "rb") as fh:
        raw = fh.read()

    ep = EmlParser()

    # Compatibility: handle older versions of eml_parser
    try:
        parsed = ep.decode_email_bytes(raw, include_raw_body=False)
    except TypeError:
        parsed = ep.decode_email_bytes(raw)

    # Normalize datetime objects to ISO format
    def norm(o):
        if isinstance(o, dict):
            return {k: norm(v) for k, v in o.items()}
        if isinstance(o, list):
            return [norm(i) for i in o]
        if isinstance(o, datetime.datetime):
            return o.isoformat()
        return o

    parsed = norm(parsed)

    # Extract attachment metadata only
    attachments = []
    for a in parsed.get("attachment", []):
        attachments.append({
            "filename": a.get("filename"),
            "content_type": a.get("content_type"),
            "size": a.get("size")
        })

    parsed["_attachments_meta"] = attachments
    return parsed


def extract_attachments(file_path, out_dir="uploads/attachments"):
    """
    Save attachments to disk and return their file paths.
    """
    os.makedirs(out_dir, exist_ok=True)

    with open(file_path, "rb") as fh:
        raw = fh.read()

    ep = EmlParser()

    # Compatibility for old versions
    try:
        parsed = ep.decode_email_bytes(raw, include_raw_body=False)
    except TypeError:
        parsed = ep.decode_email_bytes(raw)

    saved = []
    for a in parsed.get("attachment", []):
        filename = a.get("filename") or "attachment.bin"
        payload = a.get("payload") or b""
        save_path = os.path.join(out_dir, filename)

        # Avoid overwriting existing files
        base, ext = os.path.splitext(save_path)
        i = 1
        while os.path.exists(save_path):
            save_path = f"{base}_{i}{ext}"
            i += 1

        with open(save_path, "wb") as outfh:
            outfh.write(payload)
        saved.append(save_path)

    return saved
