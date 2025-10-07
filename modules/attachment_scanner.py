# modules/attachment_scanner.py
import os
from modules import vt_client

def scan_attachment(file_path):
    """
    Hash local file, upload to VT, poll analysis, return parsed VT report dict.
    """
    result = {"local_path": file_path}
    try:
        result["hash_sha256"] = vt_client.hash_it(file_path, algorithm="sha256")
    except Exception as e:
        result["error"] = f"hash_error: {e}"
        return result

    try:
        # upload
        upload_resp = vt_client.vt_post_files(file_path)
        if upload_resp is None:
            result["error"] = "upload_failed"
            return result
        # poll analyses
        sha256 = vt_client.vt_get_analyses(upload_resp)
        # get final report
        report = vt_client.vt_get_data(sha256)
        parsed = vt_client.parse_response(report)
        result["vt_report"] = parsed
    except Exception as e:
        result["error"] = str(e)
    return result
