# modules/vt_client.py
import os
import hashlib
import requests
from time import sleep
from pathlib import Path

try:
    from key import API_KEY
except Exception:
    API_KEY = os.getenv("VT_API_KEY", "")

HEADERS = {"x-apikey": API_KEY}

def hash_it(file_path, algorithm="sha256"):
    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    elif algorithm == "md5":
        hasher = hashlib.md5()
    else:
        raise Exception("Invalid algorithm")
    with open(file_path, "rb") as f:
        hasher.update(f.read())
    return hasher.hexdigest()

def error_handle(response):
    if response.status_code == 429:
        sleep(60)
        return False
    if response.status_code == 401:
        raise Exception("Invalid API key")
    if response.status_code not in (200, 202, 404, 204):
        raise Exception(f"HTTP {response.status_code}")
    return True

def vt_get_upload_url():
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    while True:
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    return response.json().get("data")

def vt_post_files(file_path, url="https://www.virustotal.com/api/v3/files"):
    # Accepts local file path; posts to VT and returns response
    with open(file_path, "rb") as f:
        file_bin = f.read()
    upload_package = {"file": (Path(file_path).name, file_bin)}
    while True:
        response = requests.post(url, headers=HEADERS, files=upload_package)
        if error_handle(response):
            break
    return response

def vt_get_analyses(response):
    _id = response.json()["data"]["id"]
    url = f"https://www.virustotal.com/api/v3/analyses/{_id}"
    while True:
        sleep(15)
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            # keep checking until completed
            pass
        try:
            status = response.json()["data"]["attributes"]["status"]
        except Exception:
            status = None
        if status == "completed":
            return response.json()["meta"]["file_info"]["sha256"]

def vt_get_data(f_hash):
    url = f"https://www.virustotal.com/api/v3/files/{f_hash}"
    while True:
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    return response

def parse_response(response):
    json_obj = response.json()["data"]["attributes"]
    output = {
        "name": json_obj.get("meaningful_name"),
        "stats": json_obj.get("last_analysis_stats"),
        "engine_detected": {},
        "votes": json_obj.get("total_votes"),
        "hash": {"sha1": json_obj.get("sha1"), "sha256": json_obj.get("sha256"), "md5": json_obj.get("md5")},
        "size": json_obj.get("size"),
    }
    for engine, result in json_obj.get("last_analysis_results", {}).items():
        if result and result.get("category") != "undetected":
            output["engine_detected"][engine] = {
                "category": result.get("category"),
                "result": result.get("result"),
            }
    return output

# IP report (compact)
def vt_ip_report(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        data = response.json().get("data", {}).get("attributes", {})
        return {
            "ip": ip,
            "country": data.get("country"),
            "asn": data.get("asn"),
            "as_owner": data.get("as_owner"),
            "last_analysis_stats": data.get("last_analysis_stats"),
            "last_analysis_results": {
                engine: result.get("category")
                for engine, result in data.get("last_analysis_results", {}).items()
                if result.get("category") != "undetected"
            },
            "reputation": data.get("reputation"),
            "tags": data.get("tags"),
        }
    elif response.status_code == 404:
        return {"error": "IP not found in VirusTotal"}
    else:
        return {"error": f"HTTP {response.status_code}"}
