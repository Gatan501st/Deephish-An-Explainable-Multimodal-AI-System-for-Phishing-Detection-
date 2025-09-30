import hashlib
import requests
from time import sleep
from pathlib import Path

try:
    from key import API_KEY
except:
    API_KEY = ""

HEADERS = {"x-apikey": API_KEY}

def hash_it(file, algorithm="sha256"):
    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    elif algorithm == "md5":
        hasher = hashlib.md5()
    else:
        raise Exception("Invalid algorithm")

    with open(file, "rb") as f:
        hasher.update(f.read())
    return hasher.hexdigest()

def vt_get_data(f_hash):
    url = f"https://www.virustotal.com/api/v3/files/{f_hash}"
    while True:
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    return response

def vt_post_files(file, url="https://www.virustotal.com/api/v3/files"):
    with open(file, "rb") as f:
        file_bin = f.read()
    upload_package = {"file": (Path(file).name, file_bin)}
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
            break
        if response.json()["data"]["attributes"]["status"] == "completed":
            return response.json()["meta"]["file_info"]["sha256"]

def vt_get_upload_url():
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    while True:
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    return response.json()["data"]

def error_handle(response):
    if response.status_code == 429:
        sleep(60)
    if response.status_code == 401:
        raise Exception("Invalid API key")
    elif response.status_code not in (200, 404, 429):
        raise Exception(response.status_code)
    else:
        return True
    return False

def parse_response(response):
    json_obj = response.json()["data"]["attributes"]

    output = {
        "name": json_obj.get("meaningful_name"),
        "stats": json_obj.get("last_analysis_stats"),
        "engine_detected": {},
        "votes": json_obj.get("total_votes"),
        "hash": {"sha1": json_obj.get("sha1"), "sha256": json_obj.get("sha256")},
        "size": json_obj.get("size"),
    }

    for engine, result in json_obj.get("last_analysis_results").items():
        if result["category"] != "undetected":
            output["engine_detected"][engine] = {
                "category": result["category"],
                "result": result["result"],
            }

    return output
