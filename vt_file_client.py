import hashlib
import requests
import os
import time
import threading
import sys
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY or VT_API_KEY.strip() in [
    "",
    "your_api_key",
]:
    print(
        "[CRITICAL] Invalid or missing VT_API_KEY in .env file. Please configure a valid key."
    )
    sys.exit(1)

FOLDER_PATH = os.getenv("FOLDER_PATH")
VT_API_URL = "https://www.virustotal.com/api/v3/"

# Fallback for standalone testing; in production, queue_manager passes the exact path
headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
_request_timestamps = []
_rate_limiter_lock = threading.Lock()
MAX_REQUESTS_PER_MINUTE = 4


def safe_vt_request(method: str, url: str, **kwargs) -> requests.Response:
    global _request_timestamps

    with _rate_limiter_lock:
        now = time.time()
        _request_timestamps = [t for t in _request_timestamps if now - t < 60]

        if len(_request_timestamps) >= MAX_REQUESTS_PER_MINUTE:
            oldest_timestamp = _request_timestamps[0]
            sleep_duration = 60 - (now - oldest_timestamp) + 0.5

            if sleep_duration > 0:
                print(
                    f"⌛ [Rate Limiter] Free quota reached (4 req/min). Pausing for {sleep_duration:.1f}s..."
                )
                time.sleep(sleep_duration)

        _request_timestamps.append(time.time())

    return requests.request(method, url, **kwargs)


def get_file_sha256(file_path: str) -> str:
    with open(file_path, "rb") as f:
        digest = hashlib.file_digest(f, "sha256")
    return digest.hexdigest()


def check_file_by_hash(file_path: str, headers: dict) -> dict:
    hash_id = get_file_sha256(file_path)
    url = VT_API_URL + "files/" + hash_id
    response = safe_vt_request("GET", url, headers=headers)

    if response.status_code == 200:
        attr = response.json().get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)

        if malicious_count > 0:
            verdict = "MALICIOUS"
        elif suspicious_count > 0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        summary = {
            "status": "success",
            "verdict": verdict,
            "sha256": attr.get("sha256"),
            "file_name": os.path.basename(file_path),
            "size_mb": (
                round(attr.get("size") / 1024 / 1024, 2) if attr.get("size") else None
            ),
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "total_engines": sum(stats.values()),
            "flagged_vendors": [],
            "error_message": None,
        }

        for vendor, details in attr.get("last_analysis_results", {}).items():
            if details.get("category") in ["malicious", "suspicious"]:
                summary["flagged_vendors"].append(f"{vendor}: {details.get('result')}")

        return summary
    elif response.status_code == 404:
        print("File not found in VirusTotal. Uploading the file for analysis.")
        return upload_file_to_virustotal(file_path, headers)
    else:
        summary = {
            "status": "error",
            "verdict": "ERROR",
            "sha256": hash_id,
            "file_name": os.path.basename(file_path),
            "size_mb": None,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "flagged_vendors": [],
            "error_message": f"Hash lookup failed with HTTP status {response.status_code}",
        }
        return summary


def upload_file_to_virustotal(file_path: str, headers: dict) -> dict:
    file_size_mb = os.path.getsize(file_path) / 1024 / 1024
    print(f"{file_size_mb:.2f} MB")

    if file_size_mb <= 32:
        with open(file_path, "rb") as file_to_upload:
            files = {"file": file_to_upload}
            url = VT_API_URL + "files"
            response = safe_vt_request("POST", url, headers=headers, files=files)
            if response.status_code == 200:
                data = response.json()
                analysis_id = data["data"]["id"]
                print(f"Analysis ID: {analysis_id}")
                time.sleep(30)
                return check_analysis_report(analysis_id, headers, file_path)
            else:
                summary = {
                    "status": "error",
                    "verdict": "ERROR",
                    "sha256": get_file_sha256(file_path),
                    "file_name": os.path.basename(file_path),
                    "size_mb": round(file_size_mb, 2),
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "total_engines": 0,
                    "flagged_vendors": [],
                    "error_message": f"Upload failed with HTTP status {response.status_code}",
                }
                return summary
    else:
        url = VT_API_URL + "files/upload_url"
        response = safe_vt_request("GET", url, headers=headers)
        if response.status_code == 200:
            upload_url = response.json()["data"]
            with open(file_path, "rb") as file_to_upload:
                files = {"file": file_to_upload}
                response = safe_vt_request(
                    "POST", upload_url, headers=headers, files=files
                )
                if response.status_code == 200:
                    data = response.json()
                    analysis_id = data["data"]["id"]
                    print(f"Analysis ID: {analysis_id}")
                    time.sleep(30)
                    return check_analysis_report(analysis_id, headers, file_path)
                else:
                    summary = {
                        "status": "error",
                        "verdict": "ERROR",
                        "sha256": get_file_sha256(file_path),
                        "file_name": os.path.basename(file_path),
                        "size_mb": round(file_size_mb, 2),
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "total_engines": 0,
                        "flagged_vendors": [],
                        "error_message": f"Large file upload failed with HTTP status {response.status_code}",
                    }
                    return summary
        else:
            summary = {
                "status": "error",
                "verdict": "ERROR",
                "sha256": get_file_sha256(file_path),
                "file_name": os.path.basename(file_path),
                "size_mb": round(file_size_mb, 2),
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_engines": 0,
                "flagged_vendors": [],
                "error_message": f"Failed to get upload URL with HTTP status {response.status_code}",
            }
            return summary


def _analysis_summary(response, file_path: str) -> dict:
    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious > 0:
        verdict = "MALICIOUS"
    elif suspicious > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    flagged = [
        f"{vendor}: {details.get('result')}"
        for vendor, details in attributes.get("results", {}).items()
        if details.get("category") in ("malicious", "suspicious")
    ]
    return {
        "status": "success",
        "verdict": verdict,
        "sha256": data.get("meta", {}).get("file_info", {}).get("sha256"),
        "file_name": os.path.basename(file_path),
        "size_mb": round(os.path.getsize(file_path) / 1024 / 1024, 2),
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": sum(stats.values()),
        "flagged_vendors": flagged,
        "error_message": None,
    }


def _analysis_error(file_path: str, message: str) -> dict:
    return {
        "status": "error",
        "verdict": "ERROR",
        "sha256": get_file_sha256(file_path),
        "file_name": os.path.basename(file_path),
        "size_mb": round(os.path.getsize(file_path) / 1024 / 1024, 2),
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_engines": 0,
        "flagged_vendors": [],
        "error_message": message,
    }


def check_analysis_report(analysis_id: str, headers: dict, file_path: str) -> dict:
    url = f"{VT_API_URL}analyses/{analysis_id}"
    delay = 30
    max_tries = 8

    for attempt in range(1, max_tries + 1):
        response = safe_vt_request("GET", url, headers=headers)

        if response.status_code != 200:
            summary = _analysis_error(
                file_path,
                f"Failed to retrieve analysis status with HTTP status {response.status_code}",
            )
            return summary

        analysis_data = response.json()
        status = analysis_data["data"]["attributes"]["status"]

        if status == "completed":
            print(f"Analysis completed on attempt {attempt}")
            summary = _analysis_summary(response, file_path)
            return summary

        print(
            f"[Attempt {attempt}/{max_tries}] Analysis status: '{status}'. Checking again in {delay}s..."
        )

        time.sleep(delay)
        delay = min(delay * 2, 120)

    summary = {
        "status": "timeout",
        "verdict": "TIMEOUT",
        "sha256": get_file_sha256(file_path),
        "file_name": os.path.basename(file_path),
        "size_mb": round(os.path.getsize(file_path) / 1024 / 1024, 2),
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_engines": 0,
        "flagged_vendors": [],
        "error_message": f"Analysis timed out after {max_tries} attempts",
    }
    return summary
