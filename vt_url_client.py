import base64
import os
import sys
import time
import requests
import json
from dotenv import load_dotenv

from vt_file_client import safe_vt_request

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

VT_API_URL = "https://www.virustotal.com/api/v3/"
headers = {"accept": "application/json", "x-apikey": VT_API_KEY}


def get_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_url(target_url: str) -> dict:
    url_id = get_url_id(target_url)
    api_endpoint = f"{VT_API_URL}urls/{url_id}"

    response = safe_vt_request("GET", api_endpoint, headers=headers)

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

        flagged_vendors = [
            f"{vendor}: {details.get('result')}"
            for vendor, details in attr.get("last_analysis_results", {}).items()
            if details.get("category") in ["malicious", "suspicious"]
        ]

        return {
            "status": "success",
            "verdict": verdict,
            "target": attr.get("url", target_url),
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "total_engines": sum(stats.values()),
            "flagged_vendors": flagged_vendors,
            "error_message": None,
        }

    elif response.status_code == 404:
        print("[VT URL Client] URL not found in database. Submitting for fresh scan...")
        return submit_url_for_analysis(target_url)

    else:
        return {
            "status": "error",
            "verdict": "ERROR",
            "target": target_url,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "flagged_vendors": [],
            "error_message": f"URL lookup failed with HTTP status {response.status_code}",
        }


def submit_url_for_analysis(target_url: str) -> dict:
    api_endpoint = f"{VT_API_URL}urls"
    payload = {"url": target_url}

    response = safe_vt_request("POST", api_endpoint, headers=headers, data=payload)

    if response.status_code == 200:
        data = response.json()
        analysis_id = data.get("data", {}).get("id")
        print(
            f"[VT URL Client] Scan submitted successfully. Analysis ID: {analysis_id}"
        )
        time.sleep(15)
        return check_analysis_report(analysis_id, target_url)
    else:
        return {
            "status": "error",
            "verdict": "ERROR",
            "target": target_url,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "flagged_vendors": [],
            "error_message": f"URL submission failed with HTTP status {response.status_code}",
        }


def _analysis_summary(response: requests.Response, target_url: str) -> dict:
    json_data = response.json()
    attr = json_data.get("data", {}).get("attributes", {})
    stats = attr.get("stats", {})

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
        for vendor, details in attr.get("results", {}).items()
        if details.get("category") in ("malicious", "suspicious")
    ]

    resolved_url = (
        attr.get("url")
        or json_data.get("meta", {}).get("url_info", {}).get("url")
        or target_url
    )

    return {
        "status": "success",
        "verdict": verdict,
        "target": resolved_url,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": sum(stats.values()),
        "flagged_vendors": flagged,
        "error_message": None,
    }


def check_analysis_report(analysis_id: str, target_url: str) -> dict:
    api_endpoint = f"{VT_API_URL}analyses/{analysis_id}"
    delay = 15
    max_tries = 8

    for attempt in range(1, max_tries + 1):
        response = safe_vt_request("GET", api_endpoint, headers=headers)

        if response.status_code != 200:
            return {
                "status": "error",
                "verdict": "ERROR",
                "target": target_url,
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_engines": 0,
                "flagged_vendors": [],
                "error_message": f"Failed to retrieve report with HTTP status {response.status_code}",
            }

        analysis_data = response.json()
        status = analysis_data.get("data", {}).get("attributes", {}).get("status")

        if status == "completed":
            print(f"[VT URL Client] Analysis completed on attempt {attempt}")
            return _analysis_summary(response, target_url)

        print(
            f"[VT URL Client] [Attempt {attempt}/{max_tries}] Status: '{status}'. Checking again in {delay}s..."
        )
        time.sleep(delay)
        delay = min(delay * 2, 60)

    return {
        "status": "timeout",
        "verdict": "TIMEOUT",
        "target": target_url,
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_engines": 0,
        "flagged_vendors": [],
        "error_message": f"URL analysis timed out after {max_tries} attempts",
    }
