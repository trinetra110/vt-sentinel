import queue
import threading
import time
import os
import shutil
from plyer import notification
from vt_file_client import check_file_by_hash
from vt_url_client import check_url
from logger import log_scan_summary

FOLDER_PATH = os.getenv("FOLDER_PATH", ".")
CLEAN_DIR = os.getenv("CLEAN_FOLDER_PATH", os.path.join(FOLDER_PATH, "Clean"))
QUARANTINE_DIR = os.getenv(
    "QUARANTINE_FOLDER_PATH", os.path.join(FOLDER_PATH, "Quarantined")
)

os.makedirs(CLEAN_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

task_queue = queue.Queue()
_worker_started = False
_worker_lock = threading.Lock()


def _is_file_stable(
    file_path: str, poll_interval: float = 1.0, max_wait_sec: int = 60
) -> bool:
    start_time = time.time()
    last_size = -1

    while time.time() - start_time < max_wait_sec:
        if not os.path.exists(file_path):
            return False

        try:
            current_size = os.path.getsize(file_path)
            if current_size == last_size:
                return True
            last_size = current_size
        except OSError:
            pass

        time.sleep(poll_interval)

    return os.path.exists(file_path)


def _route_file(file_path: str, verdict: str) -> None:
    if verdict == "CLEAN":
        dest_dir = CLEAN_DIR
    elif verdict in ["MALICIOUS", "SUSPICIOUS"]:
        dest_dir = QUARANTINE_DIR
    else:
        return

    filename = os.path.basename(file_path)
    dest_path = os.path.join(dest_dir, filename)

    if os.path.exists(dest_path):
        base, ext = os.path.splitext(filename)
        dest_path = os.path.join(dest_dir, f"{base}_{int(time.time())}{ext}")

    try:
        shutil.move(file_path, dest_path)
        print(f"[Router] Moved {filename} -> {dest_dir}")
    except Exception as e:
        print(f"[Router] Failed to move {filename}: {e}")


def _notify_result(summary: dict) -> None:
    verdict = summary.get("verdict", "ERROR")
    target_name = summary.get("target") or summary.get("file_name", "Unknown")

    if verdict in ["MALICIOUS", "SUSPICIOUS"]:
        title = f"ALERT: {verdict} Target Detected!"
    elif verdict in ["ERROR", "TIMEOUT"]:
        title = f"Scan Issue: {verdict}"
    else:
        return

    try:
        notification.notify(
            title=title,
            message=f"Target: {target_name}",
            app_name="VT Scanner",
        )
    except Exception as e:
        print(f"[Notification] Failed to send desktop alert: {e}")


def _queue_worker() -> None:
    while True:
        task_type, item = task_queue.get()

        try:
            if task_type == "file":
                file_path = item
                print(
                    f"\n[Queue Manager] Picked up file: {os.path.basename(file_path)}"
                )

                if not _is_file_stable(file_path):
                    print(f"[Queue Manager] File unreadable or missing: {file_path}")
                    continue

                summary = check_file_by_hash(file_path)
                log_scan_summary(summary)
                _notify_result(summary)
                _route_file(file_path, summary.get("verdict"))

            elif task_type == "url":
                target_url = item
                print(f"\n[Queue Manager] Picked up URL: {target_url}")

                summary = check_url(target_url)
                log_scan_summary(summary)
                _notify_result(summary)

        except Exception as e:
            print(
                f"[Queue Manager] Unexpected error processing {task_type} '{item}': {e}"
            )
        finally:
            task_queue.task_done()


def start_queue_worker() -> None:
    global _worker_started
    with _worker_lock:
        if not _worker_started:
            worker_thread = threading.Thread(target=_queue_worker, daemon=True)
            worker_thread.start()
            _worker_started = True
            print("[Queue Manager] Background worker thread started.")


def add_file_to_queue(file_path: str) -> None:
    start_queue_worker()
    task_queue.put(("file", file_path))
    print(f"[Queue Manager] Added file to queue: {os.path.basename(file_path)}")


def add_url_to_queue(target_url: str) -> None:
    start_queue_worker()
    task_queue.put(("url", target_url))
    print(f"[Queue Manager] Added URL to queue: {target_url}")


def wait_for_completion() -> None:
    task_queue.join()
