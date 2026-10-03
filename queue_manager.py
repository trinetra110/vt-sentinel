import queue
import threading
import time
import os
import shutil
from plyer import notification
from vt_file_client import check_file_by_hash, headers
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
    """Waits dynamically until file size stops growing or the file is deleted."""
    start_time = time.time()
    last_size = -1

    while time.time() - start_time < max_wait_sec:
        # Check on every loop iteration if file was moved or deleted by AV
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
    """Moves the scanned file to the appropriate directory based on its verdict."""
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
    """Triggers a desktop notification ONLY for threats or errors."""
    verdict = summary.get("verdict", "ERROR")
    file_name = summary.get("file_name", "Unknown")

    if verdict in ["MALICIOUS", "SUSPICIOUS"]:
        title = f"ALERT: {verdict} File Detected!"
    elif verdict in ["ERROR", "TIMEOUT"]:
        title = f"Scan Issue: {verdict}"
    else:
        return

    try:
        notification.notify(
            title=title,
            message=f"File: {file_name}",
            app_name="VT Scanner",
        )
    except Exception as e:
        print(f"[Notification] Failed to send desktop alert: {e}")


def _queue_worker() -> None:
    """Background worker thread consuming queued file paths sequentially."""
    while True:
        file_path = task_queue.get()

        try:
            print(f"\n[Queue Manager] Picked up file: {os.path.basename(file_path)}")

            if not _is_file_stable(file_path):
                print(
                    f"[Queue Manager] File unreadable or missing (possibly deleted by AV): {file_path}"
                )
                continue

            # Execute scan via VirusTotal API client
            summary = check_file_by_hash(file_path, headers)

            # Persist summary to scan_history.log
            log_scan_summary(summary)

            # Notify the user of the result
            _notify_result(summary)

            # Route the file to Clean or Quarantine
            _route_file(file_path, summary.get("verdict"))

        except Exception as e:
            print(f"[Queue Manager] Unexpected error processing {file_path}: {e}")
        finally:
            task_queue.task_done()


def start_queue_worker() -> None:
    """Spawns the background worker thread if not already running."""
    global _worker_started
    with _worker_lock:
        if not _worker_started:
            worker_thread = threading.Thread(target=_queue_worker, daemon=True)
            worker_thread.start()
            _worker_started = True
            print("[Queue Manager] Background worker thread started.")


def add_file_to_queue(file_path: str) -> None:
    """Public interface to add a file path to the processing queue."""
    start_queue_worker()
    task_queue.put(file_path)
    print(f"[Queue Manager] Added to queue: {os.path.basename(file_path)}")


def wait_for_completion() -> None:
    """Blocks execution until all queued files have been scanned."""
    task_queue.join()
