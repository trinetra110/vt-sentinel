import os
import time
import argparse
import sys

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from queue_manager import (
    add_file_to_queue,
    add_url_to_queue,
    wait_for_completion,
    FOLDER_PATH,
    CLEAN_DIR,
    QUARANTINE_DIR,
)

IGNORED_EXTS = {".tmp", ".crdownload", ".part"}
IGNORED_DIRS = {os.path.abspath(CLEAN_DIR), os.path.abspath(QUARANTINE_DIR)}


def is_valid_target(file_path: str) -> bool:
    """Determines if a filesystem item should be scanned."""
    abs_path = os.path.abspath(file_path)

    for ignored_dir in IGNORED_DIRS:
        if abs_path.startswith(ignored_dir):
            return False

    file_ext = os.path.splitext(file_path)[1].lower()
    if file_ext in IGNORED_EXTS:
        return False

    return True


class DownloadMonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        if is_valid_target(event.src_path):
            print(f"[Watchdog] New file detected: {os.path.basename(event.src_path)}")
            add_file_to_queue(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        if is_valid_target(event.dest_path):
            print(
                f"[Watchdog] File download completed: {os.path.basename(event.dest_path)}"
            )
            add_file_to_queue(event.dest_path)


def run_file_sweep():
    print(f"[INFO] Scanning existing unprocessed files in {FOLDER_PATH}...")
    if os.path.exists(FOLDER_PATH):
        for entry in os.scandir(FOLDER_PATH):
            if entry.is_file() and is_valid_target(entry.path):
                add_file_to_queue(entry.path)

    wait_for_completion()
    print("[INFO] File sweep mode completed.")


def run_file_watchdog():
    print(f"[INFO] Monitoring {FOLDER_PATH} for new files in real-time...")
    event_handler = DownloadMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, FOLDER_PATH, recursive=False)

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping watchdog observer. Waiting for queue to finish...")
        observer.stop()

    observer.join()
    wait_for_completion()
    print("[INFO] Application exited safely.")


def process_single_url(target_url: str):
    print(f"[INFO] Queueing URL for scan: {target_url}")
    add_url_to_queue(target_url)
    wait_for_completion()
    print("[INFO] URL scan completed.")


def process_url_file(file_path: str):
    if not os.path.exists(file_path):
        print(f"[ERROR] URL list file not found: {file_path}")
        sys.exit(1)

    print(f"[INFO] Reading URLs from {file_path}...")
    count = 0
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if url and not url.startswith("#"):
                add_url_to_queue(url)
                count += 1

    print(f"[INFO] Queued {count} URLs from file.")
    wait_for_completion()
    print("[INFO] Batch URL scan completed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="VirusTotal Automated Malware & Threat Scanner (Files & URLs)"
    )

    parser.add_argument(
        "--target",
        type=str,
        default="file",
        choices=["file", "url"],
        help="Target type to scan ('file' or 'url'). Default is 'file'.",
    )

    parser.add_argument(
        "--mode",
        type=str,
        default="sweep",
        choices=["sweep", "watch"],
        help="For file targets: 'sweep' to scan existing files once, 'watch' for real-time monitoring.",
    )

    parser.add_argument(
        "--url",
        type=str,
        help="Single URL string to scan when --target=url.",
    )

    parser.add_argument(
        "--file",
        type=str,
        help="Path to a text file containing URLs (one per line) when --target=url.",
    )

    args = parser.parse_args()

    if args.target == "file":
        if not FOLDER_PATH or not os.path.exists(FOLDER_PATH):
            print(f"[ERROR] Target folder path does not exist: {FOLDER_PATH}")
            sys.exit(1)

        if args.mode == "sweep":
            run_file_sweep()
        elif args.mode == "watch":
            run_file_watchdog()
        else:
            print(
                "[ERROR] Invalid mode for file target. Use '--mode sweep' or '--mode watch'."
            )
            sys.exit(1)
            
    elif args.target == "url":
        if args.url:
            process_single_url(args.url)
        elif args.file:
            process_url_file(args.file)
        else:
            print(
                "[ERROR] For --target url, you must provide either '--url <URL>' or '--file <path_to_txt_file>'."
            )
            sys.exit(1)
