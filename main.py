import os
import time
import argparse
import sys

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification

from queue_manager import (
    add_file_to_queue,
    wait_for_completion,
    FOLDER_PATH,
    CLEAN_DIR,
    QUARANTINE_DIR,
)

# Set up exclusion paths to prevent infinite loops and re-scanning
IGNORED_EXTS = {".tmp", ".crdownload", ".part"}
IGNORED_DIRS = {os.path.abspath(CLEAN_DIR), os.path.abspath(QUARANTINE_DIR)}


def is_valid_target(file_path: str) -> bool:
    """Helper function to determine if a file should be scanned."""
    abs_path = os.path.abspath(file_path)

    # 1. Ignore if the file is inside the Clean or Quarantine directories
    for ignored_dir in IGNORED_DIRS:
        if abs_path.startswith(ignored_dir):
            return False

    # 2. Ignore temporary browser download extensions
    file_ext = os.path.splitext(file_path)[1].lower()
    if file_ext in IGNORED_EXTS:
        return False

    return True


class DownloadMonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        """Triggered when a file is directly copied or created in the folder."""
        if event.is_directory:
            return

        if is_valid_target(event.src_path):
            print(f"[Watchdog] New file detected: {os.path.basename(event.src_path)}")
            add_file_to_queue(event.src_path)

    def on_moved(self, event):
        """Triggered when a browser finishes downloading and renames .crdownload to the final extension."""
        if event.is_directory:
            return

        # We check the dest_path (the new name of the file after renaming)
        if is_valid_target(event.dest_path):
            print(
                f"[Watchdog] File download completed: {os.path.basename(event.dest_path)}"
            )
            add_file_to_queue(event.dest_path)


def run_sweep():
    print(f"[INFO] Scanning existing unprocessed files in {FOLDER_PATH}...")

    # Using os.scandir for a flat scan of the root directory only.
    # This prevents digging into old subfolders recursively.
    if os.path.exists(FOLDER_PATH):
        for entry in os.scandir(FOLDER_PATH):
            if entry.is_file() and is_valid_target(entry.path):
                add_file_to_queue(entry.path)

    wait_for_completion()
    print("[INFO] Sweep mode completed.")


def run_watchdog():
    print(f"[INFO] Monitoring {FOLDER_PATH} for new files in real-time...")

    event_handler = DownloadMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, FOLDER_PATH, recursive=False)

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(
            "\n[INFO] Stopping watchdog observer. Please wait for the current queue to finish..."
        )
        observer.stop()

    observer.join()
    wait_for_completion()
    print("[INFO] Application exited safely.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Monitor a directory for new files and scan for malware using the VirusTotal API."
    )

    parser.add_argument(
        "--mode",
        type=str,
        default="sweep",
        choices=["sweep", "watch"],
        help="'sweep' to scan existing files once, 'watch' to monitor the folder continuously.",
    )

    args = parser.parse_args()

    if not FOLDER_PATH or not os.path.exists(FOLDER_PATH):
        print(f"[ERROR] Target folder path does not exist: {FOLDER_PATH}")
        sys.exit(1)

    if args.mode == "sweep":
        run_sweep()
    elif args.mode == "watch":
        run_watchdog()
