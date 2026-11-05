import os
from pathlib import Path
from dotenv import load_dotenv

CONFIG_PATH = Path.home() / "VT-SENTINEL" / ".vt-sentinel.env"


def load_env():
    if CONFIG_PATH.exists():
        load_dotenv(CONFIG_PATH)
    load_dotenv()


def run_setup():
    print("\n=== VT-Sentinel Interactive Setup ===")
    api_key = input("Enter your VirusTotal API Key: ").strip()

    if not api_key:
        print("[ERROR] VirusTotal API Key cannot be empty.")
        return

    os.makedirs(CONFIG_PATH.parent, exist_ok=True)

    default_folder = (
        os.path.expanduser("~/Downloads")
        if os.path.exists(os.path.expanduser("~/Downloads"))
        else os.getcwd()
    )
    folder_input = input(f"Enter folder path to monitor [{default_folder}]: ").strip()

    target_folder = (
        os.path.abspath(os.path.expanduser(folder_input))
        if folder_input
        else default_folder
    )
    clean_folder = os.path.join(target_folder, "clean")
    quarantine_folder = os.path.join(target_folder, "quarantine")

    env_content = (
        f"VT_API_KEY={api_key}\n"
        f"FOLDER_PATH={target_folder}\n"
        f"CLEAN_FOLDER_PATH={clean_folder}\n"
        f"QUARANTINE_FOLDER_PATH={quarantine_folder}\n"
    )

    CONFIG_PATH.write_text(env_content, encoding="utf-8")

    try:
        os.chmod(CONFIG_PATH, 0o600)
    except Exception:
        pass

    os.makedirs(clean_folder, exist_ok=True)
    os.makedirs(quarantine_folder, exist_ok=True)

    print(f"\n[+] Configuration saved successfully to: {CONFIG_PATH}")
    print(f"[+] Target Folder: {target_folder}")
    print(f"[+] Clean Directory: {clean_folder}")
    print(f"[+] Quarantine Directory: {quarantine_folder}\n")
