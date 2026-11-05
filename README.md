# VT-Sentinel (VirusTotal Malware Scanner)

A modular, thread-safe Python security agent utilizing the VirusTotal v3 API. This tool provides continuous filesystem monitoring, automated file quarantine, bulk URL scanning, sliding-window rate limiting, and native OS desktop alerts.

## Features

* **Global CLI Tool**: Run `vt-sentinel` from anywhere on your system.
* **Interactive Setup**: Zero-touch configuration wizard to set up your API keys and folders.
* **File Scanning**: Monitor directories in real-time or sweep existing files.
* **URL Scanning**: Check individual links or process batch text files.
* **Automated Routing**: Automatically moves malicious files to a Quarantine folder and safe files to a Clean folder.
* **Rate Limiting**: Thread-safe sliding window ensures compliance with the free VirusTotal API quota (4 requests per minute).
* **Desktop Notifications**: Native OS alerts for malicious or suspicious findings.
* **Centralized Logging**: Comprehensive UTF-8 logging of all scan summaries stored globally.

## Prerequisites

* VirusTotal API Key (Free tier)
* *Optional:* Python 3.11+ and `pipx` (only required if not using the standalone binary)

## Installation

Choose the installation method that best fits your environment.

### Option 1: Standalone Binary (Recommended for non-technical users)

You do not need Python installed for this method. Download the executable for your OS from the **Releases** tab on GitHub.

**Windows:**
Open Command Prompt or PowerShell:
```powershell
cd Downloads
.\vt-sentinel-windows.exe --setup
.\vt-sentinel-windows.exe --target file --mode sweep
```

**Linux:**
Open your terminal and grant execution permissions:
```bash
cd ~/Downloads
chmod +x vt-sentinel-linux
./vt-sentinel-linux --setup
./vt-sentinel-linux --target file --mode watch
```

**macOS:**
Open your terminal and grant execution permissions:
```bash
cd ~/Downloads
chmod +x vt-sentinel-macos
./vt-sentinel-macos --setup
./vt-sentinel-macos --target url --url "https://example.com"
```
*(Note: If macOS Gatekeeper blocks the file because it is an unrecognized developer, you can clear the quarantine flag by running: `xattr -d com.apple.quarantine vt-sentinel-macos`)*

### Option 2: Install globally via pipx (Recommended for Python users)

This installs `vt-sentinel` into an isolated virtual environment and adds it to your global system path.

```bash
pipx install git+https://github.com/trinetra110/vt-sentinel.git
```

### Option 3: Install from Source (For Developers)

```bash
git clone https://github.com/trinetra110/vt-sentinel.git
cd vt-sentinel
pip install -e .
```
*Developer Note:* You can configure the application using the interactive `vt-sentinel --setup` command, or manually reference the provided `.env.example` file to build your own configuration.

## Configuration

VT-Sentinel features an interactive setup wizard. You no longer need to manually edit configuration files. Run the following command and follow the prompts:

```bash
vt-sentinel --setup
```

*Note: Your configuration and logs are safely stored in your global home directory at `~/VT-SENTINEL/`.*

## Usage

The application is controlled entirely through the unified `vt-sentinel` command. 
*(If you downloaded the binary, replace `vt-sentinel` with your downloaded file's name, e.g., `.\vt-sentinel-windows.exe`)*

### File Targets

Scan all existing unprocessed files in the target folder:
```bash
vt-sentinel --target file --mode sweep
```

Monitor the target folder continuously for new downloads:
```bash
vt-sentinel --target file --mode watch
```

### URL Targets

Scan a single URL:
```bash
vt-sentinel --target url --url "https://example.com"
```

Scan a list of URLs from a text file (one URL per line, supports `#` comments):
```bash
vt-sentinel --target url --file "urls.txt"
```

## File Structure & Architecture

```text
~/VT-SENTINEL/            # Global User Directory (Auto-generated)
├── .vt-sentinel.env      # Plain-text environment variables (API key and paths)
└── scan_history.log      # Centralized audit logs

vt-sentinel/              # Source Code
├── README.md             # Project documentation
├── pyproject.toml        # Build and packaging configuration
├── config.py             # Global state and setup logic
├── logger.py             # Event and threat logging module
├── main.py               # Unified CLI entry point
├── queue_manager.py      # Background worker and task queue handling
├── vt_file_client.py     # VirusTotal v3 API logic for file hashes/uploads
└── vt_url_client.py      # VirusTotal v3 API logic for URL scanning
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.