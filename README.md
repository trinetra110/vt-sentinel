# VT-Sentinel (VirusTotal Malware Scanner)

A modular, thread-safe Python security agent utilizing the VirusTotal v3 API. This tool provides continuous filesystem monitoring, automated file quarantine, bulk URL scanning, sliding-window rate limiting, and native OS desktop alerts.

## Features

- **File Scanning**: Monitor directories in real-time or sweep existing files.
- **URL Scanning**: Check individual links or process batch text files.
- **Automated Routing**: Automatically moves malicious files to a Quarantine folder and safe files to a Clean folder.
- **Rate Limiting**: Thread-safe sliding window ensures compliance with the free VirusTotal API quota (4 requests per minute).
- **Desktop Notifications**: Native OS alerts for malicious or suspicious findings.
- **Audit Logging**: Comprehensive UTF-8 logging of all scan summaries.

## Prerequisites

- Python 3.7 or higher
- VirusTotal API Key (Free tier)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/trinetra110/vt-sentinel.git
   cd vt-sentinel
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Configure the environment variables:
   - Rename `.env.example` to `.env`.
   - Add your VirusTotal API key and configure your target directories.

## Usage

The application is controlled entirely through `main.py` using CLI arguments.

### File Targets

Scan all existing unprocessed files in the target folder:

```bash
python main.py --target file --mode sweep
```

Monitor the target folder continuously for new downloads:

```bash
python main.py --target file --mode watch
```

### URL Targets

Scan a single URL:

```bash
python main.py --target url --url "https://example.com"
```

Scan a list of URLs from a text file (one URL per line, supports `#` comments):

```bash
python main.py --target url --file "urls.txt"
```

## File Structure

```text
vt-sentinel/
├── .env                  # Environment variables (API keys and paths)
├── .gitignore            # Git exclusion rules
├── README.md             # Project documentation
├── requirements.txt      # Python dependencies
├── logger.py             # Event and threat logging module
├── main.py               # Unified CLI entry point
├── queue_manager.py      # Background worker and task queue handling
├── vt_file_client.py     # VirusTotal v3 API logic for file hashes/uploads
└── vt_url_client.py      # VirusTotal v3 API logic for URL scanning
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
