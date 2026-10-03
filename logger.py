import logging

LOG_FILE = "scan_history.log"


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("VT_Scanner")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def log_scan_summary(summary: dict, logger: logging.Logger = None) -> None:
    if logger is None:
        logger = setup_logger()

    status = summary.get("status", "error")
    target_name = summary.get("target") or summary.get("file_name", "Unknown Target")
    identifier = summary.get("sha256", "")
    id_str = ""
    if identifier:
        id_str = f" | SHA256: {identifier}"

    if status in ["error", "timeout"]:
        err_msg = summary.get("error_message", "Unknown error")
        logger.error(
            f"STATUS: {status.upper()} | Target: {target_name}{id_str} | Details: {err_msg}"
        )
        return

    verdict = summary.get("verdict", "UNKNOWN")
    malicious = summary.get("malicious_count", 0)
    suspicious = summary.get("suspicious_count", 0)
    total = summary.get("total_engines", 0)
    flagged = summary.get("flagged_vendors", [])

    log_msg = f"VERDICT: {verdict} | Target: {target_name}{id_str} | Detections: {malicious + suspicious}/{total}"
    if flagged:
        log_msg += f" | Flagged By: {', '.join(flagged)}"

    if verdict in ["MALICIOUS", "SUSPICIOUS"]:
        logger.warning(log_msg)
    else:
        logger.info(log_msg)
