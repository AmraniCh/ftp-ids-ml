from pathlib import Path

DAEMON_LOG_PATHS = {
    "vsftpd":  "/var/log/vsftpd.log",
}

def _autodetect_log_path() -> str | None:
    for path in DAEMON_LOG_PATHS.values():
        if Path(path).exists():
            return path
        
    return None

LOGS_PATH = _autodetect_log_path()
MODEL_PATH = "data/models/iso_forest.pkl"
CONTAMINATION = 0.05 

ALERTS_PATH     = "data/reports/alerts.csv"
CLEAN_POOL_PATH = "data/reports/clean_pool.csv"
