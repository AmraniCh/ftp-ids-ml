from ftp_ids.core.storage import Storage
from datetime import date
import ftp_ids.config as config

def compute_stats():
    #storage = Storage()
    
    return {
        "events_today": _count_events_today(),
        # "alerts_today": alerts_today,
        # "pending": pending,
        # "unique_ips_today": unique_ips_today,
    }

    
def _count_events_today():
    # TODO raise error if the logs file not exist
    today_prefix = date.today().strftime("%a %b %e")
    with open(config.LOGS_PATH, "r", errors="replace") as f:
        return sum(1 for line in f if line.startswith(today_prefix))
