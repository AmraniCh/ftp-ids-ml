from ftp_ids.core.storage import Storage
from datetime import date
import ftp_ids.config as config

def compute_stats():
    storage = Storage()
    alerts = storage.load_alerts()
    today = date.today().isoformat()
    alerts_today = 0
    unique_ips_today = set()

    for _,row in alerts.iterrows():
        if row['start_time'].startswith(today):
            alerts_today += 1
            unique_ips_today.add(row['src_ip'])

    return {
        "events_today": _count_events_today(),
        "alerts_today": alerts_today,
        # "pending": pending,
        "unique_ips_today": len(unique_ips_today),
    }

    
def _count_events_today():
    # TODO raise error if the logs file not exist
    today_prefix = date.today().strftime("%a %b %e")
    with open(config.LOGS_PATH, "r", errors="replace") as f:
        return sum(1 for line in f if line.startswith(today_prefix))


print(compute_stats())