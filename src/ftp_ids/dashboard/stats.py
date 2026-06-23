from ftp_ids.core.storage import Storage
from datetime import date
import ftp_ids.config as config
import subprocess

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

    clean_pool = storage.load_clean_pool()

    print("is watching: ", is_watch_running())

    return {
        "events_today": _count_events_today(),
        "alerts_today": alerts_today,
        "pending": len(alerts) - len(clean_pool),
        "unique_ips_today": len(unique_ips_today),
        "is_watching": is_watch_running(),
    }


def alerts_per_hour():
    storage = Storage()
    alerts = storage.load_alerts()
    today = date.today().isoformat()

    buckets = [0] * 24
    for _, row in alerts.iterrows():
        ts = str(row["start_time"])
        if ts.startswith(today):
            hour = int(ts.split("T")[1][:2])
            buckets[hour] += 1

    return buckets

def is_watch_running() -> bool:
    try:
        result = subprocess.run(["pgrep", "-f", "ftp-ids watch"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False
    
def _count_events_today():
    # TODO raise error if the logs file not exist
    today_prefix = date.today().strftime("%a %b %e")
    with open(config.LOGS_PATH, "r", errors="replace") as f:
        return sum(1 for line in f if line.startswith(today_prefix))


print(compute_stats())