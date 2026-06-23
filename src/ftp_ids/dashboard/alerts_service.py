from ftp_ids.core.storage import Storage

def list_alerts():
    storage = Storage()
    alerts = storage.load_alerts()
    pool = storage.load_clean_pool()

    pool_keys = set()
    if not pool.empty:
        for _, row in pool.iterrows():
            pool_keys.add((row["src_ip"], str(row["start_time"])))

    result = []
    for _, row in alerts.iterrows():
        item = row.to_dict()
        item["labeled"] = (item["src_ip"], str(item["start_time"])) in pool_keys
        result.append(item)

    result.sort(key=lambda r: r.get("labeled", False))
    return result


def get_alert(src_ip, start_time):
    storage = Storage()
    alerts = storage.load_alerts()
    for _, row in alerts.iterrows():
        if row["src_ip"] == src_ip and str(row["start_time"]) == start_time:
            return row.to_dict()
    return None