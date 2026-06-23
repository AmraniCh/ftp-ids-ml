from ftp_ids.core.storage import Storage

def list_alerts(page=1, per_page=12):
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

    total = len(result)
    start = (page - 1) * per_page
    end = start + per_page
    
    return {
        "items": result[start:end],
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": (total + per_page - 1) // per_page,
    }


def get_alert(src_ip, start_time):
    storage = Storage()
    alerts = storage.load_alerts()
    for _, row in alerts.iterrows():
        if row["src_ip"] == src_ip and str(row["start_time"]) == start_time:
            return row.to_dict()
    return None