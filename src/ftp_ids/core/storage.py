from ftp_ids import config
from ftp_ids.core.feature_extractor import FEATURE_NAMES
from pathlib import Path
import csv
import pandas as pd
from datetime import datetime

class Storage:

    def append_alert(self, session, score, features):
        row = {
            "src_ip":     session["src_ip"],
            "user":       session["user"] or "",
            "start_time": session["start_time"].isoformat(),
            "end_time":   session["end_time"].isoformat(),
            "n_events":   session["n_events"],
            "end_type":   session["end_type"],
            "score":      round(score, 4),
            **features,
        }

        fieldnames = [
            "src_ip", "user", "start_time", "end_time", "n_events", "end_type", "score",
            *FEATURE_NAMES,
        ]

        self._append_row(config.ALERTS_PATH, row, fieldnames)

    def load_alerts(self):
        if not Path(config.ALERTS_PATH).exists():
            return pd.DataFrame()
        return pd.read_csv(config.ALERTS_PATH)

    def clear_alerts(self):
        if Path(config.ALERTS_PATH).exists():
            Path(config.ALERTS_PATH).unlink()

    def add_to_clean_pool(self, rows):
        needed = ["src_ip", "start_time", *FEATURE_NAMES]
        rows = rows[needed].copy()
        rows["corrected_at"] = datetime.now().isoformat()

        if Path(config.CLEAN_POOL_PATH).exists():
            pool = pd.read_csv(config.CLEAN_POOL_PATH)
            new_keys = set(zip(rows["src_ip"], rows["start_time"]))
            pool = pool[~pool.apply(
                lambda r: (r["src_ip"], r["start_time"]) in new_keys, axis=1
            )]
            pool = pd.concat([pool, rows], ignore_index=True)
        else:
            pool = rows

        pool.to_csv(config.CLEAN_POOL_PATH, index=False)
        return len(pool)
    
    def load_clean_pool(self):
        if not Path(config.CLEAN_POOL_PATH).exists():
            return pd.DataFrame(columns=["src_ip", "start_time", *FEATURE_NAMES])
        return pd.read_csv(config.CLEAN_POOL_PATH)

    def clear_clean_pool(self):
        if Path(config.CLEAN_POOL_PATH).exists():
            Path(config.CLEAN_POOL_PATH).unlink()

    def _append_row(self, path, row, fieldnames):
        file_exists = Path(path).exists()
        with open(path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)