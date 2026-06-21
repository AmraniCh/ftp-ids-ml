import argparse
from ftp_ids import config
from ftp_ids.parsers.vsftpd_parser import VsftpdParser
from pprint import pprint
from ftp_ids.core.session_builder import build_sessions
from ftp_ids.core.feature_extractor import FeatureExtractor, FEATURE_NAMES
from ftp_ids.core.detector import Detector
from ftp_ids.config import MODEL_PATH, CONTAMINATION
import pandas as pd
import time
from ftp_ids.core.storage import Storage

def main():
    parser = argparse.ArgumentParser(
        prog="ftp-ids",
        description="Host-based anomaly detection IDS for FTP servers",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ftp-ids parse [--log PATH] — parse a log and show stats
    parse_p = subparsers.add_parser("parse", help="Parse a log file and show stats")
    parse_p.add_argument("--log", default=config.LOGS_PATH, help="Path to FTP log file")

    sessions_p = subparsers.add_parser("sessions", help="Build and show sessions from a log")
    sessions_p.add_argument("--log", default=config.LOGS_PATH)
    sessions_p.add_argument("--show", action="store_true", help="Dump full session dicts (including events)")

    extract_p = subparsers.add_parser("extract", help="Extract features from sessions")
    extract_p.add_argument("--log", default=config.LOGS_PATH)
    
    train_p = subparsers.add_parser("train", help="Train the model on the spcified FTP logs")
    train_p.add_argument("--log", default=config.LOGS_PATH)

    watch_p = subparsers.add_parser("watch", description="Watch the specified log and score session in live")
    watch_p.add_argument("--log", default=config.LOGS_PATH)
    watch_p.add_argument("--threshold", type=float, default=0.7) 
    
    correct_p = subparsers.add_parser("correct", help="Apply admin labels from alerts.csv to the clean pool")

    retrain_p = subparsers.add_parser("retrain", help="Rebuild model with original log + clean pool")
    retrain_p.add_argument("--log", default=config.LOGS_PATH)

    args = parser.parse_args()

    
    if args.command == "correct":
        run_correct()
    else:    
        if args and args.log is None:
            parser.error("No FTP log file found. Specify one with --log.")

        if args.command == "parse":
            run_parse(args.log)

        if args.command == "sessions":
            run_sessions(args.log, args.show)

        if args.command == "extract":
            run_extract(args.log)

        if args.command == "train":
            run_train(args.log)

        if args.command == "watch":
            run_watch(args.log, args.threshold)

        if args.command == "retrain":
            run_retrain(args.log)



def run_parse(log_path: str, output=True) :
    p = VsftpdParser()
    events, failed = [], []
    with open(log_path, "r") as f: # TODO consider errors="replace" ?
        for line in f:
            event = p.parse_line(line)
            if event: events.append(event) 
            else: failed.append(line)
            if output: pprint(event if event else line)

    if output:
        print(f"parsed : {len(events)}")
        print(f"failed : {len(failed)}")

    return events

def run_sessions(log_path, show: bool = False):
    events = run_parse(log_path, output=False)
    sessions = build_sessions(events)

    if show:
        pprint(sessions)
        return
      
    print(f"Sessions: {len(sessions)}\n")
    print(f"{'SRC_IP':<16} {'USER':<20} {'END':<8} {'EVENTS':>6}  {'START':<19}  {'END':<19}")
    
    for s in sessions:
        print(f"{s['src_ip']:<16} {s['user'] or '-':<20} {s['end_type']:<8} "
              f"{s['n_events']:>6}  {s['start_time']}  {s['end_time']}")

    return sessions

# features extracting
def run_extract(log_path, show: bool = False):
    events = run_parse(log_path, output=False)
    sessions = build_sessions(events)

    if not sessions: 
        return []

    fe = FeatureExtractor()
    featues = fe.extract_batch(sessions)
    pprint(featues)


def run_train(log_path):
    events = run_parse(log_path, output=False)
    sessions = build_sessions(events)
    
    fe = FeatureExtractor()
    features = fe.extract_batch(sessions)

    df = pd.DataFrame(features)
    print(df)
    
    dt = Detector(model_path=MODEL_PATH, contamination=CONTAMINATION)
    dt.train(sessions)
    
    storage = Storage()
    storage.clear_alerts()
    storage.clear_clean_pool()
    # TODO threshild is hardcoded here
    for i,s in enumerate(sessions):
        score = dt.score(s)
        if score >= 0.7:
            features = dt.extractor.extract(s)
            storage.append_alert(s, score, features)
            print(f"{i}: ALERT  {score:.2f}  {s['src_ip']} user={s['user'] or 'N/A'}")
        else:
            print(f"{i}: ok    {score:.2f}  {s['src_ip']} user={s['user'] or 'N/A'}")


def run_watch(log_path: str, threshold: float):
    def tail(path):
        with open(path, "r") as f:
            f.seek(0, 2) 
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.3)
                    continue
                yield line

    parser = VsftpdParser()
    storage = Storage()
    detector = Detector(model_path=MODEL_PATH, contamination=CONTAMINATION)
    if not detector.load_model():
        print("No model. Train first: ftp-ids train")
        return

    print(f"watching {log_path}, threshold={threshold}")

    buffer = []  
    seen_session_keys = set()

    for line in tail(log_path):
        event = parser.parse_line(line)
        if not event:
            continue
        buffer.append(event)

        if not event["session_end"]:
            continue

        sessions = build_sessions(buffer)

        for s in sessions:
            key = (s["src_ip"], s["start_time"])
            if key in seen_session_keys:
                continue
            score = detector.score(s)
            seen_session_keys.add(key)

            if score >= threshold:
                features = detector.extractor.extract(s)
                storage.append_alert(s, score, features)
                print(f"ALERT  {score:.2f}  {s['src_ip']} user={s['user'] or 'N/A'}")
            else:
                print(f"ok    {score:.2f}  {s['src_ip']} user={s['user'] or 'N/A'}")
    

def run_correct():
    storage = Storage()
    df = storage.load_alerts()

    if df.empty:
        print("No alerts.csv yet")
        return

    if "label" not in df.columns:
        print(f"No 'label' column in {config.ALERTS_PATH}")
        return

    valid = {"normal", "attack"}
    invalid = df[~df["label"].isin(valid)]
    if not invalid.empty:
        print(f"Invalid labels, must be 'normal' or 'attack'")
        print(invalid[["src_ip", "start_time", "label"]])
        return

    false_positives = df[df["label"] == "normal"]
    confirmed       = df[df["label"] == "attack"]

    print(f"False positives (-> clean pool): {len(false_positives)}")
    print(f"Confirmed attacks:               {len(confirmed)}")

    if len(false_positives) == 0:
        print("Nothing to add to clean pool.")
        return

    new_size = storage.add_to_clean_pool(false_positives)
    print(f"Clean pool now has {new_size} session(s).")
    print(f"Run: ftp-ids retrain")

def run_retrain(log_path: str):
    storage = Storage()
    events = run_parse(log_path, output=False)
    sessions = build_sessions(events)
    detector = Detector(model_path=MODEL_PATH, contamination=CONTAMINATION)
    original_features = pd.DataFrame(detector.extractor.extract_batch(sessions))

    clean_pool = storage.load_clean_pool()

    # combine
    if len(clean_pool) > 0:
        combined = pd.concat([
            original_features[FEATURE_NAMES],
            clean_pool[FEATURE_NAMES],
        ], ignore_index=True)
        print(f"Training on {len(original_features)} log sessions "
            f"+ {len(clean_pool)} confirmed-normal from clean pool")
    else:
        combined = original_features[FEATURE_NAMES]
        print(f"No clean pool yet, training on {len(combined)} sessions")

    detector.train_on_features(combined)


    
if __name__ == "__main__":
    main()