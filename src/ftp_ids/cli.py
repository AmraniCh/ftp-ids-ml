import argparse
from ftp_ids import config
from ftp_ids.parsers.vsftpd_parser import VsftpdParser
from pprint import pprint
from ftp_ids.core.session_builder import build_sessions
from ftp_ids.config import DAEMON_LOG_PATHS


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

    args = parser.parse_args()

    if args.log is None:
        parser.error("No FTP log file found. Specify one with --log.")

    if args.command == "parse":
        run_parse(args.log)

    if args.command == "sessions":
        run_sessions(args.log)

def run_parse(log_path: str, output=True):
    p = VsftpdParser()
    events, failed = [], []
    with open(log_path, "r") as f: # TODO consider errors="replace" ?
        for line in f:
            event = p.parse_line(line)
            if event: events.append(event) 
            else: failed.append(line)
            if output: pprint(event if event else line)

    print(f"parsed : {len(events)}")
    print(f"failed : {len(failed)}")

    return events

def run_sessions(log_path):
    events = run_parse(log_path, output=False)
    sessions = build_sessions(events)
    
    print(f"Sessions: {len(sessions)}\n")
    print(f"{'SRC_IP':<16} {'USER':<20} {'END':<8} {'EVENTS':>6}  {'START':<19}  {'END':<19}")
    
    for s in sessions:
        print(f"{s['src_ip']:<16} {s['user'] or '-':<20} {s['end_type']:<8} "
              f"{s['n_events']:>6}  {s['start_time']}  {s['end_time']}")

if __name__ == "__main__":
    main()