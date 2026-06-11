import argparse
from ftp_ids import config
from ftp_ids.parsers.vsftpd_parser import VsftpdParser


def main():
    print('main')
    parser = argparse.ArgumentParser(
        prog="ftp-ids",
        description="Host-based anomaly detection IDS for FTP servers",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ftp-ids parse [--log PATH] — parse a log and show stats
    parse_p = subparsers.add_parser("parse", help="Parse a log file and show stats")
    parse_p.add_argument("--log", default=config.LOGS_PATH, help="Path to FTP log file")
    parse_p.add_argument("--daemon", choices=["vsftpd"], default="vsftpd") # TODO consider to remove this option

    args = parser.parse_args()

    if args.log is None:
        parser.error("No FTP log file found. Specify one with --log.")

    if args.command == "parse":
        run_parse(args.log)


def run_parse(log_path: str):
    p = VsftpdParser()
    events, failed = [], []
    with open(log_path, "r") as f: # TODO consider errors="replace" ?
        for line in f:
            event = p.parse_line(line)
            if event: events.append(event) 
            else: failed.append(line)

    print(f"parsed : {len(events)}")
    print(f"failed : {len(failed)}")

if __name__ == "__main__":
    main()