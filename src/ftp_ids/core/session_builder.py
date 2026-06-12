"""
Session builder — groups parsed events into sessions.

Strategy:
  1. Group events by src_ip.
  2. Within an IP, walk events chronologically:
       - a session_end event closes the current session
       - a time gap > SESSION_GAP_MINUTES closes it too
  3. The session's user = first non-None user seen in its events.

This handles vsftpd splitting one logical session across multiple PIDs,
and the fact that the [user] tag is absent before login.
"""

from collections import defaultdict
from datetime import timedelta

SESSION_GAP_MINUTES = 5

def build_sessions(events: list[dict]) -> list[dict]:
    """Group parsed events into session dicts."""
    # 1. group events by source IP
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        by_ip[event["src_ip"]].append(event)

    sessions = []
    gap = timedelta(minutes=SESSION_GAP_MINUTES)

    # 2. walk each IP's events chronologically
    for src_ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e["timestamp"])

        current: list[dict] = []
        for event in ip_events:
            if current:
                time_gap = event["timestamp"] - current[-1]["timestamp"]
                if time_gap > gap:
                    # too long since last event -> previous session is over
                    sessions.append(_make_session(src_ip, current))
                    current = []

            current.append(event)

            if event["session_end"]:
                # explicit boundary (221 Goodbye or terminated)
                sessions.append(_make_session(src_ip, current))
                current = []

        if current:
            # leftover events with no explicit end (still open / log cut off)
            sessions.append(_make_session(src_ip, current))

    return sessions


def _make_session(src_ip: str, events: list[dict]) -> dict:
    """Build one session dict from its ordered events."""
    first, last = events[0], events[-1]

    # user = first non-None user seen
    user = next((e["user"] for e in events if e["user"]), None)

    # how the session ended
    if last["abrupt_end"]:
        end_type = "abrupt"
    elif last["session_end"]:
        end_type = "clean"
    else:
        end_type = "unknown"

    return {
        "src_ip":     src_ip,
        "user":       user,
        "start_time": first["timestamp"],
        "end_time":   last["timestamp"],
        "end_type":   end_type,
        "n_events":   len(events),
        "events":     events,
    }