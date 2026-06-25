from collections import defaultdict
from datetime import timedelta

SESSION_GAP_MINUTES = 5

def build_sessions(events):
    # group events by source ip
    by_ip = defaultdict(list)
    for event in events:
        by_ip[event["src_ip"]].append(event)

    sessions = []
    gap = timedelta(minutes=SESSION_GAP_MINUTES)

    # walk each IP events chronologically
    for src_ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e["timestamp"])

        current = []
        for event in ip_events:
            if current:
                time_gap = event["timestamp"] - current[-1]["timestamp"]
                if time_gap > gap:
                    sessions.append(_make_session(src_ip, current))
                    current = []

            current.append(event)

            if event["session_end"]:
                # explicit boundary '221 Goodbye or terminated'
                sessions.append(_make_session(src_ip, current))
                current = []

        if current:
            # no explicit boundry (still open ...)
            sessions.append(_make_session(src_ip, current))

    sessions.sort(key=lambda s: s["start_time"])

    return sessions


def _make_session(src_ip, events):
    first, last = events[0], events[-1]

    # add user for first events followed by an authentified user or Anonymous
    user = next((e["user"] for e in events if e["user"]), None)

    # is auth
    is_auth = any(e['event_type'] == 'OK_LOGIN' for e in events)

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
        "is_auth":    is_auth,
        "start_time": first["timestamp"],
        "end_time":   last["timestamp"],
        "end_type":   end_type,
        "n_events":   len(events),
        "events":     events,
    }