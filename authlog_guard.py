#!/usr/bin/env python3
"""AuthLog Guard: detect brute-force, password spraying and suspicious
successful logins in Linux SSH auth logs (e.g. /var/log/auth.log).

Usage:
    python authlog_guard.py auth.log
    python authlog_guard.py auth.log --threshold 5 --window 10 --json report.json
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s[\d:]{8})\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.:a-fA-F]+)"
)
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)


@dataclass
class Event:
    time: datetime
    kind: str  # "fail" or "success"
    user: str
    ip: str


@dataclass
class Alert:
    severity: str
    rule: str
    ip: str
    detail: str
    first_seen: str
    last_seen: str


def parse_line(line, year):
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    msg = m.group("msg")
    for regex, kind in ((FAILED_RE, "fail"), (INVALID_RE, "fail"), (ACCEPTED_RE, "success")):
        hit = regex.search(msg)
        if hit:
            return Event(ts, kind, hit.group("user"), hit.group("ip"))
    return None


def parse_log(lines, year):
    events = [e for e in (parse_line(l, year) for l in lines) if e]
    events.sort(key=lambda e: e.time)
    return events


def _fmt(t):
    return t.strftime("%Y-%m-%d %H:%M:%S")


def detect(events, threshold=5, window_min=10, spray_users=5):
    """Return a list of Alert objects."""
    window = timedelta(minutes=window_min)
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)

    alerts = []
    for ip, evs in by_ip.items():
        fails = [e for e in evs if e.kind == "fail"]

        # Rule 1: brute force = `threshold` failures inside a sliding window
        burst = None
        left = 0
        for right in range(len(fails)):
            while fails[right].time - fails[left].time > window:
                left += 1
            if right - left + 1 >= threshold:
                burst = (left, right)
        if burst:
            span = fails[burst[0]: burst[1] + 1]
            alerts.append(Alert(
                "HIGH", "BRUTE_FORCE", ip,
                f"{len(span)} failed logins within {window_min} min "
                f"(targets: {', '.join(sorted({e.user for e in span})[:5])})",
                _fmt(span[0].time), _fmt(span[-1].time)))

        # Rule 2: password spraying = many distinct usernames from one IP
        users = {e.user for e in fails}
        if len(users) >= spray_users:
            alerts.append(Alert(
                "MEDIUM", "PASSWORD_SPRAYING", ip,
                f"{len(users)} distinct usernames tried",
                _fmt(fails[0].time), _fmt(fails[-1].time)))

        # Rule 3: success after repeated failures = possible compromise
        for i, e in enumerate(evs):
            if e.kind != "success":
                continue
            prior = [f for f in fails if f.time < e.time and e.time - f.time <= window]
            if len(prior) >= max(3, threshold // 2):
                alerts.append(Alert(
                    "CRITICAL", "SUCCESS_AFTER_FAILURES", ip,
                    f"user '{e.user}' logged in after {len(prior)} recent failures",
                    _fmt(prior[0].time), _fmt(e.time)))
                break

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    alerts.sort(key=lambda a: (order[a.severity], a.ip))
    return alerts


def render(alerts, total_events):
    out = [f"AuthLog Guard report: {total_events} auth events analysed, "
           f"{len(alerts)} alert(s)", "=" * 70]
    for a in alerts:
        out.append(f"[{a.severity:<8}] {a.rule:<22} {a.ip}")
        out.append(f"           {a.detail}")
        out.append(f"           {a.first_seen} -> {a.last_seen}")
    if not alerts:
        out.append("No suspicious activity found.")
    else:
        ips = sorted({a.ip for a in alerts})
        out.append("-" * 70)
        out.append("Suggested response: review and consider blocking: " + ", ".join(ips))
        out.append("Example (ufw): sudo ufw deny from <ip> to any port 22")
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(description="Detect SSH brute-force activity in auth logs.")
    p.add_argument("logfile")
    p.add_argument("--threshold", type=int, default=5, help="failures that trigger brute-force (default 5)")
    p.add_argument("--window", type=int, default=10, help="window in minutes (default 10)")
    p.add_argument("--spray-users", type=int, default=5, help="distinct users that trigger spraying (default 5)")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year of the log (syslog omits it)")
    p.add_argument("--json", metavar="FILE", help="also write alerts as JSON")
    args = p.parse_args(argv)

    with open(args.logfile, errors="replace") as fh:
        events = parse_log(fh, args.year)
    alerts = detect(events, args.threshold, args.window, args.spray_users)
    print(render(alerts, len(events)))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump([asdict(a) for a in alerts], fh, indent=2)
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
