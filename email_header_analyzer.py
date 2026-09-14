#!/usr/bin/env python3
"""
Email Header Analyzer Toolkit
-----------------------------
Analyze raw RFC 5322 email headers for routing, sender, and authentication clues.

Features:
- SPF / DKIM / DMARC results from Authentication-Results and ARC headers
- Received header chain and extracted IP addresses
- From / Return-Path / Reply-To / Sender / Message-ID
- Message date and subject
- Authentication and routing consistency checks
- Optional DNS reverse lookup for IP addresses
- JSON report output
- Simple CLI and interactive mode

Important:
An email header can reveal the path an email took, but no analyzer can
guarantee the original human/device that sent a message. The earliest
trusted Received entry and the receiving organization's mail infrastructure
are especially important when determining the likely originating IP.
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
from email import policy
from email.parser import BytesParser, Parser
from pathlib import Path


AUTH_FIELDS = {
    "spf": re.compile(r"\bspf\s*=\s*([a-zA-Z0-9_.+-]+)", re.I),
    "dkim": re.compile(r"\bdkim\s*=\s*([a-zA-Z0-9_.+-]+)", re.I),
    "dmarc": re.compile(r"\bdmarc\s*=\s*([a-zA-Z0-9_.+-]+)", re.I),
}

IP_RE = re.compile(
    r"(?<![\w.])"
    r"(?:"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"\."
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"\."
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"\."
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"|"
    r"[0-9a-fA-F:]{2,}"
    r")"
    r"(?![\w.])"
)


def load_message(path=None):
    if path:
        data = Path(path).read_bytes()
    else:
        data = sys.stdin.buffer.read()

    # Parse as bytes so malformed/non-ASCII headers are handled more safely.
    return BytesParser(policy=policy.default).parsebytes(data)


def header_values(msg, name):
    return [str(v) for v in msg.get_all(name, [])]


def extract_ips(text):
    found = []
    for candidate in IP_RE.findall(text or ""):
        try:
            ip = ipaddress.ip_address(candidate)
            value = str(ip)
            if value not in found:
                found.append(value)
        except ValueError:
            pass
    return found


def parse_authentication_results(msg):
    results = {"spf": [], "dkim": [], "dmarc": []}
    for field in header_values(msg, "Authentication-Results"):
        for key, pattern in AUTH_FIELDS.items():
            for match in pattern.finditer(field):
                results[key].append(match.group(1).lower())
    return results


def parse_received(msg):
    entries = []
    received = header_values(msg, "Received")

    # RFC 5322 folding is already unfolded by the email parser.
    for index, value in enumerate(received, 1):
        ips = extract_ips(value)

        # Common "from hostname (hostname [IP])" form.
        from_host = None
        by_host = None
        match = re.search(r"\bfrom\s+([^\s(;]+)", value, re.I)
        if match:
            from_host = match.group(1)

        match = re.search(r"\bby\s+([^\s(;]+)", value, re.I)
        if match:
            by_host = match.group(1)

        entries.append({
            "hop": index,
            "from_host": from_host,
            "by_host": by_host,
            "ip_addresses": ips,
            "raw": value,
        })
    return entries


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def authentication_assessment(auth):
    assessment = []
    for name in ("spf", "dkim", "dmarc"):
        values = auth.get(name, [])
        if not values:
            assessment.append(f"{name.upper()}: no result found in Authentication-Results")
        else:
            # Keep all observed results because a message can contain multiple
            # Authentication-Results fields.
            good = {"pass", "bestguesspass"}
            bad = {"fail", "softfail", "neutral", "temperror", "permerror", "none"}
            statuses = set(values)
            if statuses & good:
                assessment.append(f"{name.upper()}: PASS observed ({', '.join(values)})")
            elif statuses & bad:
                assessment.append(f"{name.upper()}: no PASS observed ({', '.join(values)})")
            else:
                assessment.append(f"{name.upper()}: {', '.join(values)}")
    return assessment


def analyze(msg, do_dns=False):
    received = parse_received(msg)
    all_received_ips = []
    for hop in received:
        for ip in hop["ip_addresses"]:
            if ip not in all_received_ips:
                all_received_ips.append(ip)

    # The Received list is normally presented newest first by email clients.
    # The oldest entries are closer to the origin, but trust boundaries matter.
    oldest_hop = received[-1] if received else None

    dns = {}
    if do_dns:
        for ip in all_received_ips:
            dns[ip] = reverse_dns(ip)

    auth = parse_authentication_results(msg)

    from_header = str(msg.get("From", "")) or None
    return_path = str(msg.get("Return-Path", "")) or None
    reply_to = str(msg.get("Reply-To", "")) or None
    sender = str(msg.get("Sender", "")) or None

    report = {
        "message": {
            "subject": str(msg.get("Subject", "")) or None,
            "date": str(msg.get("Date", "")) or None,
            "message_id": str(msg.get("Message-ID", "")) or None,
        },
        "sender": {
            "from": from_header,
            "return_path": return_path,
            "reply_to": reply_to,
            "sender": sender,
        },
        "authentication": auth,
        "authentication_assessment": authentication_assessment(auth),
        "received_chain": received,
        "likely_origin_clue": {
            "oldest_received_entry": oldest_hop,
            "explanation": (
                "The oldest Received entry is usually closest to the originating "
                "mail system, but it is not automatically proof of the original "
                "sender. Trust the headers added by infrastructure you control "
                "or otherwise know to be authentic."
            ),
        },
        "ip_addresses": all_received_ips,
        "reverse_dns": dns,
        "header_warnings": [],
    }

    # Basic consistency warnings.
    if not received:
        report["header_warnings"].append(
            "No Received headers found. Origin/routing analysis is limited."
        )
    if not auth["spf"]:
        report["header_warnings"].append(
            "No SPF result was found in Authentication-Results."
        )
    if not auth["dkim"]:
        report["header_warnings"].append(
            "No DKIM result was found in Authentication-Results."
        )
    if not auth["dmarc"]:
        report["header_warnings"].append(
            "No DMARC result was found in Authentication-Results."
        )
    if from_header and reply_to and from_header.lower() != reply_to.lower():
        report["header_warnings"].append(
            "Reply-To differs from From. This can be legitimate, but it is worth reviewing."
        )

    return report


def print_report(report):
    print("=" * 72)
    print("EMAIL HEADER ANALYZER")
    print("=" * 72)

    m = report["message"]
    s = report["sender"]
    print(f"Subject:     {m['subject'] or '(none)'}")
    print(f"Date:        {m['date'] or '(none)'}")
    print(f"Message-ID:  {m['message_id'] or '(none)'}")
    print()
    print("SENDER INFORMATION")
    print("-" * 72)
    print(f"From:        {s['from'] or '(none)'}")
    print(f"Return-Path: {s['return_path'] or '(none)'}")
    print(f"Reply-To:    {s['reply_to'] or '(none)'}")
    print(f"Sender:      {s['sender'] or '(none)'}")
    print()
    print("AUTHENTICATION")
    print("-" * 72)
    for line in report["authentication_assessment"]:
        print(line)
    print()
    print("RECEIVED / ROUTING CHAIN")
    print("-" * 72)
    for hop in report["received_chain"]:
        print(f"Hop {hop['hop']}:")
        print(f"  From: {hop['from_host'] or '(not parsed)'}")
        print(f"  By:   {hop['by_host'] or '(not parsed)'}")
        print(f"  IPs:  {', '.join(hop['ip_addresses']) or '(none)'}")
        print(f"  Raw:  {hop['raw']}")
    print()
    print("LIKELY ORIGIN CLUE")
    print("-" * 72)
    origin = report["likely_origin_clue"]["oldest_received_entry"]
    if origin:
        print(f"Oldest Received entry: {origin['raw']}")
        if origin["ip_addresses"]:
            print(f"Closest observed IP(s): {', '.join(origin['ip_addresses'])}")
    else:
        print("Not available.")
    print()
    print("HEADER WARNINGS")
    print("-" * 72)
    if report["header_warnings"]:
        for warning in report["header_warnings"]:
            print(f"- {warning}")
    else:
        print("No basic parser warnings.")
    print()
    if report["reverse_dns"]:
        print("REVERSE DNS")
        print("-" * 72)
        for ip, host in report["reverse_dns"].items():
            print(f"{ip}: {host or 'no PTR result'}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze raw email headers and produce a routing/authentication report."
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Raw email file (.eml or text). If omitted, read from stdin.",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        help="Write the full analysis report to a JSON file.",
    )
    parser.add_argument(
        "--dns",
        action="store_true",
        help="Perform optional reverse-DNS lookups for observed IP addresses.",
    )
    parser.add_argument(
        "--headers-only",
        action="store_true",
        help="Treat the input as header text rather than a complete .eml message.",
    )
    args = parser.parse_args()

    if args.file:
        raw = Path(args.file).read_bytes()
    else:
        raw = sys.stdin.buffer.read()

    if args.headers_only:
        msg = Parser(policy=policy.default).parsestr(raw.decode("utf-8", errors="replace"))
    else:
        msg = BytesParser(policy=policy.default).parsebytes(raw)

    report = analyze(msg, do_dns=args.dns)
    print_report(report)

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"JSON report written to: {args.json_path}")


if __name__ == "__main__":
    main()
