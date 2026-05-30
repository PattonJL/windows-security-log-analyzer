import subprocess
import json
import smtplib
import argparse
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from collections import defaultdict
from datetime import datetime

# ─────────────────────────────────────────────
# CONFIGURATION
# Reads credentials from Windows environment variables
# The actual values never appear in this file
# ─────────────────────────────────────────────

SENDER_EMAIL   = os.environ.get("ALERT_EMAIL_SENDER")
SENDER_PASS    = os.environ.get("ALERT_EMAIL_PASSWORD")
RECEIVER_EMAIL = os.environ.get("ALERT_EMAIL_RECEIVER")


# ─────────────────────────────────────────────
# COMMAND-LINE ARGUMENTS
# Lets you customize the run without editing code
# Examples:
#   python login_analyzer.py --days 7
#   python login_analyzer.py --hours 48 --threshold 3 --email
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Windows Failed Login Analyzer")

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--hours', type=int, default=24,
                       help='Hours to look back (default: 24)')
    group.add_argument('--days', type=int,
                       help='Days to look back')

    parser.add_argument('--threshold', type=int, default=5,
                        help='Failures before flagging brute force (default: 5)')
    parser.add_argument('--email', action='store_true',
                        help='Send email alert if suspects detected')

    return parser.parse_args()


# ─────────────────────────────────────────────
# PULL EVENTS FROM WINDOWS SECURITY LOG
# ─────────────────────────────────────────────

def get_failed_logins(hours=24):
    ps_command = f"""
    $events = Get-WinEvent -FilterHashtable @{{
        LogName = 'Security'
        Id = 4625
        StartTime = (Get-Date).AddHours(-{hours})
    }} -MaxEvents 1000 -ErrorAction SilentlyContinue

    if ($events) {{
        $results = $events | ForEach-Object {{
            $xml = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data
            [PSCustomObject]@{{
                TimeCreated     = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                TargetUserName  = ($data | Where-Object {{ $_.Name -eq 'TargetUserName' }}).'#text'
                IpAddress       = ($data | Where-Object {{ $_.Name -eq 'IpAddress' }}).'#text'
                LogonType       = ($data | Where-Object {{ $_.Name -eq 'LogonType' }}).'#text'
                WorkstationName = ($data | Where-Object {{ $_.Name -eq 'WorkstationName' }}).'#text'
            }}
        }}
        $results | ConvertTo-Json
    }} else {{
        '[]'
    }}
    """
    result = subprocess.run(
        ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
        capture_output=True, text=True
    )
    return result.stdout, result.stderr


# ─────────────────────────────────────────────
# ANALYZE
# ─────────────────────────────────────────────

def analyze(json_data, threshold=5):
    if not json_data.strip() or json_data.strip() == '[]':
        return None

    try:
        events = json.loads(json_data)
        if isinstance(events, dict):
            events = [events]
    except json.JSONDecodeError:
        return None

    logon_types = {
        '2' : 'Interactive (Local)',
        '3' : 'Network',
        '7' : 'Unlock',
        '10': 'Remote/RDP',
        '11': 'Cached Interactive'
    }

    by_user = defaultdict(int)
    by_ip   = defaultdict(int)
    by_type = defaultdict(int)

    for e in events:
        by_user[e.get('TargetUserName', 'Unknown')] += 1
        by_ip[e.get('IpAddress',        'Unknown')] += 1
        by_type[e.get('LogonType',      '?')]       += 1

    return {
        'total'    : len(events),
        'by_user'  : dict(sorted(by_user.items(), key=lambda x: x[1], reverse=True)),
        'by_ip'    : dict(sorted(by_ip.items(),   key=lambda x: x[1], reverse=True)),
        'by_type'  : {logon_types.get(k, f'Type {k}'): v for k, v in by_type.items()},
        'suspects' : {u: c for u, c in by_user.items() if c >= threshold}
    }


# ─────────────────────────────────────────────
# BUILD REPORT
# Kept separate from printing so email can reuse it
# ─────────────────────────────────────────────

def build_report(data, hours):
    now   = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines = []

    lines.append("=" * 60)
    lines.append("       FAILED LOGIN ANALYSIS REPORT")
    lines.append(f"       Generated : {now}")
    lines.append(f"       Timeframe : Last {hours} hour(s)")
    lines.append("=" * 60)
    lines.append(f"\n  Total Failed Attempts: {data['total']}\n")

    lines.append("─" * 60)
    lines.append("  TOP TARGETED USERNAMES")
    lines.append("─" * 60)
    for user, count in list(data['by_user'].items())[:10]:
        bar = '█' * min(count, 40)
        lines.append(f"  {user:<30} {count:>4}  {bar}")

    lines.append("\n" + "─" * 60)
    lines.append("  TOP SOURCE IP ADDRESSES")
    lines.append("─" * 60)
    for ip, count in list(data['by_ip'].items())[:10]:
        if ip not in ('-', '', 'Unknown', None):
            bar = '█' * min(count, 40)
            lines.append(f"  {ip:<30} {count:>4}  {bar}")

    lines.append("\n" + "─" * 60)
    lines.append("  LOGON TYPE BREAKDOWN")
    lines.append("─" * 60)
    for ltype, count in data['by_type'].items():
        lines.append(f"  {ltype:<35} {count:>4}")

    lines.append("\n" + "─" * 60)
    if data['suspects']:
        lines.append("  ⚠️  BRUTE FORCE SUSPECTS DETECTED")
        lines.append("─" * 60)
        for user, count in data['suspects'].items():
            lines.append(f"  🚨  {user}  —  {count} failed attempts")
    else:
        lines.append("  ✅  No brute force patterns detected.")

    lines.append("=" * 60)
    return "\n".join(lines)


# ─────────────────────────────────────────────
# SEND EMAIL ALERT
# Only fires when --email flag is used
# AND suspects are actually found
# ─────────────────────────────────────────────

def send_alert(report_text, suspect_count, hours):
    if not all([SENDER_EMAIL, SENDER_PASS, RECEIVER_EMAIL]):
        print("  ⚠️  Email credentials missing from environment variables.")
        print("      Run setup_env.ps1 and restart PowerShell, then try again.\n")
        return

    machine = os.environ.get('COMPUTERNAME', 'Unknown Machine')
    now     = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    msg            = MIMEMultipart('alternative')
    msg['Subject'] = f"🚨 SECURITY ALERT — {suspect_count} Brute Force Suspect(s) | {machine}"
    msg['From']    = SENDER_EMAIL
    msg['To']      = RECEIVER_EMAIL

    body = (
        f"Brute force activity detected.\n\n"
        f"Machine   : {machine}\n"
        f"Time      : {now}\n"
        f"Timeframe : Last {hours} hour(s)\n"
        f"Suspects  : {suspect_count}\n\n"
        f"{'=' * 60}\n\n"
        f"{report_text}"
    )

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(SENDER_EMAIL, SENDER_PASS)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        print("  📧 Alert email sent successfully.\n")
    except Exception as e:
        print(f"  ❌ Email failed: {e}\n")


# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    args  = parse_args()
    hours = args.days * 24 if args.days else args.hours

    print(f"\n🔍 Scanning Security Event Log (last {hours} hour(s))...\n")

    raw, errors = get_failed_logins(hours=hours)

    if errors and 'error' in errors.lower():
        print(f"⚠️  Error: {errors}\n")

    data = analyze(raw, threshold=args.threshold)

    if not data:
        print("✅ No failed login events found in the specified timeframe.\n")
    else:
        report = build_report(data, hours)
        print(report)

        filename = f"failed_logins_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\n  📄 Report saved to: {filename}\n")

        if args.email and data['suspects']:
            send_alert(report, len(data['suspects']), hours)
        elif args.email and not data['suspects']:
            print("  📧 No suspects found — email not triggered.\n")