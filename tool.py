#!/usr/bin/env python3
"""
Advanced Recon Tool - with Wappalyzer & WhatWeb integration
- Wappalyzer (via python-wappalyzer or CLI wrapper)
- WhatWeb (via CLI with JSON output parsing)
- Custom modules for sensitive info, IP disclosures, subdomains, WHOIS, security headers
"""

import subprocess
import sys
import argparse
import re
import requests
import socket
import json
import warnings
import os
import ssl
import tempfile
import datetime
import io
import textwrap
import time
from urllib.parse import urlparse
import urllib3
from rich import box
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# -----------------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------------
ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
COLOR_ENABLED = sys.stdout.isatty() and os.getenv("NO_COLOR") is None
console = Console(width=120)
SCAN_STATS = {
    "modules": 0,
    "rows": 0,
    "findings": 0,
    "warnings": 0,
    "errors": 0,
    "start": None,
}
EXECUTED_MODULES = []

def ensure_blocking_streams():
    for stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(stream, "fileno"):
                os.set_blocking(stream.fileno(), True)
        except Exception:
            pass

ensure_blocking_streams()

COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_black": "\033[90m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
    "bright_white": "\033[97m",
}

def colorize(value, *styles):
    if not COLOR_ENABLED:
        return value
    prefix = "".join(COLORS[style] for style in styles if style in COLORS)
    return f"{prefix}{value}{COLORS['reset']}" if prefix else value

def color_cell(value):
    upper_value = clean_cell(value).upper()
    red_statuses = {"ERROR", "FAILED", "MISSING"}
    green_statuses = {"FOUND", "DETECTED", "PRESENT", "EXPECTED"}
    yellow_statuses = {"HIGH", "REVIEW", "WARNING", "TRUNCATED"}
    cyan_statuses = {"INFO", "OUTPUT", "SKIPPED"}

    if upper_value in red_statuses or upper_value.startswith("ERROR:"):
        return colorize(value, "bright_red", "bold")
    if upper_value in green_statuses:
        return colorize(value, "bright_green", "bold")
    if upper_value in yellow_statuses or upper_value.startswith("HIGH ") or upper_value.startswith("HIGH("):
        return colorize(value, "bright_yellow", "bold")
    if upper_value in cyan_statuses or upper_value.startswith("SKIPPED"):
        return colorize(value, "bright_cyan")
    if "LOW" in upper_value:
        return colorize(value, "yellow")
    return value

def clean_cell(value):
    value = "" if value is None else str(value)
    value = ANSI_PATTERN.sub("", value)
    return re.sub(r"\s+", " ", value).strip()

def write_safely(text, stream=None, chunk_size=4096):
    stream = stream or sys.__stdout__
    offset = 0
    while offset < len(text):
        chunk = text[offset:offset + chunk_size]
        try:
            written = stream.write(chunk)
            if written is None:
                written = len(chunk)
            offset += written
        except BlockingIOError:
            time.sleep(0.02)
    try:
        stream.flush()
    except Exception:
        pass

def safe_console_print(renderable):
    try:
        console.print(renderable)
    except BlockingIOError:
        buffer = io.StringIO()
        fallback_console = Console(
            file=buffer,
            width=console.width,
            force_terminal=False,
            color_system=None,
            no_color=True,
        )
        fallback_console.print(renderable)
        write_safely(buffer.getvalue())
    except Exception:
        try:
            write_safely(f"{renderable}\n")
        except Exception:
            pass

def wrap_cell(value, width):
    value = clean_cell(value)
    if not value:
        return [""]
    return textwrap.wrap(
        value,
        width=width,
        break_long_words=True,
        break_on_hyphens=False
    ) or [""]

def print_table(title, headers, rows, empty_message=None):
    if not rows:
        if empty_message:
            if not headers:
                headers = ["Status", "Message", "Details"]
            placeholder = ["INFO"]
            if len(headers) > 1:
                placeholder.append(empty_message)
                placeholder.extend(["-"] * (len(headers) - 2))
            rows = [placeholder[:len(headers)]]
        else:
            return

    rows = [[clean_cell(cell) for cell in row] for row in rows]
    headers = [clean_cell(header) for header in headers]

    table = Table(
        box=box.ROUNDED,
        expand=len(headers) > 2,
        show_lines=True,
        header_style="bold bright_cyan",
        pad_edge=False,
        collapse_padding=True,
        padding=(0, 0),
    )

    for i, header in enumerate(headers):
        header_lower = header.lower()
        if len(headers) == 2:
            if i == 0:
                if header_lower in {"tool", "type", "field", "port", "status", "check", "plugin", "source"}:
                    table.add_column(header, width=20, no_wrap=False, overflow="fold")
                else:
                    table.add_column(header, width=24, no_wrap=False, overflow="fold")
            else:
                table.add_column(header, ratio=1, overflow="fold")
            continue
        if "subdomain" in header_lower:
            table.add_column(header, ratio=4, overflow="fold")
        elif "value" in header_lower:
            table.add_column(header, ratio=3, overflow="fold")
        elif "details" in header_lower or "result" in header_lower:
            table.add_column(header, ratio=3, overflow="fold")
        elif "header" in header_lower:
            table.add_column(header, ratio=2, overflow="fold")
        elif header_lower == "version":
            table.add_column(header, ratio=3, overflow="fold")
        elif "status" in header_lower or "purpose" in header_lower:
            table.add_column(header, ratio=1, overflow="fold")
        elif header_lower in {"port", "service", "type"}:
            table.add_column(header, ratio=1, overflow="fold")
        else:
            table.add_column(header, ratio=1, overflow="fold")

    for row in rows:
        normalized = [row[i] if i < len(row) else "" for i in range(len(headers))]
        styled = []
        for value in normalized:
            upper_value = value.upper()
            if upper_value.startswith("ERROR") or upper_value in {"FAILED", "MISSING"}:
                styled.append(f"[bold red]{value}[/]")
            elif upper_value.startswith("WARNING") or upper_value in {"REVIEW", "HIGH"}:
                styled.append(f"[bold yellow]{value}[/]")
            elif upper_value in {"FOUND", "DETECTED", "PRESENT", "EXPECTED"}:
                styled.append(f"[bold green]{value}[/]")
            elif upper_value in {"INFO", "OUTPUT"} or upper_value.startswith("SKIPPED"):
                styled.append(f"[cyan]{value}[/]")
            else:
                styled.append(value)
        table.add_row(*styled)

    update_stats(rows)
    safe_console_print(Panel(table, title=f"[bold bright_magenta]{title}[/]", border_style="bright_blue", padding=(1, 1)))

def update_stats(rows):
    SCAN_STATS["modules"] += 1
    SCAN_STATS["rows"] += len(rows)
    for row in rows:
        row_text = " ".join(clean_cell(cell).upper() for cell in row)
        if "ERROR" in row_text or "FAILED" in row_text:
            SCAN_STATS["errors"] += 1
        elif "WARNING" in row_text or "MISSING" in row_text or "REVIEW" in row_text:
            SCAN_STATS["warnings"] += 1
        elif any(token in row_text for token in ("FOUND", "DETECTED", "PRESENT", "EXPECTED")):
            SCAN_STATS["findings"] += 1

def output_to_table(title, output, max_lines=None):
    rows = []
    for line in output.splitlines():
        line = line.strip()
        if line:
            rows.append(["OUTPUT", line])
        if max_lines and len(rows) >= max_lines:
            rows.append(["INFO", "Output truncated"])
            break
    print_table(title, ["Type", "Result"], rows, "No output produced.")

def parse_nmap_output(output):
    rows = []
    port_header_seen = False
    port_pattern = re.compile(r"^(?P<port>\d+/\w+)\s+(?P<state>\w+)\s+(?P<service>\S+)(?:\s+(?P<version>.*))?$")
    current_port_index = None
    for raw_line in output.splitlines():
        line = clean_cell(raw_line)
        if not line:
            continue
        if line.startswith("PORT "):
            port_header_seen = True
            current_port_index = None
            continue
        if line.startswith("Nmap scan report for"):
            rows.append(["INFO", line])
            current_port_index = None
            continue
        if line.startswith("Host is up"):
            continue
        if port_header_seen:
            match = port_pattern.match(line)
            if match:
                rows.append([
                    match.group("port"),
                    match.group("state"),
                    match.group("service"),
                    match.group("version") or "-",
                ])
                current_port_index = len(rows) - 1
                continue
            if current_port_index is not None and (
                line.startswith("|")
                or line.startswith("Service Info:")
                or line.startswith("MAC Address:")
                or line.startswith("Nmap done:")
            ):
                detail = line.lstrip("|").strip()
                if detail.startswith("_"):
                    detail = detail[1:].strip()
                if detail:
                    if rows[current_port_index][3] in {"-", ""}:
                        rows[current_port_index][3] = detail
                    elif detail not in rows[current_port_index][3]:
                        rows[current_port_index][3] = f"{rows[current_port_index][3]} | {detail}"
            continue
    return rows

def format_value(value):
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            if isinstance(item, list):
                joined = ", ".join(clean_cell(x) for x in item if clean_cell(x))
                if joined:
                    parts.append(f"{key}: {joined}")
            elif item not in (None, "", []):
                parts.append(f"{key}: {clean_cell(item)}")
        return "; ".join(parts) if parts else "-"
    if isinstance(value, list):
        items = [clean_cell(item) for item in value if clean_cell(item)]
        return ", ".join(items) if items else "-"
    text = clean_cell(value)
    return text if text else "-"

def parse_whatweb_json(data):
    rows = []
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        return rows

    plugins = data.get("plugins", {})
    if isinstance(plugins, dict):
        for plugin, details in plugins.items():
            summary = format_value(details)
            rows.append([plugin, summary])
    return rows

# -----------------------------------------------------------------------------
# Helper: false-positive reduction
# -----------------------------------------------------------------------------
def is_internal_ip(ip):
    private_blocks = [
        re.compile(r"^10\."),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^169\.254\."),
        re.compile(r"^127\."),
        re.compile(r"^::1$"),
        re.compile(r"^fe80::", re.I)
    ]
    return any(p.match(ip) for p in private_blocks)

def plausible_sensitive_key(value, pattern_type):
    if len(value) < 12:
        return False, "too short"
    if re.fullmatch(r"[0-9A-Fa-f]+", value) and len(value) < 32:
        return False, "hex hash, unlikely secret"
    if re.match(r"([a-zA-Z0-9])\1{10,}", value):
        return False, "repetitive pattern"
    if pattern_type == "aws_key" and value.startswith("AKIA"):
        return True, "AWS Access Key"
    if pattern_type == "github_token" and (value.startswith("ghp_") or value.startswith("gho_")):
        return True, "GitHub token"
    if pattern_type == "jwt" and value.count('.') == 2:
        return True, "JWT structure"
    if (re.search(r'[A-Z]', value) and re.search(r'[a-z]', value) and
        re.search(r'[0-9]', value) and re.search(r'[_\-+=]', value) and len(value) > 16):
        return True, "high entropy secret"
    return False, "likely false positive"

SENSITIVE_PATTERNS = {
    "aws_key": r"(?i)(AKIA|ASIA)[0-9A-Z]{16}",
    "github_token": r"(?i)(ghp_|gho_|ghu_|ghs_)[0-9A-Za-z]{36}",
    "jwt": r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    "google_api": r"AIza[0-9A-Za-z\-_]{35}",
    "slack_token": r"xox[baprs]-[0-9]{10,12}-[0-9]{12,14}-[a-zA-Z0-9]{24}",
    "generic_api": r"(?i)(api[_-]?key|apikey|secret|token|password)[\"']?\s*[:=]\s*[\"']([^\"']{16,64})[\"']"
}

# -----------------------------------------------------------------------------
# Custom modules (low false positives)
# -----------------------------------------------------------------------------
def fetch_url(url, timeout=10):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        resp = requests.get(url, timeout=timeout, headers=headers, verify=False)
        resp.raise_for_status()
        return resp.text, resp.headers
    except Exception:
        return None, None

def sensitive_info_check(target_url):
    rows = []
    content, _ = fetch_url(target_url)
    if not content:
        print_table("[🔍] Sensitive Information", ["Type", "Finding", "Confidence", "Details"], [
            ["ERROR", "Could not fetch page content", "-", "-"]
        ])
        return
    for name, pattern in SENSITIVE_PATTERNS.items():
        for match in re.finditer(pattern, content, re.IGNORECASE):
            if name == "generic_api":
                key_value = match.group(2)
                reason_type = "generic API key"
            else:
                key_value = match.group(0)
                reason_type = f"{name} pattern"
            plausible, reason = plausible_sensitive_key(key_value, name)
            confidence = "HIGH" if plausible else "LOW (likely false positive)"
            rows.append([name.upper(), key_value[:20] + "...", confidence, f"{reason_type} ({reason})"])
    print_table(
        "[🔍] Sensitive Information",
        ["Type", "Finding", "Confidence", "Details"],
        rows,
        "No sensitive information found with high confidence."
    )

def ip_disclosure_check(target_url, domain):
    rows = []
    content, headers = fetch_url(target_url)
    if not content:
        print_table("[🌐] IP Address Disclosures", ["Type", "IP / Header", "Status", "Details"], [
            ["ERROR", "Could not fetch page content", "-", "-"]
        ])
        return
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    ips_in_page = set(ip_pattern.findall(content))
    for ip in ips_in_page:
        octets = ip.split('.')
        if all(0 <= int(oct) <= 255 for oct in octets):
            if is_internal_ip(ip):
                rows.append(["Internal IP", ip, "FOUND", "Possible source code leak"])
            else:
                try:
                    server_ip = socket.gethostbyname(domain)
                    if ip == server_ip:
                        rows.append(["Server public IP", ip, "EXPECTED", "Matches resolved target IP"])
                    else:
                        rows.append(["External IP", ip, "REVIEW", "Possible third-party resource"])
                except socket.gaierror:
                    rows.append(["IP found", ip, "REVIEW", "Could not resolve domain"])
    if headers and 'X-Forwarded-For' in headers:
        rows.append(["Header IP", headers['X-Forwarded-For'], "FOUND", "X-Forwarded-For header"])
    print_table(
        "[🌐] IP Address Disclosures",
        ["Type", "IP / Header", "Status", "Details"],
        rows,
        "No unexpected IP address disclosures found."
    )

def subdomain_enum(domain):
    rows = []
    subdomains = set()
    # Passive from crt.sh
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get('name_value', '')
                if name:
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and sub != domain:
                            subdomains.add(sub)
    except Exception as e:
        rows.append(["crt.sh", "-", "ERROR", e])
    # Simple brute (common, validated by DNS)
    common = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'stage', 'blog', 'shop']
    for sub in common:
        target = f"{sub}.{domain}"
        try:
            socket.gethostbyname(target)
            subdomains.add(target)
        except socket.gaierror:
            pass
    if subdomains:
        for sub in sorted(subdomains):
            rows.append(["DNS / Certificate", sub, "FOUND", "Resolved or discovered passively"])
    print_table(
        f"[🌍] Subdomain Enumeration: {domain}",
        ["Source", "Subdomain", "Status", "Details"],
        rows,
        "No subdomains found or enumeration failed."
    )
    return list(subdomains)

# -----------------------------------------------------------------------------
# Security headers check (custom, reliable)
# -----------------------------------------------------------------------------
def check_security_headers(target_url):
    rows = []
    try:
        resp = requests.get(target_url, timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        headers = resp.headers
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'X-XSS-Protection': 'XSS filter',
            'Referrer-Policy': 'Referrer policy',
            'Permissions-Policy': 'Feature policy'
        }
        for hdr, desc in security_headers.items():
            value = headers.get(hdr)
            if value:
                rows.append([hdr, "PRESENT", desc, value[:80]])
            else:
                rows.append([hdr, "MISSING", desc, "-"])
        print_table("[🔒] Security Headers", ["Header", "Status", "Purpose", "Value"], rows)
    except Exception as e:
        print_table("[🔒] Security Headers", ["Header", "Status", "Purpose", "Value"], [
            ["ERROR", "FAILED", "Could not check headers", e]
        ])

# -----------------------------------------------------------------------------
# WHOIS lookup (domain registration details)
# -----------------------------------------------------------------------------
def whois_lookup(target):
    rows = []
    # Try python-whois library first
    try:
        import whois
        try:
            info = whois.whois(target)
            # Filter out None values
            for key, value in info.items():
                if value:
                    # Handle bytes objects gracefully
                    if isinstance(value, bytes):
                        value = value.decode('utf-8', errors='ignore')
                    # Truncate long values
                    str_value = str(value)
                    if len(str_value) > 150:
                        str_value = str_value[:150] + "..."
                    rows.append([key, str_value])
            print_table("[📋] WHOIS Lookup", ["Field", "Value"], rows, "No WHOIS data found.")
        except Exception as e:
            rows.append(["python-whois", f"failed: {e}"])
            try:
                result = subprocess.run(["whois", target], capture_output=True, text=True, timeout=30)
                if result.returncode == 0 and result.stdout:
                    for line in result.stdout.splitlines():
                        if ":" in line:
                            key, value = line.split(":", 1)
                            key = key.strip()
                            value = value.strip()
                            if key and value:
                                rows.append([key, value])
                        if len(rows) >= 30:
                            rows.append(["Output", "truncated"])
                            break
                else:
                    rows.append(["system whois", "No WHOIS data found."])
            except FileNotFoundError:
                rows.append(["system whois", "Command not found. Install with: sudo apt install whois"])
            except subprocess.TimeoutExpired:
                rows.append(["system whois", "Command timed out."])
            print_table("[📋] WHOIS Lookup", ["Field", "Value"], rows, "No WHOIS data found.")
    except ImportError:
        rows.append(["python-whois", "Not installed. Using system whois."])
        try:
            result = subprocess.run(["whois", target], capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.splitlines():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip()
                        value = value.strip()
                        if key and value:
                            rows.append([key, value])
                    if len(rows) >= 30:
                        rows.append(["Output", "truncated"])
                        break
            else:
                rows.append(["system whois", "No WHOIS data found."])
        except FileNotFoundError:
            rows.append(["system whois", "Command not found. Install with: sudo apt install whois"])
        except subprocess.TimeoutExpired:
            rows.append(["system whois", "Command timed out."])
        print_table("[📋] WHOIS Lookup", ["Field", "Value"], rows, "No WHOIS data found.")
    except Exception as e:
        print_table("[📋] WHOIS Lookup", ["Field", "Value"], [["ERROR", e]])

# -----------------------------------------------------------------------------
# External tools runners
# -----------------------------------------------------------------------------
def run_tool(cmd, name, timeout=120):
    write_safely(f"\n[⚙️] Running {name}...\n")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        output = result.stdout or ""
        if result.returncode != 0 and result.stderr:
            output = f"[WARNING] {name}: {result.stderr.strip()}\n{output}"
        return output
    except subprocess.TimeoutExpired:
        return f"[ERROR] {name} timed out after {timeout}s"
    except FileNotFoundError:
        return f"[ERROR] {name} not installed. Skipping."

def nikto_scan(target_url, ssl=False, tuning=None, plugins=None, cookies=None):
    args = ["nikto", "-h", target_url, "-Format", "txt", "-nointeractive"]
    if ssl:
        args.append("-ssl")
    if tuning:
        args.extend(["-Tuning", tuning])
    if plugins:
        args.extend(["-Plugins", plugins])
    if cookies:
        args.extend(["-C", cookies])
    return run_tool(" ".join(args), "Nikto")

def build_nmap_args(
    target,
    aggressive=False,
    scripts=False,
    udp=False,
    all_ports=False,
    top_ports=None,
    ports=None,
    version_intensity=None,
    max_retries=None,
    host_timeout=None,
    min_rate=None,
):
    args = ["nmap", "-sV", "-T4"]
    if aggressive:
        args.extend(["-A", "-O", "--osscan-guess"])
    if scripts:
        args.append("-sC")
    if udp:
        args.append("-sU")
    if all_ports:
        args.append("-p-")
    elif top_ports:
        args.extend(["--top-ports", str(top_ports)])
    elif ports:
        args.extend(["-p", ports])
    else:
        args.append("-F")
    if version_intensity is not None:
        args.extend(["--version-intensity", str(version_intensity)])
    if max_retries is not None:
        args.extend(["--max-retries", str(max_retries)])
    if host_timeout is not None:
        args.extend(["--host-timeout", str(host_timeout)])
    if min_rate is not None:
        args.extend(["--min-rate", str(min_rate)])
    args.append(target)
    return args

def nmap_scan(
    target,
    aggressive=False,
    scripts=False,
    udp=False,
    all_ports=False,
    top_ports=None,
    ports=None,
    version_intensity=None,
    max_retries=None,
    host_timeout=None,
    min_rate=None,
):
    args = build_nmap_args(
        target,
        aggressive=aggressive,
        scripts=scripts,
        udp=udp,
        all_ports=all_ports,
        top_ports=top_ports,
        ports=ports,
        version_intensity=version_intensity,
        max_retries=max_retries,
        host_timeout=host_timeout,
        min_rate=min_rate,
    )
    return run_tool(" ".join(args), "Nmap scan")

def whatweb_scan(target_url, plugins=None, user_agent=None, timeout=120):
    """Run WhatWeb and return parsed JSON output for better parsing."""
    temp_path = os.path.join(tempfile.gettempdir(), f"whatweb_{os.getpid()}_{int(time.time() * 1000)}.json")
    cmd = ["whatweb", f"--log-json={temp_path}"]
    if plugins:
        cmd.extend(["--plugins", plugins])
    if user_agent:
        cmd.extend(["--user-agent", user_agent])
    cmd.append(target_url)
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if not os.path.exists(temp_path):
            return None
        with open(temp_path, "r", encoding="utf-8", errors="ignore") as handle:
            raw = handle.read().strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None
    finally:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            pass

def arjun_scan(target_url, method=None, headers=None, wordlist=None, threads=None):
    args = ["arjun", "-u", target_url, "-t", "10"]
    if method:
        args.extend(["-m", method])
    if headers:
        args.extend(["-H", headers])
    if wordlist:
        args.extend(["-w", wordlist])
    if threads:
        args.extend(["--threads", str(threads)])
    return run_tool(" ".join(args), "Arjun (parameter fuzzing)")

def bbot_scan(target, timeout=90, modules=None):
    write_safely(f"\n{clean_cell(colorize('[⚙️] Running BBOT passive subdomain enumeration...', 'bright_cyan', 'bold'))}\n")
    cmd = [
        "bbot",
        "-t", target,
        "--json",
        "--brief",
        "--silent",
        "-y",
        "--no-deps",
    ]
    if modules:
        cmd.extend(["-m", *modules])
    else:
        cmd.extend(["-m", "crt", "hackertarget", "anubisdb", "rapiddns"])
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            if process.returncode != 0 and stderr:
                return stdout, f"ERROR: {stderr[:300]}"
            return stdout, None
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            message = f"WARNING: BBOT stopped after {timeout}s timeout. Showing partial results."
            return stdout, message
    except subprocess.TimeoutExpired:
        return "", f"WARNING: BBOT stopped after {timeout}s timeout"
    except FileNotFoundError:
        return "", "ERROR: BBOT not installed. Install with: pipx install bbot or pip install bbot"

def summarize_bbot_value(value):
    if isinstance(value, dict):
        preferred_keys = [
            "host", "hostname", "domain", "subdomain", "url", "ip", "port",
            "protocol", "name", "title", "email", "record", "value", "type",
            "description", "text"
        ]
        parts = []
        for key in preferred_keys:
            if key in value and value[key] not in (None, "", [], {}):
                parts.append(f"{key}: {summarize_bbot_value(value[key])}")
        if parts:
            return " | ".join(parts)
        return ", ".join(f"{k}: {summarize_bbot_value(v)}" for k, v in value.items() if v not in (None, "", [], {})) or "-"
    if isinstance(value, list):
        items = [summarize_bbot_value(item) for item in value]
        items = [item for item in items if item not in ("", "-")]
        return ", ".join(items) if items else "-"
    text = clean_cell(value)
    return text if text else "-"

def summarize_bbot_event(event):
    if not isinstance(event, dict):
        return "EVENT", clean_cell(event), "-"

    event_type = clean_cell(event.get("type", "EVENT")) or "EVENT"
    module = clean_cell(event.get("module", event.get("source", "-"))) or "-"

    data = event.get("data")
    if data is None:
        data = event.get("host", event.get("url", event.get("name", event.get("target", event))))

    if isinstance(data, dict):
        summary = summarize_bbot_value(data)
    else:
        summary = summarize_bbot_value(data)

    if event_type == "SCAN" and isinstance(data, dict):
        scan_name = summarize_bbot_value(data.get("name", "-"))
        target_info = summarize_bbot_value(data.get("target", data.get("seeds", data.get("whitelist", "-"))))
        summary = f"name: {scan_name} | target: {target_info}"

    if event_type in {"DNS_NAME", "DOMAIN_NAME", "SUBDOMAIN", "URL", "OPEN_TCP_PORT", "OPEN_TCP_UDP_PORT"}:
        module = module if module != "-" else event_type

    return event_type, summary, module

def print_bbot_results(output, message=None):
    rows = []
    seen = set()
    if message:
        msg_type = "ERROR" if message.startswith("ERROR") else "WARNING"
        key = (msg_type, clean_cell(message), "-")
        if key not in seen:
            rows.append([msg_type, message, "-"])
            seen.add(key)
    for line in output.splitlines():
        line = clean_cell(line)
        if not line or line.startswith("["):
            continue
        try:
            event = json.loads(line)
            event_type, data, module = summarize_bbot_event(event)
            key = (clean_cell(event_type), clean_cell(data), clean_cell(module))
            if key not in seen:
                rows.append([event_type, data, module])
                seen.add(key)
        except json.JSONDecodeError:
            key = ("OUTPUT", line, "-")
            if key not in seen:
                rows.append(["OUTPUT", line, "-"])
                seen.add(key)
        if len(rows) >= 120:
            rows.append(["INFO", "Output truncated", "-"])
            break
    print_table(
        "[🧭] BBOT Passive Recon",
        ["Event Type", "Data", "Source"],
        rows,
        "No BBOT findings parsed. Try increasing --bbot-timeout or check BBOT/network access."
    )

def ssl_analysis(target_url):
    rows = []
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or 443
    if not hostname:
        print_table("[🔐] SSL Analysis", ["Check", "Result", "Details"], [["ERROR", "Invalid hostname", target_url]])
        return
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version() or "-"
                cipher = ssock.cipher()

        rows.append(["TLS Version", "FOUND", tls_version])
        if cipher:
            rows.append(["Cipher", "FOUND", cipher[0]])
        if cert:
            subject = dict(x[0] for x in cert.get("subject", []) if x)
            issuer = dict(x[0] for x in cert.get("issuer", []) if x)
            not_before = cert.get("notBefore", "-")
            not_after = cert.get("notAfter", "-")
            rows.append(["Certificate Subject", "FOUND", format_value(subject)])
            rows.append(["Certificate Issuer", "FOUND", format_value(issuer)])
            rows.append(["Valid From", "INFO", not_before])
            rows.append(["Valid To", "INFO", not_after])
    except ssl.SSLError as e:
        rows.append(["TLS Handshake", "ERROR", str(e)])
    except Exception as e:
        rows.append(["TLS Handshake", "ERROR", str(e)])
    print_table("[🔐] SSL Analysis", ["Check", "Status", "Details"], rows, "No SSL data could be retrieved.")

# -----------------------------------------------------------------------------
# Wappalyzer integration (technology detection)
# -----------------------------------------------------------------------------
def wappalyzer_scan(target_url):
    """Detect web technologies using Wappalyzer."""
    rows = []
    
    # Try multiple methods for maximum reliability
    
    # Method 1: Try using the python-wappalyzer library
    try:
        from Wappalyzer import Wappalyzer, WebPage
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(target_url)
            technologies = wappalyzer.analyze(webpage)
        if technologies:
            # Group technologies by category
            for tech in sorted(technologies):
                rows.append(["python-wappalyzer", tech, "DETECTED"])
            print_table("[⚙️] Wappalyzer Technology Detection", ["Source", "Technology", "Status"], rows)
            return technologies
        else:
            rows.append(["python-wappalyzer", "-", "No technologies detected"])
    except ImportError:
        rows.append(["python-wappalyzer", "-", "Not installed"])
    except Exception as e:
        rows.append(["python-wappalyzer", "-", f"ERROR: {e}"])
    
    # Method 2: Try using the 'wappalyzer' CLI tool (if available)
    try:
        # Check if wappalyzer command exists
        result = subprocess.run(["which", "wappalyzer"], capture_output=True, text=True)
        if result.returncode == 0:
            output = run_tool(f"wappalyzer -i {target_url}", "Wappalyzer CLI")
            if output:
                # Try to parse JSON output
                try:
                    data = json.loads(output)
                    if isinstance(data, list) and len(data) > 0:
                        techs = data[0].get('technologies', [])
                        for tech in techs:
                            rows.append(["Wappalyzer CLI", tech.get('name', 'Unknown'), "DETECTED"])
                        print_table("[⚙️] Wappalyzer Technology Detection", ["Source", "Technology", "Status"], rows)
                        return techs
                except json.JSONDecodeError:
                    # Fallback: print raw output
                    rows.append(["Wappalyzer CLI", output[:500], "RAW OUTPUT"])
                    print_table("[⚙️] Wappalyzer Technology Detection", ["Source", "Technology", "Status"], rows)
                return None
    except FileNotFoundError:
        pass
    except Exception as e:
        rows.append(["Wappalyzer CLI", "-", f"ERROR: {e}"])
    
    # Method 3: Use the 'wap' library (alternative implementation)
    try:
        import wap
        # wap expects HTTP response content
        content, headers = fetch_url(target_url)
        if content and headers:
            # Create a simple response-like object
            response = type('Response', (), {})()
            response.text = content
            response.headers = headers
            technologies = wap.analyze_response(response)
            if technologies:
                for tech in technologies:
                    rows.append(["wap", tech, "DETECTED"])
                print_table("[⚙️] Wappalyzer Technology Detection", ["Source", "Technology", "Status"], rows)
                return technologies
        else:
            rows.append(["wap", "-", "Could not fetch content"])
    except ImportError:
        rows.append(["wap", "-", "Not installed"])
    except Exception as e:
        rows.append(["wap", "-", f"ERROR: {e}"])
    
    # Method 4: Use API fallback (public Wappalyzer API or InternetDB alternative)
    try:
        content, headers = fetch_url(target_url)
        if not content:
            rows.append(["Manual detection", "-", "Could not fetch page content"])
            print_table("[⚙️] Wappalyzer Technology Detection", ["Source", "Technology", "Status"], rows)
            return None
        
        # Simple technology detection based on common patterns
        technologies = []
        
        # Server headers
        if headers and 'Server' in headers:
            server = headers['Server']
            technologies.append(f"Web Server: {server}")
            rows.append(["Manual detection", f"Web Server: {server}", "DETECTED"])
        
        # Framework detection
        if re.search(r'wp-content|wordpress', content, re.IGNORECASE):
            technologies.append("CMS: WordPress")
            rows.append(["Manual detection", "CMS: WordPress", "DETECTED"])
        if re.search(r'drupal', content, re.IGNORECASE):
            technologies.append("CMS: Drupal")
            rows.append(["Manual detection", "CMS: Drupal", "DETECTED"])
        if re.search(r'joomla', content, re.IGNORECASE):
            technologies.append("CMS: Joomla")
            rows.append(["Manual detection", "CMS: Joomla", "DETECTED"])
        
        # JavaScript libraries
        js_libs = {
            'jquery': 'jQuery',
            'react': 'React',
            'angular': 'Angular',
            'vue': 'Vue.js',
            'bootstrap': 'Bootstrap'
        }
        for pattern, name in js_libs.items():
            if re.search(pattern, content, re.IGNORECASE):
                technologies.append(f"JavaScript: {name}")
                rows.append(["Manual detection", f"JavaScript: {name}", "DETECTED"])
        
        # Analytics
        if 'google-analytics' in content or 'gtag' in content:
            technologies.append("Analytics: Google Analytics")
            rows.append(["Manual detection", "Analytics: Google Analytics", "DETECTED"])
        
        if not technologies:
            rows.append(["Manual detection", "-", "No technologies detected"])
        print_table("[⚙️] Wappalyzer Technology Detection", ["Source", "Technology", "Status"], rows)
        return technologies
        
    except Exception as e:
        rows.append(["Manual detection", "-", f"ERROR: {e}"])
    
    print_table("[⚙️] Wappalyzer Technology Detection", ["Source", "Technology", "Status"], rows)
    return None

# -----------------------------------------------------------------------------
# Rich terminal UI and additional framework modules
# -----------------------------------------------------------------------------
def render_banner():
    title = Text()
    title.append(r"    ___       __                          __" + "\n", style="bold bright_green")
    title.append(r"   /   | ____/ /   __ ___  ____  ________/ /" + "\n", style="bold bright_green")
    title.append(r"  / /| |/ __  / | / / __ `/ __ \/ ___/ _  /" + "\n", style="bold bright_green")
    title.append(r" / ___ / /_/ /| |/ / /_/ / / / / /__/  __/" + "\n", style="bold bright_green")
    title.append(r"/_/  |_\__,_/ |___/\__,_/_/ /_/\___/\___/" + "\n", style="bold bright_green")
    title.append(r"        R E C O N   S U I T E" + "\n", style="bold bright_green")
    title.append(r"    ADVANCED RECON SUITE" + "\n", style="bold bright_cyan")
    title.append(r"    Active Recon", style="bright_magenta")

    safe_console_print(
        Panel(
            Align.center(title),
            box=box.ROUNDED,
            border_style="bright_cyan",
            padding=(0, 1),
        )
    )

def render_target_summary(target_url, domain, target_ip, headers=None, technologies=None, executed_modules=None):
    cdn = detect_cdn(headers)
    waf = detect_waf(headers)
    tech_value = ", ".join(sorted(technologies))[:100] if technologies else "Pending detection"
    rows = [
        ["URL", target_url],
        ["Domain", domain],
        ["IP", target_ip or "Could not resolve"],
        ["CDN", cdn],
        ["WAF", waf],
        ["Technologies", tech_value],
        ["Executed Modules", ", ".join(executed_modules) if executed_modules else "Pending"],
    ]
    print_table("[🎯] Target Summary", ["Field", "Value"], rows)

def detect_cdn(headers):
    if not headers:
        return "Unknown"
    combined = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    cdn_markers = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cf"],
        "Akamai": ["akamai", "akamaighost"],
        "Fastly": ["fastly", "x-served-by"],
        "CloudFront": ["cloudfront", "x-amz-cf"],
        "Sucuri": ["sucuri"],
    }
    for name, markers in cdn_markers.items():
        if any(marker in combined for marker in markers):
            return name
    return "Not detected"

def detect_waf(headers):
    if not headers:
        return "Unknown"
    combined = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    waf_markers = {
        "Cloudflare WAF": ["cf-ray", "cloudflare"],
        "Akamai Kona": ["akamai", "akamai-ghost"],
        "Sucuri WAF": ["sucuri"],
        "AWS WAF": ["awselb", "x-amzn"],
        "Imperva": ["incap_ses", "visid_incap", "imperva"],
        "F5 BIG-IP ASM": ["bigip", "f5"],
    }
    for name, markers in waf_markers.items():
        if any(marker in combined for marker in markers):
            return name
    return "Not detected"

def dns_enumeration(domain):
    rows = []
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CAA"]
    for record_type in record_types:
        try:
            output = subprocess.run(
                ["dig", "+short", domain, record_type],
                capture_output=True,
                text=True,
                timeout=15,
            )
            records = [line.strip() for line in output.stdout.splitlines() if line.strip()]
            if records:
                for record in records:
                    rows.append([record_type, record, "FOUND"])
            else:
                rows.append([record_type, "No records returned", "INFO"])
        except FileNotFoundError:
            rows.append(["dig", "dig command not installed", "ERROR"])
            break
        except subprocess.TimeoutExpired:
            rows.append([record_type, "DNS query timed out", "WARNING"])
    print_table("[🧬] DNS Enumeration", ["Type", "Record", "Status"], rows)

def cloud_detection(domain, headers=None):
    rows = []
    combined = " ".join(f"{k}: {v}" for k, v in (headers or {}).items()).lower()
    cloud_markers = {
        "AWS": ["amazonaws", "cloudfront", "x-amz", "awselb"],
        "Azure": ["azure", "microsoft", "azurewebsites"],
        "Google Cloud": ["google", "gcp", "googleusercontent"],
        "Cloudflare": ["cloudflare", "cf-ray"],
        "Vercel": ["vercel"],
        "Netlify": ["netlify"],
    }
    for provider, markers in cloud_markers.items():
        if any(marker in combined or marker in domain.lower() for marker in markers):
            rows.append([provider, "Detected from headers/domain markers", "DETECTED"])
    if not rows:
        rows.append(["Cloud Provider", "No strong cloud provider fingerprint found", "INFO"])
    print_table("[☁️] Cloud Detection", ["Provider", "Evidence", "Status"], rows)

def waf_detection(target_url, headers=None):
    rows = [[detect_waf(headers), "Header fingerprint", "DETECTED" if detect_waf(headers) not in {"Unknown", "Not detected"} else "INFO"]]
    probes = [
        ("SQLi probe", "' OR '1'='1"),
        ("XSS probe", "<script>alert(1)</script>"),
    ]
    for name, payload in probes:
        try:
            resp = requests.get(target_url, params={"v": payload}, timeout=8, verify=False, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code in {403, 406, 429, 501}:
                rows.append([name, f"HTTP {resp.status_code} response to probe", "REVIEW"])
            else:
                rows.append([name, f"HTTP {resp.status_code}", "INFO"])
        except Exception as e:
            rows.append([name, e, "WARNING"])
    print_table("[🛡️] WAF Detection", ["Check", "Evidence", "Status"], rows)

def run_whatweb_module(target_url, plugins=None, user_agent=None, timeout=120):
    whatweb_output = whatweb_scan(target_url, plugins=plugins, user_agent=user_agent, timeout=timeout)
    if whatweb_output:
        rows = parse_whatweb_json(whatweb_output)
        if rows:
            print_table("[🔍] WhatWeb Technology Detection", ["Plugin", "Details"], rows, "No WhatWeb findings parsed.")
        else:
            print_table("[🔍] WhatWeb Technology Detection", ["Plugin", "Details"], [["INFO", "No plugins detected"]])
    else:
        print_table("[🔍] WhatWeb Technology Detection", ["Plugin", "Details"], [["ERROR", "WhatWeb scan produced no output. Tool may not be installed."]])

def run_nikto_module(target_url, ssl=False, tuning=None, plugins=None, cookies=None):
    output = nikto_scan(target_url, ssl=ssl, tuning=tuning, plugins=plugins, cookies=cookies)
    if output:
        filtered = [line for line in output.splitlines() if not ("OSVDB-" in line and "unusual" in line.lower())]
        output_to_table("[🧪] Nikto Scan", "\n".join(filtered))
    else:
        print_table("[🧪] Nikto Scan", ["Type", "Result"], [["INFO", "No output produced"]])

def run_nmap_module(
    domain,
    aggressive=False,
    scripts=False,
    udp=False,
    all_ports=False,
    top_ports=None,
    ports=None,
    version_intensity=None,
    max_retries=None,
    host_timeout=None,
    min_rate=None,
):
    if any([aggressive, scripts, udp, all_ports, top_ports, ports, version_intensity is not None, max_retries is not None, host_timeout, min_rate is not None]):
        option_rows = [
            ["Aggressive", "Enabled" if aggressive else "Disabled"],
            ["Scripts", "Enabled" if scripts else "Disabled"],
            ["UDP", "Enabled" if udp else "Disabled"],
            ["All Ports", "Enabled" if all_ports else "Disabled"],
            ["Top Ports", str(top_ports) if top_ports else "Default"],
            ["Ports", ports if ports else "Default"],
            ["Version Intensity", str(version_intensity) if version_intensity is not None else "Default"],
            ["Max Retries", str(max_retries) if max_retries is not None else "Default"],
            ["Host Timeout", str(host_timeout) if host_timeout else "Default"],
            ["Min Rate", str(min_rate) if min_rate is not None else "Default"],
        ]
        print_table("[🛰️] Nmap Options", ["Flag", "Value"], option_rows)

    output = nmap_scan(
        domain,
        aggressive=aggressive,
        scripts=scripts,
        udp=udp,
        all_ports=all_ports,
        top_ports=top_ports,
        ports=ports,
        version_intensity=version_intensity,
        max_retries=max_retries,
        host_timeout=host_timeout,
        min_rate=min_rate,
    )
    if output:
        rows = parse_nmap_output(output)
        print_table("[🛰️] Nmap Fast Scan", ["Port", "State", "Service", "Version"], rows, "No open ports detected or no output parsed.")
    else:
        print_table("[🛰️] Nmap Fast Scan", ["Port", "State", "Service", "Version"], [["INFO", "-", "-", "No output produced"]])

def run_arjun_module(target_url, method=None, headers=None, wordlist=None, threads=None):
    output = arjun_scan(target_url, method=method, headers=headers, wordlist=wordlist, threads=threads)
    if output:
        output_to_table("[🔎] Arjun Parameter Fuzzing", output)
    else:
        print_table("[🔎] Arjun Parameter Fuzzing", ["Type", "Result"], [["INFO", "No output produced"]])

def run_bbot_module(domain, timeout, modules=None):
    output, bbot_message = bbot_scan(domain, timeout=timeout, modules=modules)
    print_bbot_results(output, bbot_message)

def run_module(progress, task_id, name, func, *args, **kwargs):
    if progress is not None and task_id is not None:
        progress.update(task_id, description=f"{name} running")
    func(*args, **kwargs)
    if progress is not None and task_id is not None:
        progress.advance(task_id)

def render_stats_dashboard(elapsed):
    table = Table(box=box.HEAVY_EDGE, expand=True, header_style="bold bright_green")
    table.add_column("Metric", style="bright_cyan")
    table.add_column("Value", style="bold white")
    table.add_row("Modules Rendered", str(SCAN_STATS["modules"]))
    table.add_row("Result Rows", str(SCAN_STATS["rows"]))
    table.add_row("Positive Findings", str(SCAN_STATS["findings"]))
    table.add_row("Warnings / Review Items", str(SCAN_STATS["warnings"]))
    table.add_row("Errors", str(SCAN_STATS["errors"]))
    table.add_row("Execution Time", f"{elapsed:.2f}s")
    safe_console_print(Panel(table, title="[bold bright_magenta]📊 Scan Statistics Dashboard[/]", border_style="bright_green"))

# -----------------------------------------------------------------------------
# Main orchestrator
# -----------------------------------------------------------------------------
def main():
    global COLOR_ENABLED, EXECUTED_MODULES
    SCAN_STATS["start"] = time.perf_counter()
    parser = argparse.ArgumentParser(description="Advanced Recon Tool - with Wappalyzer & WhatWeb")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("--skip-external", action="store_true", help="Skip external tools (whatweb, nikto, nmap, arjun, bbot)")
    parser.add_argument("--skip-bbot", action="store_true", help="Skip only BBOT passive recon")
    parser.add_argument("--bbot-timeout", type=int, default=90, help="BBOT timeout in seconds (default: 90)")
    parser.add_argument("--bbot-modules", nargs="+", help="Override BBOT modules, e.g. crt hackertarget anubisdb rapiddns")
    parser.add_argument("--whatweb-plugins", help="Limit WhatWeb to specific plugins")
    parser.add_argument("--whatweb-user-agent", help="Set WhatWeb user-agent")
    parser.add_argument("--whatweb-timeout", type=int, default=120, help="WhatWeb timeout in seconds (default: 120)")
    parser.add_argument("--nikto-ssl", action="store_true", help="Force Nikto SSL mode (-ssl)")
    parser.add_argument("--nikto-tuning", help="Set Nikto tuning options (-Tuning)")
    parser.add_argument("--nikto-plugins", help="Load Nikto plugins (-Plugins)")
    parser.add_argument("--nikto-cookies", help="Send Nikto cookies (-C)")
    parser.add_argument("--arjun-method", help="Set Arjun HTTP method")
    parser.add_argument("--arjun-headers", help="Set Arjun custom headers")
    parser.add_argument("--arjun-wordlist", help="Set Arjun wordlist")
    parser.add_argument("--arjun-threads", type=int, help="Set Arjun thread count")
    parser.add_argument("--nmap-aggressive", action="store_true", help="Use aggressive Nmap scan (-A -O --osscan-guess)")
    parser.add_argument("--nmap-scripts", action="store_true", help="Run default Nmap scripts (-sC)")
    parser.add_argument("--nmap-udp", action="store_true", help="Include UDP scan (-sU)")
    parser.add_argument("--nmap-all-ports", action="store_true", help="Scan all TCP ports (-p-)")
    parser.add_argument("--nmap-top-ports", type=int, help="Scan top N ports (--top-ports N)")
    parser.add_argument("--nmap-ports", help="Scan a custom port list (-p 22,80,443)")
    parser.add_argument("--nmap-version-intensity", type=int, help="Set Nmap version intensity (0-9)")
    parser.add_argument("--nmap-max-retries", type=int, help="Set Nmap max retries")
    parser.add_argument("--nmap-host-timeout", help="Set Nmap host timeout, e.g. 10m")
    parser.add_argument("--nmap-min-rate", type=int, help="Set Nmap minimum packet rate")
    parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Color output mode: auto, always, or never"
    )
    args = parser.parse_args()
    if args.color == "always":
        COLOR_ENABLED = True
    elif args.color == "never":
        COLOR_ENABLED = False

    # Normalise target
    target_url = args.url
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    parsed = urlparse(target_url)
    domain = parsed.netloc.split(':')[0]

    render_banner()

    target_ip = None
    try:
        target_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        pass

    _, target_headers = fetch_url(target_url, timeout=8)
    executed_modules = []

    module_plan = [
        ("Subdomain Enumeration", subdomain_enum, (domain,), {}),
        ("Technology Detection (Wappalyzer)", wappalyzer_scan, (target_url,), {}),
        ("Sensitive Data Discovery", sensitive_info_check, (target_url,), {}),
        ("Header Analysis", check_security_headers, (target_url,), {}),
        ("SSL Analysis", ssl_analysis, (target_url,), {}),
        ("DNS Enumeration", dns_enumeration, (domain,), {}),
        ("Cloud Detection", cloud_detection, (domain, target_headers), {}),
        ("WAF Detection", waf_detection, (target_url, target_headers), {}),
        ("IP Disclosure Check", ip_disclosure_check, (target_url, domain), {}),
        ("WHOIS Lookup", whois_lookup, (domain,), {}),
    ]

    if not args.skip_external:
        module_plan.extend([
            ("WhatWeb", run_whatweb_module, (target_url, args.whatweb_plugins, args.whatweb_user_agent, args.whatweb_timeout), {}),
            ("Nikto", run_nikto_module, (target_url, args.nikto_ssl, args.nikto_tuning, args.nikto_plugins, args.nikto_cookies), {}),
            (
                "Nmap",
                run_nmap_module,
                (
                    domain,
                    args.nmap_aggressive,
                    args.nmap_scripts,
                    args.nmap_udp,
                    args.nmap_all_ports,
                    args.nmap_top_ports,
                    args.nmap_ports,
                    args.nmap_version_intensity,
                    args.nmap_max_retries,
                    args.nmap_host_timeout,
                    args.nmap_min_rate,
                ),
                {},
            ),
            ("Arjun", run_arjun_module, (target_url, args.arjun_method, args.arjun_headers, args.arjun_wordlist, args.arjun_threads), {}),
        ])
        if not args.skip_bbot:
            module_plan.append(("BBOT Passive Recon", run_bbot_module, (domain, args.bbot_timeout, args.bbot_modules), {}))
        else:
            module_plan.append(("BBOT Passive Recon", lambda: print_table("[🧭] BBOT Passive Recon", ["Tool", "Status"], [["bbot", "Skipped by --skip-bbot"]]), (), {}))
    else:
        module_plan.append(("External Tools", lambda: print_table("[⏩] External Tools", ["Tool", "Status"], [["whatweb / nikto / nmap / arjun / bbot", "Skipped by --skip-external"]]), (), {}))

    EXECUTED_MODULES = [
        "Subdomain Enumeration",
        "Technology Detection (Wappalyzer)",
        "Sensitive Data Discovery",
        "Header Analysis",
        "SSL Analysis",
        "DNS Enumeration",
        "Cloud Detection",
        "WAF Detection",
        "IP Disclosure Check",
        "WHOIS Lookup",
    ]
    render_target_summary(target_url, domain, target_ip, target_headers, executed_modules=EXECUTED_MODULES)

    safe_console_print(Rule("[bold bright_cyan]Scan Progress[/]"))
    for name, func, f_args, f_kwargs in module_plan:
        safe_console_print(Rule(f"[bold bright_magenta]{name}[/]"))
        run_module(None, None, name, func, *f_args, **f_kwargs)

    elapsed = time.perf_counter() - SCAN_STATS["start"]
    render_stats_dashboard(elapsed)
    safe_console_print(Panel(
        "[bold green]✔ Analysis complete.[/] [yellow]Review findings manually before reporting or exploiting anything.[/]",
        border_style="bright_green",
        box=box.DOUBLE,
    ))

if __name__ == "__main__":
    main()
