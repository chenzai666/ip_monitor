#!/usr/bin/env python3
"""
Public IP Monitor - Cross-platform (Windows / Linux / macOS)
Usage:
  python ip_monitor.py
  python ip_monitor.py --verbose --proxy http://127.0.0.1:7890
Remote execute:
  Linux/macOS:  curl -Ls URL | python -
  Windows:      irm URL | python -
"""

import os
import sys
import re
import argparse
import platform
import ssl
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

# Defaults
DEFAULT_LOG_DIR = str(Path.home() / ".ip_monitor")
DEFAULT_LOG_FILE = os.path.join(DEFAULT_LOG_DIR, "ip_history.log")

IP_API_SERVICES = [
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://checkip.amazonaws.com",
    "https://ifconfig.me/ip",
    "https://ipinfo.io/ip"
]


def get_public_ip(proxy=None):
    """Get public IP address"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    https_handler = urllib.request.HTTPSHandler(context=ctx)
    handlers = [https_handler]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))

    opener = urllib.request.build_opener(*handlers)

    for service in IP_API_SERVICES:
        try:
            req = urllib.request.Request(service, headers={"User-Agent": user_agent})
            with opener.open(req, timeout=10) as response:
                ip = response.read().decode('utf-8').strip()
                if ip and validate_ip(ip):
                    return ip
        except (urllib.error.URLError, urllib.error.HTTPError,
                ConnectionResetError, TimeoutError) as e:
            reason = str(e.reason) if hasattr(e, 'reason') else str(e)
            print(f"  - {service} failed: {reason}")
            continue
        except Exception as e:
            print(f"  - {service} error: {str(e)}")
            continue

    print("ERROR: All IP services failed!")
    return None


def validate_ip(ip):
    """Validate IP format and exclude private ranges (RFC 1918)"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False

    nums = []
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
        nums.append(num)

    # 10.0.0.0/8
    if nums[0] == 10:
        return False
    # 172.16.0.0/12
    if nums[0] == 172 and 16 <= nums[1] <= 31:
        return False
    # 192.168.0.0/16
    if nums[0] == 192 and nums[1] == 168:
        return False

    return True


def setup_logging(log_path):
    """Create log directory and file if not exist"""
    try:
        log_dir = os.path.dirname(log_path)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            print(f"Created log dir: {log_dir}")

        if not os.path.exists(log_path):
            with open(log_path, 'w') as f:
                f.write("# IP Monitor Log - Format: [Time] [Status] [IP] [Details]\n")
                f.write("# Status: INIT=First, CHANGED=IP changed, UNCHANGED=No change\n")
                f.write("#" * 80 + "\n")
            try:
                os.chmod(log_path, 0o644)
            except AttributeError:
                pass
            print(f"Created log file: {log_path}")

        return True
    except Exception as e:
        print(f"Log setup failed: {str(e)}")
        return False


def write_log_entry(log_path, timestamp, status, ip, previous_ip=None):
    """Write a log entry"""
    try:
        with open(log_path, 'a') as f:
            if status == "INIT":
                f.write(f"[{timestamp}] INIT      {ip} (first record)\n")
            elif status == "CHANGED":
                f.write(f"[{timestamp}] CHANGED   {previous_ip} -> {ip}\n")
            else:
                f.write(f"[{timestamp}] UNCHANGED {ip} (same as last)\n")
        return True
    except Exception as e:
        print(f"Write log failed: {str(e)}")
        return False


def read_last_ip(log_path):
    """Read last recorded IP from log file (binary read, encoding agnostic)"""
    if not os.path.exists(log_path):
        return None

    try:
        with open(log_path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            if file_size == 0:
                return None

            pos = file_size
            buf = bytearray()
            while pos > 0:
                pos -= 1
                f.seek(pos)
                ch = f.read(1)
                if ch == b'\n' and len(buf) > 0:
                    line = buf.decode('ascii', errors='replace')[::-1].strip()
                    if any(k in line for k in ('UNCHANGED', 'CHANGED', 'INIT')):
                        match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                        if match:
                            return match.group(1)
                    buf = bytearray()
                else:
                    buf.extend(ch)
            if buf:
                line = buf.decode('ascii', errors='replace')[::-1].strip()
                match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                if match:
                    return match.group(1)
    except Exception as e:
        print(f"Read log failed: {str(e)}")

    return None


def main():
    print("=" * 60)
    print(f"IP Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"OS: {platform.system()} {platform.release()}")
    print(f"Python: {platform.python_version()}")
    print("=" * 60)

    parser = argparse.ArgumentParser(description='Public IP Monitor')
    parser.add_argument('--log', default=DEFAULT_LOG_FILE, help='Log file path')
    parser.add_argument('--proxy', default=None, help='Proxy (http://ip:port)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    log_path = os.path.abspath(args.log)

    if not setup_logging(log_path):
        print("ERROR: Log setup failed, exit.")
        sys.exit(1)

    start_time = datetime.now()
    timestamp = start_time.strftime('%Y-%m-%d %H:%M:%S')

    print("Fetching public IP...")
    if args.verbose:
        print(f"  - Proxy: {args.proxy if args.proxy else 'none'}")
        print(f"  - Services: {', '.join(IP_API_SERVICES)}")

    current_ip = get_public_ip(args.proxy)

    if not current_ip:
        print(f"[{timestamp}] ERROR: Cannot get public IP")
        try:
            with open(log_path, 'a') as f:
                f.write(f"[{timestamp}] ERROR Cannot get public IP\n")
        except Exception:
            pass
        sys.exit(1)

    last_ip = read_last_ip(log_path)

    if last_ip is None:
        status = "INIT"
    elif current_ip != last_ip:
        status = "CHANGED"
    else:
        status = "UNCHANGED"

    write_log_entry(log_path, timestamp, status, current_ip, last_ip)

    exec_time = (datetime.now() - start_time).total_seconds()

    print(f"\nResult:")
    print(f"  - Public IP: {current_ip}")

    if (current_ip.startswith("10.") or
            current_ip.startswith("192.168.") or
            (current_ip.startswith("172.") and
             16 <= int(current_ip.split('.')[1]) <= 31)):
        print("  - WARNING: Private IP detected, may not be correct")

    if status == "INIT":
        print(f"  - Status: First record")
    elif status == "CHANGED":
        print(f"  - Status: IP changed ({last_ip} -> {current_ip})")
    else:
        print(f"  - Status: No change")

    print(f"  - Log: {log_path}")
    print(f"  - Time: {exec_time:.2f}s")
    print("-" * 60)
    print(f"Done - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
