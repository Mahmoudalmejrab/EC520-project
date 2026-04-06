#!/usr/bin/env python3
import os
import re
import sys
import time
import subprocess
from collections import deque, defaultdict
import argparse

# Config
LOG_FILE = "/var/log/auth.log"
THRESHOLD = 3
WINDOW = 60  # seconds (1 minute)
FIREWALL_CMD = "ufw"

# Store connection attempt timestamps per IP
# Format: { ip: deque([timestamp1, timestamp2, ...]) }
attempts = defaultdict(lambda: deque())
blocked_ips = set()

def is_root():
    """Verify if the script is running as root."""
    return os.geteuid() == 0

def block_ip(ip, dry_run=False):
    """Block the specified IP using UFW."""
    if dry_run:
        print(f"[DRY-RUN] Would block IP: {ip}")
        return True
    
    if ip in blocked_ips:
        return False

    try:
        print(f"[ACTION] Blocking IP: {ip} due to excessive SSH attempts (> {THRESHOLD} in {WINDOW}s)...")
        # Using subprocess to interact with UFW safely
        result = subprocess.run([FIREWALL_CMD, "deny", "from", ip], 
                                capture_output=True, text=True, check=True)
        print(f"[SUCCESS] {result.stdout.strip()}")
        blocked_ips.add(ip)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block {ip}: {e.stderr.strip()}", file=sys.stderr)
        return False

def tail_file(filename):
    """Continuously yield lines from the end of a file."""
    try:
        with open(filename, "r") as f:
            # Go to the end of the file to start monitoring new entries
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1) # Wait for new entries
                    continue
                yield line
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped by user.")
    except Exception as e:
        print(f"[ERROR] Could not read {filename}: {e}", file=sys.stderr)

def extract_ip(line):
    """Extract IP address from an SSH login attempt log line."""
    # Common log patterns for SSH connections and failures:
    # "sshd[...]: Failed password for invalid user bistu2 from 193.32.162.82 port 35556 ssh2"
    # "sshd[...]: Invalid user bistu2 from 193.32.162.82 port 35556"
    # "sshd[...]: Accepted password for root from 1.2.3.4 port 12345"
    if "sshd" in line:
        # Match 'from <IP>'
        match = re.search(r"from ([\d\.]+)", line)
        if match:
            return match.group(1)
    return None

def monitor(log_path, dry_run=False):
    """Monitor SSH logs and block IPs exceeding threshold."""
    print(f"[INFO] Monitoring {log_path} for SSH brute-force attempts...")
    print(f"[INFO] Settings: Threshold = {THRESHOLD}, Window = {WINDOW}s, Mode = {'DRY-RUN' if dry_run else 'ACTIVE'}")

    for line in tail_file(log_path):
        ip = extract_ip(line)
        if ip:
            now = time.time()
            # Add current attempt timestamp
            attempts[ip].append(now)
            
            # Remove timestamps older than the sliding window
            while attempts[ip] and attempts[ip][0] < now - WINDOW:
                attempts[ip].popleft()
            
            # Check if threshold exceeded
            if len(attempts[ip]) > THRESHOLD:
                block_ip(ip, dry_run)
                # Cleanup to avoid repeated blocking signals for the same window
                # The firewall will handle the actual block.
                attempts[ip].clear()

def main():
    parser = argparse.ArgumentParser(description="SSH Brute-Force Blocker")
    parser.add_argument("--log", default=LOG_FILE, help=f"Path to SSH auth log (default: {LOG_FILE})")
    parser.add_argument("--dry-run", action="store_true", help="Simulate blocking without modifying firewall rules")
    args = parser.parse_args()

    # Pre-checks
    if not args.dry_run and not is_root():
        print("[CRITICAL] This script must be run as root to modify firewall rules. Use sudo.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.log):
         print(f"[CRITICAL] Log file {args.log} does not exist.", file=sys.stderr)
         sys.exit(1)

    monitor(args.log, args.dry_run)

if __name__ == "__main__":
    main()
