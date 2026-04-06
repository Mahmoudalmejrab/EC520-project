#!/usr/bin/env python3
import time
import subprocess
import os

# Configuration
TEST_LOG = "test_auth.log"
BLOCKER_SCRIPT = "ssh_blocker.py"
MOCK_IP = "1.2.3.4"

def run_test():
    # 1. Create a clean test log file
    print(f"[1/4] Creating test log: {TEST_LOG}")
    with open(TEST_LOG, "w") as f:
        f.write("# Simulated Auth Log\n")

    # 2. Start the blocker script in DRY-RUN mode in the background
    print(f"[2/4] Starting {BLOCKER_SCRIPT} in background (DRY-RUN mode)...")
    try:
        process = subprocess.Popen(
            ["python3", "-u", BLOCKER_SCRIPT, "--log", TEST_LOG, "--dry-run"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except Exception as e:
        print(f"[ERROR] Could not start script: {e}")
        return

    # Give the background process a moment to start tailing
    time.sleep(1)

    # 3. Simulate 5 SSH connection attempts from the same IP
    print(f"[3/4] Simulating 5 SSH attempts from {MOCK_IP}...")
    with open(TEST_LOG, "a") as f:
        for i in range(1, 6):
            # Typical SSH failure log format
            log_entry = f"2026-04-06T20:00:{i:02d}.000000+00:00 server sshd[123]: Failed password for root from {MOCK_IP} port 5678 ssh2\n"
            f.write(log_entry)
            f.flush()
            print(f"      Attempt {i} logged.")
            time.sleep(0.5)

    # 4. Wait and capture output
    print("[4/4] Checking results...")
    time.sleep(2)
    process.terminate()
    stdout, stderr = process.communicate()

    print("\n--- Blocker Output ---")
    print(stdout if stdout else "No output captured.")
    if stderr:
        print("--- Errors ---")
        print(stderr)
    print("----------------------")

    # Cleanup
    if os.path.exists(TEST_LOG):
        os.remove(TEST_LOG)
    print("\nTest complete. Cleanup finished.")

if __name__ == "__main__":
    run_test()
