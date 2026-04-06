# EC520 project - SSH Brute-Force Blocker

A Python script that automatically monitors SSH login attempts and blocks any IP address that exceeds 3 connection attempts within a one-minute window using `ufw`.

## Files
- `ssh_blocker.py`: The main script to monitor logs and block IPs.
- `run_test.py`: A utility script to verify the logic using mock logs.

## Usage

> [!IMPORTANT]
> This script requires **root privileges** to read system logs and modify firewall rules.

1. **Dry-Run mode (Simulate)**:
   ```bash
   sudo python3 ssh_blocker.py --dry-run
   ```

2. **Active mode (Live block)**:
   ```bash
   sudo python3 ssh_blocker.py
   ```

## Verification
You can use the provided test script to check the detection logic without actually blocking real IPs:
```bash
python3 run_test.py
```
