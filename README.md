# 🛡️ Ransomware Defense System

A real-time file monitoring system that detects and stops ransomware-like behavior on your computer.

## What It Does

- **Monitors** a folder for suspicious file activity
- **Detects** ransomware patterns (mass encryption, suspicious extensions, high entropy)
- **Responds** automatically by killing malicious processes and locking folders
- **Includes** a GUI for easy control and testing

---

## Quick Start

### 1. Install Dependencies

```bash
pip install watchdog psutil
```

### 2. Run the Defense System

```bash
python3 main.py
```

### 3. Test It (Optional)

```bash
# Create test files and run simulation
python3 simulate_ransomware.py --create-test-files
```

### 4. Use the GUI (Easier)

```bash
python3 gui_controller.py
```

---

## GUI Features

**5 Main Buttons:**
- ▶️ **Start Defense System** - Begins monitoring files
- ⏹️ **Stop Defense System** - Stops monitoring
- 🧪 **Run Simulation** - Tests the system with fake ransomware
- 🗑️ **Reset Directories** - Cleans up test files
- 🔍 **Check Folder Lock** - Shows if folder is locked (protected) or unlocked

**Two Live Terminals:**
- Left: Defense system logs
- Right: Simulation and status logs

---

## How It Works

1. **Monitors** the `protected_data/` folder for file changes
2. **Analyzes** each change for suspicious patterns:
   - Too many files modified too quickly (5+ files in 10 seconds)
   - Files renamed to `.encrypted`, `.locked`, etc.
   - High entropy = encrypted files
3. **Takes Action** when threat detected:
   - Kills the malicious process
   - Locks the folder (read-only)
   - Alerts you with logs

---

## Project Files

```
ransomware-defense-system/
├── main.py                    # Main program
├── monitor.py                 # Watches files
├── detector.py                # Detects threats
├── responder.py               # Takes action
├── config.py                  # Settings
├── gui_controller.py          # GUI control panel
└── simulate_ransomware.py     # Safe test simulator
```

---

## Configuration

Edit `config.py` to change settings:

```python
THRESHOLD_FILES_MODIFIED = 5    # Files before alert
THRESHOLD_TIME_WINDOW = 10      # Seconds to watch
THRESHOLD_ENTROPY = 7.0         # Encryption threshold

ENABLE_PROCESS_KILL = True      # Kill malicious process?
ENABLE_DIRECTORY_LOCK = True    # Lock folder?
```

---

## Common Commands

```bash
# Start monitoring
python3 main.py

# Run simulation test
python3 simulate_ransomware.py --create-test-files

# Reset everything after test
chmod -R u+w protected_data
rm -rf protected_data backup logs
mkdir protected_data

# Check if folder is locked
ls -la protected_data
```

---

## What Gets Detected

✅ **Mass file encryption** (many files changed quickly)  
✅ **Suspicious file extensions** (.encrypted, .locked, .crypto)  
✅ **High entropy files** (encrypted data)  
✅ **Rapid file renaming**  

---

## Limitations

⚠️ **This is a demo project for learning purposes**

- Not a replacement for real antivirus software
- May have false positives (compressed files, etc.)
- Requires proper permissions to kill processes
- Best tested on Linux/Mac

---

## Example Output

```
🛡️  Ransomware Defense System Active
📁 Monitoring: /home/user/protected_data

================================================================================
🚨 RANSOMWARE ATTACK DETECTED!
Process: python3 (PID: 12345)
Threat Reasons: 2
  1. mass_modification
  2. suspicious_extension
================================================================================

✅ Terminated malicious process (PID: 12345)
✅ Protected directory locked: /home/user/protected_data
```


## Requirements

- Python 3.8+
- Linux, macOS, or Windows (with WSL)
- Libraries: `watchdog`, `psutil`

---

**Built for educational purposes to demonstrate ransomware detection techniques.**

