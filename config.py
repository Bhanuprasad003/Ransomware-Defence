"""
Configuration for Ransomware Prevention System
"""
import os

DEMO_MODE = True

# Directory to monitor and protect
PROTECTED_DIR = os.path.join(os.getcwd(), "protected_data")

# Backup directory for file recovery
BACKUP_DIR = os.path.join(os.getcwd(), "backup")

# Log file location
LOG_DIR = os.path.join(os.getcwd(), "logs")
LOG_FILE = os.path.join(LOG_DIR, "ransomware_defense.log")

# Detection thresholds
THRESHOLD_FILES_MODIFIED = 5  # Number of files modified
THRESHOLD_TIME_WINDOW = 10    # Within this many seconds
THRESHOLD_ENTROPY = 7.0       # Entropy threshold for encrypted files (0-8, higher = more random)

# Suspicious file extension patterns
SUSPICIOUS_EXTENSIONS = [
    '.encrypted', '.locked', '.crypto', '.crypt', 
    '.enc', '.ransom', '.pay', '.WNCRY'
]

# Trusted processes (PIDs will be added at runtime)
TRUSTED_PROCESSES = [
   
]

# Enable/disable features
ENABLE_PROCESS_KILL = True
ENABLE_DIRECTORY_LOCK = True
ENABLE_AUTO_BACKUP = True

# Alert settings
ALERT_EMAIL = None  # Set to email address for notifications
CONSOLE_ALERTS = True