"""
Threat Response Module
Takes action when ransomware-like behavior is detected
"""
import os
import signal
import stat
import shutil
import logging
import psutil
import config

logger = logging.getLogger(__name__)


class ThreatResponder:
    """Responds to detected threats"""
    
    def __init__(self, detector):
        self.detector = detector
        self.killed_processes = set()
        self.locked_directories = set()
        
    def kill_process(self, pid):
        """
        Terminate a malicious process
        
        Args:
            pid: Process ID to kill
        """
        if not config.ENABLE_PROCESS_KILL:
            logger.info(f"Process kill disabled in config. Would kill PID: {pid}")
            return False
        
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            
            logger.warning(f"⚠️ KILLING MALICIOUS PROCESS: {process_name} (PID: {pid})")
            
            # Try graceful termination first
            process.terminate()
            
            # Wait a bit
            try:
                process.wait(timeout=3)
            except psutil.TimeoutExpired:
                # Force kill if still running
                process.kill()
                logger.warning(f"Force killed process {pid}")
            
            self.killed_processes.add(pid)
            self.detector.blacklisted_pids.add(pid)
            
            return True
            
        except psutil.NoSuchProcess:
            logger.info(f"Process {pid} already terminated")
            return False
        except psutil.AccessDenied:
            logger.error(f"Access denied: Cannot kill process {pid} (try running with sudo)")
            return False
        except Exception as e:
            logger.error(f"Error killing process {pid}: {e}")
            return False
    
    def lock_directory(self, directory):
        """
        Make directory read-only to prevent further modifications
        
        Args:
            directory: Directory path to lock
        """
        if not config.ENABLE_DIRECTORY_LOCK:
            logger.info(f"Directory lock disabled. Would lock: {directory}")
            return False
        
        try:
            # Remove write permissions for all users
            current_permissions = os.stat(directory).st_mode
            
            # Remove write bits
            new_permissions = current_permissions & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
            
            os.chmod(directory, new_permissions)
            
            # Also lock all files in directory
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        current_file_perms = os.stat(file_path).st_mode
                        new_file_perms = current_file_perms & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
                        os.chmod(file_path, new_file_perms)
                    except Exception as e:
                        logger.warning(f"Could not lock file {file_path}: {e}")
            
            self.locked_directories.add(directory)
            logger.warning(f"🔒 DIRECTORY LOCKED: {directory}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error locking directory {directory}: {e}")
            return False
    
    def unlock_directory(self, directory):
        """
        Restore write permissions to a locked directory
        
        Args:
            directory: Directory path to unlock
        """
        try:
            # Restore write permissions
            current_permissions = os.stat(directory).st_mode
            new_permissions = current_permissions | stat.S_IWUSR
            
            os.chmod(directory, new_permissions)
            
            # Unlock files
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        current_file_perms = os.stat(file_path).st_mode
                        new_file_perms = current_file_perms | stat.S_IWUSR
                        os.chmod(file_path, new_file_perms)
                    except Exception as e:
                        logger.warning(f"Could not unlock file {file_path}: {e}")
            
            self.locked_directories.remove(directory)
            logger.info(f"🔓 DIRECTORY UNLOCKED: {directory}")
            
        except Exception as e:
            logger.error(f"Error unlocking directory {directory}: {e}")
    
    def backup_file(self, file_path):
        """
        Create a backup of a file before it's modified
        
        Args:
            file_path: Path to file to backup
        """
        if not config.ENABLE_AUTO_BACKUP:
            return False
        
        try:
            # Create backup directory if it doesn't exist
            os.makedirs(config.BACKUP_DIR, exist_ok=True)
            
            # Generate backup filename
            filename = os.path.basename(file_path)
            backup_path = os.path.join(config.BACKUP_DIR, f"{filename}.backup")
            
            # Copy file
            shutil.copy2(file_path, backup_path)
            logger.info(f"📦 Backed up: {file_path} -> {backup_path}")
            
            return True
            
        except Exception as e:
            logger.warning(f"Could not backup {file_path}: {e}")
            return False
    
    def respond_to_threat(self, detection_result):
        """
        Take action based on threat detection
        
        Args:
            detection_result: Detection results from analyzer
        """
        if not detection_result.get('threat_detected'):
            return
        
        pid = detection_result.get('pid')
        process_name = detection_result.get('process_name', 'unknown')
        reasons = detection_result.get('reasons', [])
        
        # Log the threat
        logger.critical("=" * 80)
        logger.critical("🚨 RANSOMWARE-LIKE BEHAVIOR DETECTED!")
        logger.critical(f"Process: {process_name} (PID: {pid})")
        logger.critical(f"File: {detection_result.get('file_path', 'unknown')}")
        logger.critical(f"Reasons:")
        
        for reason in reasons:
            logger.critical(f"  - {reason}")
        
        logger.critical("=" * 80)
        
        # Print console alert
        if config.CONSOLE_ALERTS:
            print("\n" + "=" * 80)
            print("🚨 RANSOMWARE ATTACK DETECTED!")
            print(f"Process: {process_name} (PID: {pid})")
            print(f"Threat Reasons: {len(reasons)}")
            for i, reason in enumerate(reasons, 1):
                print(f"  {i}. {reason.get('reason', 'unknown')}")
            print("=" * 80 + "\n")
        
        # Take action: Kill the process
        # Take action: Kill the process (skip in demo mode)
        if pid and pid not in self.killed_processes:
            if config.DEMO_MODE:
                logger.warning("🧪 Demo mode: skipping process kill")
                print("🧪 Demo mode: process kill skipped")
            else:
                success = self.kill_process(pid)
                if success:
                    print(f"✅ Terminated malicious process (PID: {pid})")

        
        # Take action: Lock the protected directory
        if config.PROTECTED_DIR not in self.locked_directories:
            success = self.lock_directory(config.PROTECTED_DIR)
            if success:
                print(f"✅ Protected directory locked: {config.PROTECTED_DIR}")
                print("   Run 'unlock_protection()' to restore write access")