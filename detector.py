"""
Behavioral Detection Engine
Analyzes file system events to detect ransomware-like patterns
"""
import time
import os
import math
from collections import defaultdict, deque
import logging
import config
   
logger = logging.getLogger(__name__)


class RansomwareDetector:
    """Detects ransomware-like behavior patterns"""
    
    def __init__(self):
        # Track events per process
        self.process_events = defaultdict(lambda: deque(maxlen=100))
        
        # Track file modifications with timestamps
        self.recent_modifications = deque(maxlen=1000)
        
        # Track extension changes
        self.extension_changes = defaultdict(int)
        
        # Blacklisted PIDs (detected as malicious)
        self.blacklisted_pids = set()
        
    def calculate_entropy(self, file_path):
        """
        Calculate Shannon entropy of a file
        High entropy (>7.0) often indicates encryption
        
        Args:
            file_path: Path to file
            
        Returns:
            float: Entropy value (0-8)
        """
        try:
            # Read first 1024 bytes for efficiency
            with open(file_path, 'rb') as f:
                data = f.read(1024)
            
            if len(data) == 0:
                return 0.0
            
            # Calculate frequency of each byte
            frequency = defaultdict(int)
            for byte in data:
                frequency[byte] += 1
            
            # Calculate Shannon entropy
            entropy = 0.0
            for count in frequency.values():
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            logger.warning(f"Could not calculate entropy for {file_path}: {e}")
            return 0.0
    
    def is_suspicious_extension(self, file_path):
        """Check if file has a suspicious extension"""
        _, ext = os.path.splitext(file_path)
        return ext.lower() in config.SUSPICIOUS_EXTENSIONS
    
    def detect_mass_modification(self):
        """
        Detect if many files are being modified rapidly
        
        Returns:
            tuple: (is_suspicious, details)
        """
        current_time = time.time()
        
        # Remove old events outside time window
        while (self.recent_modifications and 
               current_time - self.recent_modifications[0]['time'] > config.THRESHOLD_TIME_WINDOW):
            self.recent_modifications.popleft()
        
        # Check if threshold exceeded
        if len(self.recent_modifications) >= config.THRESHOLD_FILES_MODIFIED:
            # Group by process
            process_counts = defaultdict(int)
            for event in self.recent_modifications:
                process_counts[event['pid']] += 1
            
            # Find the most active process
            max_pid = max(process_counts, key=process_counts.get)
            max_count = process_counts[max_pid]
            
            if max_count >= config.THRESHOLD_FILES_MODIFIED:
                return True, {
                    'reason': 'mass_modification',
                    'file_count': max_count,
                    'time_window': config.THRESHOLD_TIME_WINDOW,
                    'pid': max_pid,
                    'files': [e['path'] for e in self.recent_modifications if e['pid'] == max_pid]
                }
        
        return False, {}
    
    def detect_extension_change_attack(self):
        """
        Detect if file extensions are being changed en masse
        
        Returns:
            tuple: (is_suspicious, details)
        """
        # Check if we have multiple extension changes
        total_changes = sum(self.extension_changes.values())
        
        if total_changes >= config.THRESHOLD_FILES_MODIFIED:
            return True, {
                'reason': 'extension_change_attack',
                'total_changes': total_changes,
                'extensions': dict(self.extension_changes)
            }
        
        return False, {}
    
    def analyze_event(self, event_type, file_path, process_info, dest_path=None):
        """
        Analyze a file system event for suspicious behavior
        
        Args:
            event_type: Type of event (modified, created, deleted, moved)
            file_path: Path to affected file
            process_info: Information about the process
            dest_path: Destination path for moved files
            
        Returns:
            dict: Detection results
        """
        pid = process_info.get('pid')
        process_name = process_info.get('name', 'unknown')
        
        # Skip if process is blacklisted already
        if pid in self.blacklisted_pids:
            return {
                'threat_detected': True,
                'reason': 'blacklisted_process',
                'pid': pid,
                'process_name': process_name,
                'file_path': file_path
            }
        
        # Skip trusted processes
        if process_name in config.TRUSTED_PROCESSES:
            return {'threat_detected': False}
        
        detection_result = {
            'threat_detected': False,
            'reasons': [],
            'pid': pid,
            'process_name': process_name,
            'file_path': file_path,
            'event_type': event_type
        }
        
        # Track the event
        current_time = time.time()
        event_data = {
            'time': current_time,
            'type': event_type,
            'path': file_path,
            'pid': pid,
            'process': process_name
        }
        
        self.recent_modifications.append(event_data)
        self.process_events[pid].append(event_data)
        
        # Check for mass modifications
        is_mass_mod, mass_mod_details = self.detect_mass_modification()
        if is_mass_mod:
            detection_result['threat_detected'] = True
            detection_result['reasons'].append(mass_mod_details)
        
        # Check for suspicious extensions
        if event_type in ['created', 'modified', 'moved']:
            check_path = dest_path if dest_path else file_path
            if self.is_suspicious_extension(check_path):
                detection_result['threat_detected'] = True
                detection_result['reasons'].append({
                    'reason': 'suspicious_extension',
                    'file': check_path
                })
        
        # Check for extension changes (rename attacks)
        if event_type == 'moved' and dest_path:
            src_ext = os.path.splitext(file_path)[1]
            dest_ext = os.path.splitext(dest_path)[1]
            
            if src_ext != dest_ext:
                self.extension_changes[dest_ext] += 1
                
                is_ext_attack, ext_attack_details = self.detect_extension_change_attack()
                if is_ext_attack:
                    detection_result['threat_detected'] = True
                    detection_result['reasons'].append(ext_attack_details)
        
        # Check for high entropy (encryption detection)
        if event_type in ['created', 'modified']:
            if os.path.exists(file_path):
                entropy = self.calculate_entropy(file_path)
                
                if entropy > config.THRESHOLD_ENTROPY:
                    detection_result['threat_detected'] = True
                    detection_result['reasons'].append({
                        'reason': 'high_entropy',
                        'entropy': entropy,
                        'file': file_path,
                        'note': 'File appears to be encrypted or highly compressed'
                    })
        
        return detection_result