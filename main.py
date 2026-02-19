"""
Main Orchestrator for Ransomware Prevention System
Coordinates all components
"""
import os
import time
import logging
import signal
import sys
from monitor import FileSystemMonitor
from detector import RansomwareDetector
from responder import ThreatResponder
import config


def setup_logging():
    """Configure logging system"""
    os.makedirs(config.LOG_DIR, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(config.LOG_FILE),
            logging.StreamHandler()
        ]
    )


class RansomwareDefenseSystem:
    """Main defense system coordinator"""
    
    def __init__(self):
        self.detector = RansomwareDetector()
        self.responder = ThreatResponder(self.detector)
        self.monitor = None
        self.logger = logging.getLogger(__name__)
        self.running = False
        
    def handle_file_event(self, event_type, file_path, process_info, dest_path=None):
        """
        Callback for file system events
        
        Args:
            event_type: Type of event
            file_path: Path to affected file
            process_info: Process information
            dest_path: Destination for moved files
        """
        # Log the event
        self.logger.info(f"Event: {event_type} - {file_path} - Process: {process_info.get('name', 'unknown')}")
        
        # Analyze the event
        detection_result = self.detector.analyze_event(
            event_type, file_path, process_info, dest_path
        )
        
        # Respond if threat detected
        if detection_result.get('threat_detected'):
            self.responder.respond_to_threat(detection_result)
    
    def start(self):
        """Start the defense system"""
        # Create protected directory if it doesn't exist
        os.makedirs(config.PROTECTED_DIR, exist_ok=True)
        os.makedirs(config.BACKUP_DIR, exist_ok=True)
        
        self.logger.info("=" * 80)
        self.logger.info("🛡️  RANSOMWARE DEFENSE SYSTEM STARTING")
        self.logger.info("=" * 80)
        self.logger.info(f"Protected Directory: {config.PROTECTED_DIR}")
        self.logger.info(f"Backup Directory: {config.BACKUP_DIR}")
        self.logger.info(f"Detection Threshold: {config.THRESHOLD_FILES_MODIFIED} files in {config.THRESHOLD_TIME_WINDOW}s")
        self.logger.info(f"Entropy Threshold: {config.THRESHOLD_ENTROPY}")
        self.logger.info("=" * 80)
        
        print("\n🛡️  Ransomware Defense System Active")
        print(f"📁 Monitoring: {config.PROTECTED_DIR}")
        print(f"⚠️  Press Ctrl+C to stop\n")
        
        # Start file system monitor
        self.monitor = FileSystemMonitor(config.PROTECTED_DIR, self.handle_file_event)
        self.monitor.start()
        
        self.running = True
        
        try:
            # Keep running
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the defense system"""
        self.logger.info("Stopping defense system...")
        print("\n🛑 Shutting down defense system...")
        
        if self.monitor:
            self.monitor.stop()
        
        # Unlock any locked directories
        for directory in list(self.responder.locked_directories):
            self.responder.unlock_directory(directory)
        
        self.running = False
        self.logger.info("Defense system stopped.")
        print("✅ Defense system stopped.\n")


def main():
    """Main entry point"""
    setup_logging()
    
    defense_system = RansomwareDefenseSystem()
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        defense_system.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        defense_system.start()
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()