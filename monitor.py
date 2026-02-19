"""
File System Monitor using watchdog
Tracks all file system events in protected directories
"""
import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import logging


logger = logging.getLogger(__name__)

class FileEventHandler(FileSystemEventHandler):
    """Custom handler for file system events"""
    
    def __init__(self, event_callback):
        super().__init__()
        self.event_callback = event_callback
        
    def _get_process_info(self):
        """Get information about the process that triggered the file change"""
        try:
            # Get all processes accessing files
            current_process = psutil.Process()
            parent = current_process.parent()
            
            return {
                'pid': parent.pid if parent else os.getpid(),
                'name': parent.name() if parent else 'unknown',
                'cmdline': ' '.join(parent.cmdline()) if parent else 'unknown'
            }
        except Exception as e:
            logger.warning(f"Could not get process info: {e}")
            return {'pid': None, 'name': 'unknown', 'cmdline': 'unknown'}
    
    def on_modified(self, event):
        """Called when a file is modified"""
        if not event.is_directory:
            process_info = self._get_process_info()
            self.event_callback('modified', event.src_path, process_info)
    
    def on_created(self, event):
        """Called when a file is created"""
        if not event.is_directory:
            process_info = self._get_process_info()
            self.event_callback('created', event.src_path, process_info)
    
    def on_deleted(self, event):
        """Called when a file is deleted"""
        if not event.is_directory:
            process_info = self._get_process_info()
            self.event_callback('deleted', event.src_path, process_info)
    
    def on_moved(self, event):
        """Called when a file is moved/renamed"""
        if not event.is_directory:
            process_info = self._get_process_info()
            # Moved events have both src and dest paths
            self.event_callback('moved', event.src_path, process_info, 
                              dest_path=event.dest_path)


class FileSystemMonitor:
    """Monitor file system for changes"""
    
    def __init__(self, path, event_callback):
        """
        Initialize the monitor
        
        Args:
            path: Directory path to monitor
            event_callback: Function to call when events occur
        """
        self.path = path
        self.event_callback = event_callback
        self.observer = Observer()
        
    def start(self):
        """Start monitoring the file system"""
        event_handler = FileEventHandler(self.event_callback)
        self.observer.schedule(event_handler, self.path, recursive=True)
        self.observer.start()
        logger.info(f"Started monitoring: {self.path}")
        
    def stop(self):
        """Stop monitoring"""
        self.observer.stop()
        self.observer.join()
        logger.info(f"Stopped monitoring: {self.path}")