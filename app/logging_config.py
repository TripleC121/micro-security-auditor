"""Structured JSON logging configuration for observability."""

import json
import logging
import sys
from datetime import datetime, timezone

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record):
        """Format log record as JSON with consistent structure."""
        log_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
        }
        
        # Add extra fields if present (run_id, metrics, etc.)
        if hasattr(record, 'run_id'):
            log_data['run_id'] = record.run_id
        if hasattr(record, 'component'):
            log_data['component'] = record.component
        if hasattr(record, 'resources_scanned'):
            log_data['resources_scanned'] = record.resources_scanned
        if hasattr(record, 'findings_count'):
            log_data['findings_count'] = record.findings_count
        if hasattr(record, 'duration_seconds'):
            log_data['duration_seconds'] = record.duration_seconds
            
        # Add any other extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'created', 'filename', 
                          'funcName', 'levelname', 'levelno', 'lineno', 
                          'module', 'msecs', 'message', 'pathname', 'process',
                          'processName', 'relativeCreated', 'stack_info',
                          'thread', 'threadName', 'exc_info', 'exc_text',
                          'run_id', 'component', 'resources_scanned',
                          'findings_count', 'duration_seconds']:
                log_data[key] = value
        
        return json.dumps(log_data)

def setup_logging(level=logging.INFO):
    """Configure structured JSON logging for the application."""
    # Clear any existing handlers
    root = logging.getLogger()
    root.handlers = []
    
    # Create console handler with JSON formatter
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    
    # Configure root logger
    root.setLevel(level)
    root.addHandler(handler)
    
    # Suppress boto3/botocore noise
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    return root
