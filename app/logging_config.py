"""Structured JSON logging configuration for observability."""

import json
import logging
import sys
from datetime import datetime, timezone

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record):
        """Format log record as JSON with consistent structure."""
        # Start with core fields
        log_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
        }
        
        # Add known extra fields only (whitelist approach)
        # This explicitly controls what goes into the output
        extra_fields = {
            'run_id': None,
            'component': None,
            'resources_scanned': None,
            'findings_count': None,
            'duration_seconds': None,
            'mode': None,
            'use_llm': None,
            'total_findings': None,
            'security_score': None
        }
        
        for key in extra_fields:
            if hasattr(record, key):
                value = getattr(record, key)
                # Only add if not None
                if value is not None:
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