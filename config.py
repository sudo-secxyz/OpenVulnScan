import os

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Database
DB_PATH = os.path.join(DATA_DIR, "vulnscan.db")

def initialize_directories():
    """Create necessary directories and files for the application"""
    # Create directories
    for directory in [DATA_DIR, TEMPLATES_DIR, STATIC_DIR]:
        os.makedirs(directory, exist_ok=True)
    
    # Create basic HTML template if not exists
    INDEX_HTML = os.path.join(TEMPLATES_DIR, "index.html")
    if not os.path.exists(INDEX_HTML):
        with open(INDEX_HTML, "w", encoding='utf-8') as f:
            f.write("""<!DOCTYPE html>
<html>
<head><title>Scan History</title></head>
<body>
    <h1>Scan History</h1>
    <ul>
        {% for scan in scans %}
        <li><a href="/scan/{{ scan[0] }}">Scan {{ scan[0] }}</a> - Started: {{ scan[1] }} - Completed: {{ scan[2] or 'In progress' }}</li>
        {% endfor %}
    </ul>
</body>
</html>""")

    # Create scan result template if not exists
    SCAN_RESULT_HTML = os.path.join(TEMPLATES_DIR, "scan_result.html")
    if not os.path.exists(SCAN_RESULT_HTML):
        with open(SCAN_RESULT_HTML, "w", encoding='utf-8') as f:
            f.write("""<!DOCTYPE html>
<html>
<head><title>Scan Results</title></head>
<body>
    <h1>Scan Results</h1>
    <h2>Scan ID: {{ scan_id }}</h2>
    <p>Started at: {{ started_at }}</p>
    <p>Completed at: {{ completed_at or 'In progress' }}</p>
    
    <h3>Targets:</h3>
    <ul>
        {% for target in targets %}
        <li>{{ target }}</li>
        {% endfor %}
    </ul>
    
    <h3>Findings:</h3>
    <ul>
        {% for finding in findings %}
        <li>{{ finding }}</li>
        {% endfor %}
    </ul>
    
    <p><a href="/scan/{{ scan_id }}/pdf">Download PDF Report</a></p>
    <p><a href="/">Back to Scan History</a></p>
</body>
</html>""")
import os
import logging
from logging.handlers import RotatingFileHandler

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Database
DB_PATH = os.path.join(DATA_DIR, "vulnscan.db")

# Log files
LOG_DIR = "/var/log"
LOG_FILE = os.path.join(LOG_DIR, "openvulnscan.log")

def setup_logging():
    """Configure application logging"""
    try:
        logger = logging.getLogger("openvulnscan")
        logger.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Try to use /var/log directory, fall back to app data dir if permission denied
        try:
            if not os.path.exists(LOG_DIR):
                os.makedirs(LOG_DIR, exist_ok=True)
            file_handler = RotatingFileHandler(
                LOG_FILE,
                maxBytes=10485760,  # 10MB
                backupCount=5
            )
        except PermissionError:
            # Fall back to local logging
            log_file = os.path.join(DATA_DIR, "openvulnscan.log")
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10485760,  # 10MB
                backupCount=5
            )
            print(f"Warning: Could not write to {LOG_FILE}, using {log_file} instead")
        
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Also log to console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger
    except Exception as e:
        print(f"Error setting up logging: {e}")
        return None

def initialize_directories():
    """Create necessary directories and files for the application"""
    # Create directories
    for directory in [DATA_DIR, TEMPLATES_DIR, STATIC_DIR]:
        os.makedirs(directory, exist_ok=True)
    
    # Create basic HTML template if not exists
    INDEX_HTML = os.path.join(TEMPLATES_DIR, "index.html")
    if not os.path.exists(INDEX_HTML):
        with open(INDEX_HTML, "w", encoding='utf-8') as f:
            # HTML content here...
            pass
    
    # Create scan result template if not exists
    SCAN_RESULT_HTML = os.path.join(TEMPLATES_DIR, "scan_result.html")
    if not os.path.exists(SCAN_RESULT_HTML):
        with open(SCAN_RESULT_HTML, "w", encoding='utf-8') as f:
            # HTML content here...
            pass