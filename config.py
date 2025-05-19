import os
import logging
from logging.handlers import RotatingFileHandler

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# ZAP scan results directory
ZAP_RESULTS_DIR = os.getenv("ZAP_RESULTS_DIR", os.path.join(DATA_DIR, "zap_results"))

# Database
DB_PATH = os.path.join(DATA_DIR, "vulnscan.db")

# Log files
DEFAULT_LOG_DIR = "/var/log"
FALLBACK_LOG_FILE = os.path.join(DATA_DIR, "openvulnscan.log")
LOG_FILE = os.path.join(DEFAULT_LOG_DIR, "openvulnscan.log")

def setup_logging():
    """Configure application logging"""
    logger = logging.getLogger("openvulnscan")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    try:
        os.makedirs(DEFAULT_LOG_DIR, exist_ok=True)
        file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
    except PermissionError:
        file_handler = RotatingFileHandler(FALLBACK_LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
        print(f"Warning: Could not write to {LOG_FILE}, using fallback at {FALLBACK_LOG_FILE}")

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger

def initialize_directories():
    """Create necessary directories and default templates"""
    for directory in [DATA_DIR, TEMPLATES_DIR, STATIC_DIR, ZAP_RESULTS_DIR]:
        os.makedirs(directory, exist_ok=True)

    # index.html
    index_path = os.path.join(TEMPLATES_DIR, "index.html")
    if not os.path.exists(index_path):
        with open(index_path, "w", encoding='utf-8') as f:
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

    # scan_result.html
    result_path = os.path.join(TEMPLATES_DIR, "scan_result.html")
    if not os.path.exists(result_path):
        with open(result_path, "w", encoding='utf-8') as f:
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
