# database/db_manager.py
import sqlite3
import json
import datetime
from config import DB_PATH

def get_db_connection():
    """Get a database connection"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with required tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        targets TEXT,
        findings TEXT,
        started_at TEXT,
        completed_at TEXT
    )''')
    conn.commit()
    conn.close()

def insert_scan(scan_id, targets, started_at):
    """Insert a new scan record into the database"""
    conn = get_db_connection()
    conn.execute(
        '''INSERT INTO scans (id, targets, findings, started_at, completed_at) VALUES (?, ?, ?, ?, ?)''',
        (scan_id, json.dumps(targets), json.dumps([]), started_at.isoformat(), None)
    )
    conn.commit()
    conn.close()

def update_scan_findings(scan_id, findings):
    """Update the findings for a scan and mark it complete"""
    conn = get_db_connection()
    conn.execute(
        "UPDATE scans SET findings = ?, completed_at = ? WHERE id = ?",
        (json.dumps(findings), datetime.datetime.utcnow().isoformat(), scan_id)
    )
    conn.commit()
    conn.close()

def get_scan(scan_id):
    """Get details for a single scan"""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = cur.fetchone()
    conn.close()
    
    if not scan:
        return None
    
    # Make sure we properly deserialize the JSON fields
    try:
        targets = json.loads(scan["targets"])
    except:
        targets = []
        
    try:
        findings = json.loads(scan["findings"]) 
    except:
        findings = []
    
    return {
        "scan_id": scan["id"],  # Use scan_id to match template
        "targets": targets,
        "findings": findings,
        "started_at": scan["started_at"],
        "completed_at": scan["completed_at"]
    }

def get_all_scans():
    """Get all scans ordered by start date"""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, started_at, completed_at FROM scans ORDER BY started_at DESC')
    scans = cur.fetchall()
    conn.close()
    return scans
def debug_scan_findings(scan_id):
    """Debug function to print scan findings"""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT findings FROM scans WHERE id = ?", (scan_id,))
    findings = cur.fetchone()
    conn.close()
    if findings:
        print(f"DEBUG findings from DB: {findings['findings']}")
        return json.loads(findings['findings'])
    return None

# Initialize database on import
init_db()