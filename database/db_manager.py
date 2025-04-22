# database/db_manager.py
import sqlite3
import json
import datetime
from config import DB_PATH

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# You can adjust your DB URL here
SQLALCHEMY_DATABASE_URL = "sqlite:///./openvulnscan.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        

def get_db_connection():
    """Get a database connection"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_agent_reports_table():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agent_reports (
        id TEXT PRIMARY KEY,
        hostname TEXT,
        os TEXT,
        packages TEXT,
        reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

initialize_agent_reports_table()

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
    """Get all scans ordered by start date as a list of dictionaries"""
    conn = get_db_connection()
    cur = conn.cursor()

    # Modify the SQL query to select the 'targets' column as well
    cur.execute('SELECT id, targets, started_at, completed_at FROM scans ORDER BY started_at DESC')
    
    scans = cur.fetchall()
    conn.close()

    # Convert list of tuples into list of dictionaries
    scans_dict = []
    for scan in scans:
        try:
            # Convert the row into a dictionary, ensuring that 'targets' is parsed as JSON
            scans_dict.append({
                "scan_id": scan["id"],
                "scan_targets": json.loads(scan["targets"]),  # Deserialize the 'targets' JSON
                "started_at": scan["started_at"],
                "completed_at": scan["completed_at"]
            })
        except Exception as e:
            print(f"Error processing scan {scan['id']}: {e}")
    
    return scans_dict
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

def save_agent_report(hostname, packages):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS agent_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            packages TEXT,
            reported_at TEXT
        )
    ''')
    cur.execute('''
        INSERT INTO agent_reports (hostname, packages, reported_at)
        VALUES (?, ?, ?)
    ''', (hostname, json.dumps(packages), datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


# Initialize database on import
init_db()