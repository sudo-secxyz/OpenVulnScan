from fpdf import FPDF
import os
import json
from sqlalchemy.orm import Session
from models.scan import Scan
from database.db_manager import SessionLocal
from config import DATA_DIR

def safe_parse_targets(targets):
    try:
        parsed = json.loads(targets)
        return parsed if isinstance(parsed, list) else [parsed]
    except Exception:
        return [targets]

def generate_scan_report(scan_id: str) -> str:
    """Generate a PDF report for a scan"""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None

        targets_list = safe_parse_targets(scan.targets)
        started_at = scan.started_at.isoformat() if scan.started_at else "Unknown"
        completed_at = scan.completed_at.isoformat() if scan.completed_at else "In progress"

        try:
            findings_data = json.loads(scan.findings)
        except (TypeError, json.JSONDecodeError):
            findings_data = []

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Scan Report: {scan_id}", ln=True, align='C')
        pdf.ln(10)
        pdf.cell(200, 10, txt=f"Targets: {', '.join(targets_list)}", ln=True)
        pdf.cell(200, 10, txt=f"Started at: {started_at}", ln=True)
        pdf.cell(200, 10, txt=f"Completed at: {completed_at}", ln=True)
        pdf.ln(10)
        pdf.cell(200, 10, txt="Findings:", ln=True)
        
        if findings_data:
            for finding in findings_data:
                desc = finding.get('description', 'No description')
                severity = finding.get('severity', 'N/A')
                cve = finding.get('cve_id', 'N/A')
                summary = f"- {desc} | Severity: {severity} | CVE: {cve}"
                pdf.cell(200, 10, txt=summary, ln=True)
        else:
            pdf.cell(200, 10, txt="- No findings recorded.", ln=True)

        filename = os.path.join(DATA_DIR, f"scan_{scan_id}.pdf")
        pdf.output(filename)
        return filename
    finally:
        db.close()
