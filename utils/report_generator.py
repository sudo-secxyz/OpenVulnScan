# utils/report_generator.py
from fpdf import FPDF
import os
import json
from typing import Optional
from sqlalchemy.orm import Session
from models.scan import Scan
from database.db_manager import SessionLocal
from config import DATA_DIR

def safe_parse_targets(targets):
    try:
        parsed = json.loads(targets)
        # Flatten the list if necessary
        if isinstance(parsed, list):
            return [str(item) for sublist in parsed for item in (sublist if isinstance(sublist, list) else [sublist])]
        return [str(parsed)]
    except Exception:
        return [str(targets)]  # Ensure that any target is a string

def generate_scan_report(scan: Scan) -> Optional[str]:
    """Generate a PDF report for a scan"""
    if not scan:
        return None

    pdf = FPDF()
    pdf.add_page()
    try:
        pdf.set_font("Arial", size=12)
    except RuntimeError:
        pdf.set_font("Helvetica", size=12)  # fallback font

    pdf.set_title(f"Scan Report: {scan.id}")
    pdf.set_author("OpenVulnScan")

    pdf.cell(200, 10, txt=f"Scan Report for {', '.join(scan.targets or [])}", ln=True, align='C')
    pdf.ln(10)

    pdf.cell(200, 10, txt=f"Status: {scan.status}", ln=True)
    pdf.cell(200, 10, txt=f"Started At: {scan.started_at.isoformat() if scan.started_at else 'Unknown'}", ln=True)
    pdf.cell(200, 10, txt=f"Completed At: {scan.completed_at.isoformat() if scan.completed_at else 'In Progress'}", ln=True)
    pdf.ln(10)

    # Parse raw_data
    raw_data = scan.raw_data or []
    for finding in raw_data:
        pdf.cell(200, 10, txt=f"IP Address: {finding.get('ip', 'N/A')}", ln=True)
        pdf.cell(200, 10, txt=f"Hostname: {finding.get('hostname', 'N/A')}", ln=True)

        pdf.cell(200, 10, txt="Open Ports:", ln=True)
        for port in finding.get("open_ports", []):
            pdf.cell(200, 10, txt=f"  - {port['port']}/{port['protocol']} ({port['service']})", ln=True)

        pdf.cell(200, 10, txt="Vulnerabilities:", ln=True)
        for vuln in finding.get("vulnerabilities", []):
            pdf.cell(200, 10, txt=f"  - {vuln['id']}: {vuln['description']}", ln=True)

        pdf.ln(10)

    filename = os.path.join(DATA_DIR, f"scan_{scan.id}_report.pdf")
    pdf.output(filename)
    return filename