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

    targets_list = scan.targets or []
    started_at = scan.started_at.isoformat() if scan.started_at else "Unknown"
    completed_at = scan.completed_at.isoformat() if scan.completed_at else "In progress"

    pdf = FPDF()
    pdf.add_page()
    try:
        pdf.set_font("Arial", size=12)
    except RuntimeError:
        pdf.set_font("Helvetica", size=12)  # fallback font

    pdf.set_title(f"Scan Report: {scan.id}")
    pdf.set_author("OpenVulnScan")

    pdf.cell(200, 10, txt=f"Scan Report: {scan.id}", ln=True, align='C')
    pdf.ln(10)
    pdf.cell(200, 10, txt=f"Targets: {', '.join(targets_list)}", ln=True)
    pdf.cell(200, 10, txt=f"Started at: {started_at}", ln=True)
    pdf.cell(200, 10, txt=f"Completed at: {completed_at}", ln=True)
    pdf.ln(10)
    pdf.cell(200, 10, txt="Findings:", ln=True)

    if scan.findings:
        print(f"Generating report for scan {scan.id}")
        print(f"Found {len(scan.findings)} findings")
        for finding in scan.findings:
            desc = finding.description or 'No description'
            severity = finding.severity or 'N/A'
            cve_ids = ', '.join([cve.cve_id for cve in finding.cves]) if finding.cves else 'N/A'
            summary = f"- {desc} | Severity: {severity} | CVEs: {cve_ids}"
            pdf.multi_cell(0, 10, txt=summary)
            print(f"Finding: {finding.description}, CVEs: {[c.cve_id for c in finding.cves]}")

    else:
        pdf.cell(200, 10, txt="- No findings recorded.", ln=True)

    filename = os.path.join(DATA_DIR, f"scan_{scan.id}.pdf")

    if os.path.exists(filename):
        os.remove(filename)

    pdf.output(filename)
    return filename