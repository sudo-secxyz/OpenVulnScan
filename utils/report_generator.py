from fpdf import FPDF
import os
from database.db_manager import get_scan
from config import DATA_DIR

def generate_scan_report(scan_id: str) -> str:
    """Generate a PDF report for a scan"""
    scan_data = get_scan(scan_id)
    if not scan_data:
        return None
    
    targets = scan_data["targets"]
    findings = scan_data["findings"]
    started_at = scan_data["started_at"]
    completed_at = scan_data["completed_at"] or "In progress"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Scan Report: {scan_id}", ln=True, align='C')
    pdf.ln(10)
    pdf.cell(200, 10, txt=f"Targets: {', '.join(targets)}", ln=True)
    pdf.cell(200, 10, txt=f"Started at: {started_at}", ln=True)
    pdf.cell(200, 10, txt=f"Completed at: {completed_at}", ln=True)
    pdf.ln(10)
    pdf.cell(200, 10, txt="Findings:", ln=True)
    for finding in findings:
        pdf.cell(200, 10, txt=f"- {finding}", ln=True)

    filename = os.path.join(DATA_DIR, f"scan_{scan_id}.pdf")
    pdf.output(filename)
    return filename