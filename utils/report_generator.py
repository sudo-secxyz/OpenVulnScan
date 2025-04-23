# utils/report_generator.py
from fpdf import FPDF
import os
from sqlalchemy.orm import Session
from models.scan import Scan
from database.db_manager import SessionLocal
from config import DATA_DIR

def generate_scan_report(scan_id: str) -> str:
    """Generate a PDF report for a scan"""
    # Create a session
    db = SessionLocal()
    try:
        # Get scan data using SQLAlchemy
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        
        if not scan:
            return None
        
        targets = scan.targets
        findings = scan.findings
        started_at = scan.started_at.isoformat() if scan.started_at else "Unknown"
        completed_at = scan.completed_at.isoformat() if scan.completed_at else "In progress"
        
        # Generate PDF
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
    finally:
        db.close()