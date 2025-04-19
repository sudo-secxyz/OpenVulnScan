from fastapi import FastAPI, BackgroundTasks, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from models.schemas import ScanRequest, ScanResult
from services.scan_service import start_scan_task, get_scan_details
from utils.report_generator import generate_scan_report
from database.db_manager import get_all_scans
from config import TEMPLATES_DIR, STATIC_DIR, initialize_directories, setup_logging

# Initialize logger
logger = setup_logging()

app = FastAPI(title="OpenVulnScan", version="0.1.0")

# Initialize directories and setup
initialize_directories()

# Templating and static file configuration
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    """Get the main page with scan history"""
    logger.info("Accessing main page")
    scans = get_all_scans()
    return templates.TemplateResponse("index.html", {"request": request, "scans": scans})

@app.post("/scan", response_model=ScanResult)
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new vulnerability scan"""
    logger.info(f"Starting new scan for targets: {req.targets}")
    result = start_scan_task(req, background_tasks) 
    logger.info(f"Scan initiated with ID: {result.id}")
    return result

@app.get("/scan/{scan_id}", response_class=HTMLResponse)
def get_scan(scan_id: str, request: Request):
    """Get details for a specific scan"""
    logger.info(f"Viewing scan results for scan ID: {scan_id}")
    scan_data = get_scan_details(scan_id)
    if not scan_data:
        logger.warning(f"Scan ID {scan_id} not found")
        return HTMLResponse(f"<h1>Scan ID {scan_id} not found</h1>", status_code=404)
    
    # Explicitly add scan_id to ensure it's available in the template
    return templates.TemplateResponse("scan_result.html", {
        "request": request,
        "scan_id": scan_id,
        **scan_data
    })