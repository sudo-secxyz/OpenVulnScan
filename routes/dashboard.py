from sqlalchemy.orm import Session
from sqlalchemy import text
from database.db_manager import get_db
from fastapi.responses import HTMLResponse
from jinja2 import Template
from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from database.db_manager import SessionLocal
from auth.dependencies import  get_current_user, BasicUser
from models.scheduled_scan import ScheduledScan
from models.scan import Scan
from models.finding import Finding
from models.cve import CVE
from models.asset import Asset  
from datetime import datetime
from sqlalchemy.orm import joinedload
import json
import logging

from fastapi.responses import FileResponse
from fastapi.templating import Jinja2Templates


router = APIRouter()
templates = Jinja2Templates(directory="templates")

logger = logging.getLogger(__name__)

@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db), user: BasicUser = Depends(get_current_user)):
    # Example: Fetch summary data
    report_count = db.execute(text("SELECT COUNT(*) FROM agent_reports")).scalar()
    package_count = db.execute(text("SELECT COUNT(*) FROM packages")).scalar()
    cve_count = db.execute(text("SELECT COUNT(*) FROM cves")).scalar()

    # Example: Fetch top vulnerable packages
    top_packages_query = text("""
        SELECT packages.name, COUNT(cves.id) AS cve_count
        FROM packages
        JOIN cves ON cves.package_id = packages.id
        GROUP BY packages.name
        ORDER BY cve_count DESC
        LIMIT 5
    """)
    top_packages = db.execute(top_packages_query).fetchall()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "report_count": report_count,
        "package_count": package_count,
        "cve_count": cve_count,
        "top_packages": top_packages,
        "current_user": user
    })

@router.get("/dashboard/report", response_class=FileResponse)
def generate_dashboard_report(db: Session = Depends(get_db)):
    # Fetch data for the report
    report_data = db.execute(text("SELECT * FROM agent_reports")).fetchall()

    # Generate a CSV file
    import csv
    report_file = "dashboard_report.csv"
    with open(report_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["ID", "Hostname", "Reported At", "OS Info"])
        for row in report_data:
            writer.writerow(row)

    return FileResponse(report_file, filename="dashboard_report.csv", media_type="text/csv")

@router.get("/dashboard/filtered", response_class=HTMLResponse)
def filtered_dashboard(request: Request, db: Session = Depends(get_db), hostname: str = None, user: BasicUser = Depends(get_current_user)):
    query = "SELECT * FROM agent_reports"
    if hostname:
        query += f" WHERE hostname = :hostname"
    reports = db.execute(text(query), {"hostname": hostname}).fetchall()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "reports": reports,
        "hostname": hostname,
        "current_user": user
    })

@router.get("/dashboard/query", response_class=HTMLResponse)
def query_dashboard(
    request: Request,
    table: str,
    query: str = None,
    db: Session = Depends(get_db),
    user: BasicUser = Depends(get_current_user)
):
    allowed_tables = ["agent_reports", "packages", "cves", "findings", "scans"]
    if table not in allowed_tables:
        logger.error(f"Invalid table name: {table}")
        return HTMLResponse("<h1>Invalid table name</h1>", status_code=400)

    # Fetch column names for the selected table
    try:
        columns_query = text(f"PRAGMA table_info({table})")
        columns_info = db.execute(columns_query).fetchall()
        valid_columns = [col[1] for col in columns_info]  # Extract column names from the second element of each tuple
        logger.debug(f"Valid columns for table {table}: {valid_columns}")
    except Exception as e:
        logger.error(f"Error fetching columns for table {table}: {str(e)}")
        return HTMLResponse(f"<h1>Error fetching columns for table {table}</h1>", status_code=400)

    sql_query = f"SELECT * FROM {table}"
    parameters = {}

    if query:
        try:
            # Split the query into key-value pairs
            if "=" not in query:
                raise ValueError("Query must be in the format 'key=value'.")

            key, value = query.split("=", 1)

            # Validate the column name
            if key not in valid_columns:
                logger.error(f"Invalid column name: {key}")
                return HTMLResponse(
                    f"<h1>Invalid column name: {key}. Valid columns are: {', '.join(valid_columns)}</h1>",
                    status_code=400
                )

            # Handle JSON array columns (e.g., "targets")
            if key == "targets":
                sql_query += f" WHERE JSON_EXTRACT({key}, '$') LIKE :value"
                parameters["value"] = f'%"{value}"%'  # Match the value within the JSON array
            elif value == "*":
                sql_query += f" WHERE {key} IS NOT NULL"
            else:
                sql_query += f" WHERE {key} = :value"
                parameters["value"] = value
        except ValueError as e:
            logger.error(f"Invalid query format: {query} - {str(e)}")
            return HTMLResponse(f"<h1>Invalid query format. Use 'key=value'.</h1>", status_code=400)

    try:
        logger.debug(f"Executing query: {sql_query} with parameters: {parameters}")
        results = db.execute(text(sql_query), parameters).fetchall()
        columns = valid_columns
    except Exception as e:
        logger.error(f"Error executing query: {sql_query} - {str(e)}")
        return HTMLResponse(f"<h1>Error executing query: {str(e)}</h1>", status_code=400)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "results": results,
        "columns": columns,
        "current_user": user
    })