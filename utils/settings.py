from fastapi import APIRouter, Request, Depends, Form, Body
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from starlette.status import HTTP_303_SEE_OTHER
from fastapi.templating import Jinja2Templates
import httpx
import os
from auth.dependencies import require_authentication
from fastapi import Depends


router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Default CVE API URL (can be modified in settings)
CVE_API_URL = os.getenv("CVE_API_URL", "https://api.osv.dev/v1/query")

@router.get("/settings", response_class=HTMLResponse, dependencies=[Depends(require_authentication)], tags=["Configuration"])
def settings_page(request: Request):
    """Display settings page."""
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "cve_api_url": CVE_API_URL
    })

@router.post("/settings/update", dependencies=[Depends(require_authentication)], tags=["Configuration"])
def update_settings(request: Request, cve_api_url: str = Form(...)):
    """Update CVE API URL setting."""
    global CVE_API_URL
    CVE_API_URL = cve_api_url
    return RedirectResponse(url="/settings", status_code=HTTP_303_SEE_OTHER)

@router.post("/cve/check", response_class=JSONResponse, dependencies=[Depends(require_authentication)], tags=["agent"])
async def check_package_cves(
    payload: dict = Body(...)
):
    """
    Dynamically query the CVE database for a given package name, version, and ecosystem.
    Expected payload format:
    {
        "name": "openssl",
        "version": "1.1.1",
        "ecosystem": "Debian"
    }
    """
    try:
        query = {
            "package": {
                "name": payload["name"],
                "ecosystem": payload.get("ecosystem", "Debian")  # Default to Debian
            },
            "version": payload["version"]
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(CVE_API_URL, json=query)
            response.raise_for_status()
            data = response.json()
            return {
                "status": "success",
                "query": query,
                "vulnerabilities": data.get("vulns", [])
            }

    except Exception as e:
        return {"status": "error", "message": str(e)}
    


    