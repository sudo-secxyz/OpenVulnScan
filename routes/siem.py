from fastapi import Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from auth.dependencies import get_current_user, BasicUser
from database.db_manager import get_db
from models.siem_config import SIEMConfig
from utils.syslog import send_syslog_message

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/siem/config/ui", response_class=HTMLResponse)
def siem_config_form(request: Request, user: BasicUser = Depends(get_current_user)):
    return templates.TemplateResponse("siem_config.html", {"request": request, "current_user": user})


@router.post("/siem/config", response_class=HTMLResponse)
def post_siem_config(
    request: Request,
    enabled: bool = Form(False),
    host: str = Form(...),
    port: int = Form(...),
    protocol: str = Form(...),
    db: Session = Depends(get_db),
      # Placeholder for user dependency
):
    config = db.query(SIEMConfig).first()
    if not config:
        config = SIEMConfig(enabled=enabled, host=host, port=port, protocol=protocol)
        db.add(config)
    else:
        config.enabled = enabled
        config.host = host
        config.port = port
        config.protocol = protocol

    db.commit()
    return RedirectResponse("/siem/config/ui", status_code=303)
