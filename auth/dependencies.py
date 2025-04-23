# OpenVulnScan/auth/dependencies.py

from fastapi import Request
from starlette.responses import RedirectResponse

def require_authentication(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return user