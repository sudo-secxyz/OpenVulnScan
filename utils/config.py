# utils/config.py
import os

CVE_API_URL = os.getenv("CVE_API_URL", "https://api.osv.dev/v1/query")
SECRET_KEY = "#youshouldchangethis"