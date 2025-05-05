from tzlocal import get_localzone_name

def get_system_timezone() -> str:
    try:
        return get_localzone_name()  # e.g., 'America/Phoenix'
    except Exception as e:
        print(f"Failed to get system timezone: {e}")
        return "UTC"
