import logging
import logging.handlers
import socket
from sqlalchemy.orm import Session
from models.siem_config import SIEMConfig

def send_syslog_message(message: str, db: Session):
    config = db.query(SIEMConfig).first()
    if not config or not config.enabled:
        print("Syslog not enabled or config missing.")
        return

    sock_type = socket.SOCK_DGRAM if config.protocol.lower() == "udp" else socket.SOCK_STREAM

    try:
        handler = logging.handlers.SysLogHandler(address=(config.host, config.port), socktype=sock_type)
        logger = logging.getLogger("siem_logger")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.propagate = False

        # Send the raw message (can be JSON string)
        logger.info(message)
        logger.removeHandler(handler)
        handler.close()
        print(f"Syslog message sent to {config.host}:{config.port} ({config.protocol})")
    except Exception as e:
        print(f"Failed to send syslog message: {e}")
