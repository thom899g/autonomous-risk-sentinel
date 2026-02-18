import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logging():
    """
    Configures the logging system with file rotation and formatting.
    Implements error handling for logging configuration issues.
    """
    try:
        log_dir = os.path.join(os.path.dirname(__file__), "logs")
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        handler = RotatingFileHandler(
            filename=os.path.join(log_dir, 'threat_intelligence.log'),
            maxBytes=1024*1024,
            backupCount=5
        )
        handler.setFormatter(formatter)

        logger = logging.getLogger("ThreatIntelligence")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        return logger

    except Exception as e:
        print(f"Failed to configure logging: {str(e)}")
        return None

def main():
    import time
    logger = setup_logging()
    if not logger:
        return
        
    logger.info("Threat Intelligence system initialized")
    while True:
        try:
            # Example log entry
            logger.info("Processing threat data...")
            time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down threat intelligence service")