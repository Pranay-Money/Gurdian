"""
ML Pipeline Logger
"""
import logging
import os
from datetime import datetime

LOG_FILE = f"{datetime.now().strftime('%m_%d_%Y_%H_%M_%S')}.log"

logs_path = os.path.join(os.getcwd(), "ml", "logs")
os.makedirs(logs_path, exist_ok=True)

LOG_FILE_PATH = os.path.join(logs_path, LOG_FILE)

logging.basicConfig(
    filename=LOG_FILE_PATH,
    format="[ %(asctime)s ] %(lineno)d %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# Also log to console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(
    logging.Formatter("[ %(asctime)s ] %(levelname)s - %(message)s")
)
logging.getLogger().addHandler(console_handler)

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logger.info("ML Pipeline logging started.")