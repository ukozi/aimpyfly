import logging
from colorama import Fore, Style, init
from datetime import datetime


init(autoreset=True)


class CustomFormatter(logging.Formatter):
    # Define log colors for each log level
    LOG_COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.MAGENTA,
    }

    def format(self, record):
        
        utc_timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        log_color = self.LOG_COLORS.get(record.levelno, Fore.WHITE)
        levelname = f"{log_color}[{record.levelname}]{Style.RESET_ALL}"
        log_message = f"{utc_timestamp} {levelname}: {record.getMessage()}"

        return log_message
        
def get_custom_logger(name="AIMClient", level=logging.WARNING):

    logger = logging.getLogger(name)
    logger.setLevel(level)
    handler = logging.StreamHandler()
    formatter = CustomFormatter()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger