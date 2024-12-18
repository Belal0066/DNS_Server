# logformat.py

import datetime
import threading
import queue
import sys
from threading import Thread

# ANSI escape sequences for coloring
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'

class ThreadSafeLogger:
    def __init__(self):
        self.log_queue = queue.Queue()
        self.log_lock = threading.Lock()
        self.running = True
        # Start logger thread
        self.logger_thread = Thread(target=self._logger_worker, daemon=True)
        self.logger_thread.start()

    def _logger_worker(self):
        while self.running:
            try:
                message, color = self.log_queue.get(timeout=1)
                with self.log_lock:
                    sys.stdout.write(f"{color}{message}{RESET}\n")
                    sys.stdout.flush()
                self.log_queue.task_done()
            except queue.Empty:
                continue

    def log(self, message, color=RESET):
        self.log_queue.put((message, color))

    def stop(self):
        self.running = False
        self.logger_thread.join()

# Create global logger instance
logger = ThreadSafeLogger()

def tt():
    return datetime.datetime.now().strftime("@%Y-%m-%d %H:%M:%S.") + str(datetime.datetime.now().microsecond).zfill(6)


def success_message(message):
    logger.log(message, color=GREEN)

def error_message(message):
    logger.log(message, color=RED)

def info_message_timed(message):
    logger.log(f"\n{tt()} {message}", color=YELLOW)

def info_message(message):
    logger.log(message, color=YELLOW)

def warning_message(message):
    logger.log(message, color=MAGENTA)

def debug_message(message):
    logger.log(message, color=CYAN)

def dns_query_message(client_addr, message_content):
    """Prints a formatted DNS query message with clear separation"""
    separator = "-" * 50
    formatted_message = f"\n{BLUE}DNS Query from {client_addr} {RESET}\n{separator}{message_content}\n{separator}\n"
    logger.log(formatted_message, color=RESET)
