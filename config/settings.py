import os

# Project directories
DATA_DIR = "data"
REPORT_DIR = "reports"
LOG_DIR = "logs"

# Ensure runtime output directories exist after a fresh clone.
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Collector settings
COLLECTOR_TIMEOUT = 60

# Report settings
REPORT_EXTENSION = ".md"

# Application settings
APP_NAME = "AI-Assisted OSINT Report Generator"
