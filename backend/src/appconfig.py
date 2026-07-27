"""
Central runtime configuration for the NIDS backend.

This module resolves *writable, per-machine* paths for the database,
trained model files, and secrets. It intentionally does NOT assume the
backend is running from a source checkout - on a fresh install the
source tree may live under Program Files (read-only) while the actual
data must live somewhere the running user can write to.

Resolution order for the data directory:
  1. NIDS_DATA_DIR environment variable (set by the installer / .env)
  2. <platform user-data dir>/NIDS  (Windows: %APPDATA%\\NIDS,
     macOS: ~/Library/Application Support/NIDS,
     Linux: ~/.local/share/NIDS)

Everything the app writes at runtime - the SQLite DB, trained model
artifacts, logs - lives under this directory so re-installing or
upgrading the app never touches user data, and a packaged (non-dev)
build never needs write access to its own install folder.
"""

import os
import sys
import secrets
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


def _default_user_data_dir(app_name: str = "NIDS") -> Path:
    """Return the OS-appropriate per-user application data directory."""
    if sys.platform.startswith("win"):
        base = os.getenv("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / app_name
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / app_name
    else:
        base = os.getenv("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        return Path(base) / app_name


DATA_DIR = Path(os.getenv("NIDS_DATA_DIR", "")) if os.getenv("NIDS_DATA_DIR") else _default_user_data_dir()
DATA_DIR.mkdir(parents=True, exist_ok=True)

MODEL_DIR = DATA_DIR / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# --- Databases -------------------------------------------------------------
# alerts.db keeps the existing alert-management schema.
# app.db holds users, rules, and everything added for auth/tiers/signatures.
ALERTS_DB_PATH = str(DATA_DIR / "alerts.db")
APP_DB_PATH = str(DATA_DIR / "app.db")
APP_DB_URI = f"sqlite:///{APP_DB_PATH}"

# --- Model artifacts ---------------------------------------------------------
MODEL_PATH = str(MODEL_DIR / "random_forest.joblib")
PREPROCESSOR_PREFIX = str(MODEL_DIR / "preprocessor")  # loader appends _scaler/_encoder/_columns.joblib
METRICS_PATH = str(MODEL_DIR / "evaluation_metrics.json")
MODEL_MANIFEST_PATH = str(MODEL_DIR / "manifest.json")

# --- Secrets -----------------------------------------------------------------
def _get_or_create_secret(env_var: str, filename: str) -> str:
    """
    Return a persistent secret. Prefer the environment variable; otherwise
    read/create a secret file under DATA_DIR so the value survives restarts
    without ever being committed to source control.
    """
    value = os.getenv(env_var)
    if value:
        return value

    secret_file = DATA_DIR / filename
    if secret_file.exists():
        return secret_file.read_text().strip()

    generated = secrets.token_hex(32)
    secret_file.write_text(generated)
    return generated


SECRET_KEY = _get_or_create_secret("SECRET_KEY", ".secret_key")
JWT_SECRET = _get_or_create_secret("JWT_SECRET", ".jwt_secret")

# --- Google OAuth --------------------------------------------------------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")

# --- Tier feature gates ----------------------------------------------------
TIER_LIMITS = {
    "free": {
        "alert_history_days": 7,
        "custom_rules": False,
        "export_data": False,
        "api_access": False,
        "max_users": 1,
        "explainability": "basic",
    },
    "pro": {
        "alert_history_days": 30,
        "custom_rules": False,
        "export_data": True,
        "api_access": True,
        "max_users": 5,
        "explainability": "full",
    },
    "enterprise": {
        "alert_history_days": 365,
        "custom_rules": True,
        "export_data": True,
        "api_access": True,
        "max_users": 100,
        "explainability": "full",
    },
}

JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))
