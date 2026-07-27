"""
Model bootstrap for a fresh install.

The trained model/preprocessor files are intentionally excluded from git
(they're large binaries, see .gitignore). This module is the single place
that knows how to find them at runtime:

  1. Look in appconfig.MODEL_DIR (the per-user data directory the
     installer copies/downloads the model into).
  2. If missing, raise a clear, actionable error rather than crashing the
     whole Flask app - routes that need the model report 503 with
     instructions instead of the server failing to boot at all.

See INSTALL.md / installer/setup_wizard.py for how the model actually
gets there on a new machine.
"""

import os
import json
import hashlib
import logging
import shutil

from appconfig import MODEL_PATH, PREPROCESSOR_PREFIX, MODEL_MANIFEST_PATH, MODEL_DIR
from .inference import InferenceEngine

logger = logging.getLogger(__name__)

_engine_instance = None

# Convenience for running from a source checkout: if the trained model
# ships alongside the code (as it does in this repo's
# ml_pipeline/models/ folder), use it automatically instead of requiring
# the installer wizard step first. A packaged/installed build won't have
# this folder (it's excluded from the Electron bundle - see
# electron-builder.yml), so this only ever applies to local/dev runs.
_DEV_MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")


class ModelNotFoundError(Exception):
    pass


def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _dev_model_files_present() -> bool:
    required = [
        "random_forest.joblib",
        "preprocessor_scaler.joblib",
        "preprocessor_encoder.joblib",
        "preprocessor_columns.joblib",
    ]
    return all(os.path.isfile(os.path.join(_DEV_MODEL_DIR, f)) for f in required)


def _copy_dev_model_into_data_dir() -> None:
    logger.info(f"Found model files in source tree ({_DEV_MODEL_DIR}) - copying into {MODEL_DIR} for local dev use")
    for filename in os.listdir(_DEV_MODEL_DIR):
        if filename in ("__init__.py",) or filename.startswith("__pycache__"):
            continue
        src = os.path.join(_DEV_MODEL_DIR, filename)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(MODEL_DIR, filename))


def model_files_present() -> bool:
    required = [
        MODEL_PATH,
        f"{PREPROCESSOR_PREFIX}_scaler.joblib",
        f"{PREPROCESSOR_PREFIX}_encoder.joblib",
        f"{PREPROCESSOR_PREFIX}_columns.joblib",
    ]
    return all(os.path.isfile(p) for p in required)


def write_manifest():
    """Write a small manifest recording what's installed, for support/debugging."""
    manifest = {
        "model_path": MODEL_PATH,
        "model_sha256": _sha256_of(MODEL_PATH) if os.path.isfile(MODEL_PATH) else None,
    }
    with open(MODEL_MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def get_inference_engine(threshold: float = 0.5) -> InferenceEngine:
    """
    Get (and lazily initialize) the process-wide InferenceEngine.
    Raises ModelNotFoundError if the model artifacts aren't installed yet -
    callers (routes) should catch this and return a 503 with setup
    instructions rather than letting it bubble into a 500.
    """
    global _engine_instance

    if _engine_instance is not None and _engine_instance.is_loaded:
        return _engine_instance

    if not model_files_present():
        if _dev_model_files_present():
            _copy_dev_model_into_data_dir()
        else:
            raise ModelNotFoundError(
                "No trained model found. Run the installer's model setup step "
                "(installer/setup_wizard.py --install-model <path-or-url>) or place "
                f"the model files manually in: {os.path.dirname(MODEL_PATH)}"
            )

    engine = InferenceEngine(threshold=threshold)
    engine.load_model(MODEL_PATH, PREPROCESSOR_PREFIX)

    if os.path.isfile(METRICS_PATH):
        try:
            with open(METRICS_PATH) as f:
                metrics = json.load(f)
            # Accept whatever key your training script used, in order of preference.
            engine.accuracy = (
                metrics.get("test_accuracy")
                or metrics.get("accuracy")
                or metrics.get("val_accuracy")
            )
        except Exception:
            logger.exception("Could not read evaluation_metrics.json, leaving accuracy unset")

    _engine_instance = engine
    logger.info("Inference engine loaded and ready")
    return engine


def reset_engine():
    """Used by tests / after an admin re-installs a model at runtime."""
    global _engine_instance
    _engine_instance = None
