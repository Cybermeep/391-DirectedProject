#!/usr/bin/env python3
"""
NIDS install wizard

Usage:
    python setup_wizard.py                       interactive wizard
    python setup_wizard.py --silent               non-interactive, skip prompts
    python setup_wizard.py --model-dir /path/to/model/files
    python setup_wizard.py --model-url https://cdn.example.com/nids-model.zip
    python setup_wizard.py --skip-venv             (useful for re-running just the model step)
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"


def _print_header(title: str) -> None:
    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)


def _venv_python(venv_dir: Path) -> Path:
    if platform.system() == "Windows":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def step_create_venv(backend_dir: Path, force: bool = False) -> Path:
    _print_header("1. Python virtual environment")
    venv_dir = backend_dir / "venv"

    if venv_dir.exists() and not force:
        print(f"Found existing venv at {venv_dir}, skipping creation.")
    else:
        print(f"Creating virtual environment at {venv_dir} ...")
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)

    python_exe = _venv_python(venv_dir)
    print("Installing backend dependencies (this can take a few minutes) ...")
    subprocess.run(
        [str(python_exe), "-m", "pip", "install", "--upgrade", "pip"],
        check=True,
    )
    subprocess.run(
        [str(python_exe), "-m", "pip", "install", "-r", str(backend_dir / "requirements.txt")],
        check=True,
    )
    print("Dependencies installed.")
    _verify_sklearn_version(python_exe)
    return python_exe


REQUIRED_SKLEARN_VERSION = "1.3.0"


def _verify_sklearn_version(python_exe: Path) -> None:
    """
    The bundled trained model was pickled with a specific scikit-learn
    version. Loading it with a *different* version can succeed silently
    (joblib.load just warns) but then fail the first real prediction with
    a cryptic internal AttributeError - verified directly against this
    project's own model file. Catching the mismatch here, right after
    install, is much more useful than discovering it mid-demo.
    """
    result = subprocess.run(
        [str(python_exe), "-c", "import sklearn; print(sklearn.__version__)"],
        capture_output=True, text=True,
    )
    installed = result.stdout.strip()
    if installed and installed != REQUIRED_SKLEARN_VERSION:
        print(
            f"\n  WARNING: scikit-learn {installed} was installed, but the bundled "
            f"trained model was built with scikit-learn=={REQUIRED_SKLEARN_VERSION}.\n"
            f"  Predictions may fail with a confusing internal error at runtime.\n"
            f"  Fix with:\n"
            f"    {python_exe} -m pip install scikit-learn=={REQUIRED_SKLEARN_VERSION}\n"
        )
    else:
        print(f"scikit-learn version OK ({installed}).")


def step_check_npcap(silent: bool) -> None:
    _print_header("2. Packet capture driver (Windows only)")

    if platform.system() != "Windows":
        print("Not on Windows - skipping (Linux/macOS use raw sockets/libpcap directly).")
        return

    npcap_indicators = [
        Path(r"C:\Windows\System32\Npcap"),
        Path(r"C:\Windows\SysWOW64\Npcap"),
    ]
    if any(p.exists() for p in npcap_indicators):
        print("Npcap appears to be installed. Good.")
        return

    print(
        "Npcap was not detected. Scapy needs Npcap to capture live traffic on\n"
        "Windows (this is separate from the Python packages just installed).\n"
        "Download and install it from: https://npcap.com/#download\n"
        "During install, check 'Install Npcap in WinPcap API-compatible Mode'."
    )
    if not silent:
        input("Press Enter once you've installed Npcap (or to skip for now) ...")


def _extract_if_archive(path: Path, dest: Path) -> Path:
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            zf.extractall(dest)
        return dest
    return path.parent


def step_install_model(python_exe: Path, model_dir: str | None, model_url: str | None, silent: bool) -> bool:
    _print_header("3. Trained model files")

    # Ask the venv's own appconfig where MODEL_DIR actually resolves to, so
    # this stays in sync with the backend even if that logic changes.
    result = subprocess.run(
        [str(python_exe), "-c", "import sys; sys.path.insert(0,'src'); import appconfig; print(appconfig.MODEL_DIR)"],
        cwd=str(BACKEND_DIR),
        capture_output=True,
        text=True,
        check=True,
    )
    target_dir = Path(result.stdout.strip())
    target_dir.mkdir(parents=True, exist_ok=True)
    print(f"Model files will be installed to: {target_dir}")

    source_dir: Path | None = None

    if model_url:
        print(f"Downloading model archive from {model_url} ...")
        tmp_path = target_dir / "_download.zip"
        urllib.request.urlretrieve(model_url, tmp_path)
        source_dir = _extract_if_archive(tmp_path, target_dir / "_extracted")
        tmp_path.unlink(missing_ok=True)
    elif model_dir:
        source_dir = Path(model_dir)
    elif not silent:
        answer = input(
            "Path to a local folder containing random_forest.joblib and the "
            "preprocessor_*.joblib files (leave blank to skip for now): "
        ).strip()
        if answer:
            source_dir = Path(answer)

    if not source_dir:
        print(
            "No model source provided. You can run this step again later with:\n"
            f"  python setup_wizard.py --skip-venv --model-dir <path>\n"
            "The app will run but /api/predict will return 503 until a model is installed."
        )
        return False

    required_files = [
        "random_forest.joblib",
        "preprocessor_scaler.joblib",
        "preprocessor_encoder.joblib",
        "preprocessor_columns.joblib",
    ]
    missing = [f for f in required_files if not (source_dir / f).exists()]
    if missing:
        print(f"ERROR: missing expected file(s) in {source_dir}: {', '.join(missing)}")
        return False

    for f in required_files:
        shutil.copy2(source_dir / f, target_dir / f)
    optional = source_dir / "evaluation_metrics.json"
    if optional.exists():
        shutil.copy2(optional, target_dir / "evaluation_metrics.json")

    print("Model files copied successfully.")

    # Write the sha256 manifest via the venv so future support requests can
    # confirm exactly what's installed.
    subprocess.run(
        [
            str(python_exe),
            "-c",
            "import sys; sys.path.insert(0,'src'); from ml_pipeline.model_loader import write_manifest; "
            "print(write_manifest())",
        ],
        cwd=str(BACKEND_DIR),
        check=True,
    )
    return True


def step_init_databases(python_exe: Path) -> None:
    _print_header("4. Databases")
    subprocess.run(
        [
            str(python_exe),
            "-c",
            "import sys; sys.path.insert(0,'src'); "
            "from auth.models import init_auth_database; import rules.models; "
            "from alert_management.models import init_database; "
            "init_auth_database(); init_database(); "
            "print('Databases initialized.')",
        ],
        cwd=str(BACKEND_DIR),
        check=True,
    )


def step_configure_env(silent: bool) -> None:
    _print_header("5. Configuration (.env)")
    env_path = BACKEND_DIR / ".env"
    example_path = BACKEND_DIR / ".env.example"

    if env_path.exists():
        print(f"{env_path} already exists, leaving it as-is.")
        return

    lines = example_path.read_text().splitlines() if example_path.exists() else []

    google_client_id = ""
    if not silent:
        google_client_id = input(
            "Google OAuth Client ID (leave blank to disable Google sign-in for now): "
        ).strip()

    output_lines = []
    for line in lines:
        if line.startswith("GOOGLE_CLIENT_ID=") and google_client_id:
            output_lines.append(f"GOOGLE_CLIENT_ID={google_client_id}")
        else:
            output_lines.append(line)

    env_path.write_text("\n".join(output_lines) + "\n")
    print(f"Wrote {env_path}")


def main():
    parser = argparse.ArgumentParser(description="NIDS install wizard")
    parser.add_argument("--silent", action="store_true", help="Non-interactive mode; skip all prompts")
    parser.add_argument("--skip-venv", action="store_true", help="Skip venv creation/dependency install")
    parser.add_argument("--force-venv", action="store_true", help="Recreate the venv even if one exists")
    parser.add_argument("--model-dir", help="Local folder containing the trained model files")
    parser.add_argument("--model-url", help="URL to a zip archive containing the trained model files")
    args = parser.parse_args()

    _print_header("NIDS Install Wizard")
    print(f"Backend directory: {BACKEND_DIR}")

    if args.skip_venv:
        python_exe = _venv_python(BACKEND_DIR / "venv")
        if not python_exe.exists():
            print("ERROR: --skip-venv given but no venv exists yet. Run without --skip-venv first.")
            sys.exit(1)
    else:
        python_exe = step_create_venv(BACKEND_DIR, force=args.force_venv)

    step_check_npcap(args.silent)
    model_installed = step_install_model(python_exe, args.model_dir, args.model_url, args.silent)
    step_init_databases(python_exe)
    step_configure_env(args.silent)

    _print_header("Setup complete")
    print("Backend venv:  ", python_exe)
    print("Model installed:", "yes" if model_installed else "no (predict endpoint will 503 until installed)")
    print()
    print("To start the backend manually:")
    print(f"  {python_exe} {BACKEND_DIR / 'run_api.py'}")
    print()
    print("The packaged desktop app will start this automatically on launch.")


if __name__ == "__main__":
    main()
