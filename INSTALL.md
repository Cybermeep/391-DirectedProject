# Installing the NIDS App on a Fresh Machine

This covers both "I'm developing this" and "I'm installing the packaged
app on a new computer" paths. The key thing to understand: **the trained
model files and Python virtual environment are never in git** (see
`.gitignore` — datasets, `*.joblib`, `venv/`), so a fresh clone or a fresh
install both need one extra step to become fully functional. That step is
what `installer/setup_wizard.py` automates.

## Before you start: one verified version-lock to know about

The bundled trained model was pickled with **scikit-learn==1.3.0**
exactly (already pinned in `requirements.txt`). This isn't just a
convention - a different installed version can load the model file
without error and then fail the *first actual prediction* with a
cryptic internal error, unrelated to anything in this codebase. Verified
directly against this project's own model file while auditing it.
`installer/setup_wizard.py` checks this automatically after installing
dependencies and warns if it doesn't match; if you ever install
dependencies manually instead, run:
```bash
pip show scikit-learn   # should print exactly 1.3.0
```

## Option A — Developer setup (running from source)

```bash
git clone <your-repo-url>
cd tempStore

# 1. Set up the backend venv + install dependencies + init databases
python installer/setup_wizard.py --model-dir /path/to/your/trained-model-folder

#    That folder must contain exactly these 4 files (produced by your
#    training pipeline under backend/src/ml_pipeline/):
#      random_forest.joblib
#      preprocessor_scaler.joblib
#      preprocessor_encoder.joblib
#      preprocessor_columns.joblib
#    evaluation_metrics.json is optional but copied along if present.
#
#    If you don't have the model yet, you can skip that flag - the app
#    will run fine, /api/predict will just return 503 until you install
#    one later:
#      python installer/setup_wizard.py --skip-venv --model-dir /path/to/model

# 2. Start the backend
cd backend
./venv/bin/python run_api.py          # Windows: venv\Scripts\python.exe run_api.py

# 3. In a second terminal, start the frontend dev server
cd frontend
npm install
npm run dev          # plain website dev server (vite.config.ts)
# — or —
npm run dev:electron # Electron shell (electron.vite.config.mjs) - check package.json scripts for the exact name in your setup
```

Then open the printed dev URL (or the Electron window), register an
account, and you're in.

## Option B — Installing the packaged desktop app on someone else's Windows machine

This is what `electron-builder` (NSIS) produces and what an end user
actually double-clicks.

1. **Build the installer** (on a dev machine):
   ```bash
   cd frontend
   npm install
   npm run build          # builds the renderer + main + preload
   npx electron-builder --win
   ```
   This bundles the `backend/` folder (minus `venv/`, `__pycache__/`,
   model files, and `.env` — see the `extraResources` filter in
   `electron-builder.yml`) into the installed app's resources folder.

2. **Run the generated `network-intrusion-app-<version>-setup.exe`** on
   the target machine. NSIS installs the app (and the bundled backend
   source) under `Program Files\network-intrusion-app\resources\backend`.

3. **Run the install wizard once**, pointed at that installed location:
   ```powershell
   cd "C:\Program Files\network-intrusion-app\resources\backend"
   python ..\..\..\installer\setup_wizard.py --model-dir C:\path\to\model-files
   ```
   (Or run it from wherever you keep `installer/setup_wizard.py` — it
   only needs to be pointed at a `backend/` folder with `requirements.txt`
   and `run_api.py` in it; adjust `BACKEND_DIR` at the top of the script
   if you're invoking it from an unusual location.)

   This step:
   - creates `resources/backend/venv` and installs all Python
     dependencies into it (this is why it needs to run with
     Administrator privileges on Windows, since it's writing under
     `Program Files` — a one-time, install-time operation)
   - detects whether **Npcap** is installed (required by Scapy for live
     packet capture on Windows) and tells you where to get it if not:
     https://npcap.com/#download — check "Install Npcap in WinPcap
     API-compatible Mode" during its install
   - copies your trained model files into the app's per-user data
     directory (`%APPDATA%\NIDS\models`) — **not** into `Program Files`,
     since that's per-user data, not part of the app itself
   - initializes both SQLite databases (`%APPDATA%\NIDS\app.db` for
     accounts/rules, `%APPDATA%\NIDS\alerts.db` for alerts)
   - optionally asks for a Google OAuth Client ID (see below) and writes
     `resources/backend/.env`

4. **Launch the app** from the Start Menu shortcut. On launch, the
   Electron main process spawns `resources/backend/venv/Scripts/python.exe
   run_api.py`, waits for `/api/health` to respond, then loads the UI.

### Distributing the model file itself

`setup_wizard.py --model-url <url>` can also download a zip containing
those 4 files from wherever you host them (a private S3 bucket, a
release asset, etc.) instead of requiring a local folder — useful if
you want the installer to be closer to "download and go" for end users
who don't have the training pipeline's output on hand.

### Setting up Google Sign-In (optional)

1. Google Cloud Console → APIs & Services → Credentials → **Create
   Credentials → OAuth client ID → Web application**.
2. Add `http://localhost:5173` (dev) and your deployed website's origin
   (if applicable) under **Authorized JavaScript origins**.
3. Put the resulting Client ID in:
   - `backend/.env` → `GOOGLE_CLIENT_ID=...` (the wizard will prompt for
     this, or add it manually)
   - `frontend/.env` → `VITE_GOOGLE_CLIENT_ID=...` (same value)

Leave both blank and the Google sign-in button simply doesn't render —
nothing breaks.

## Option C — Deploying the frontend as a plain website

`frontend/vite.config.ts` (as opposed to `electron.vite.config.mjs`)
builds a plain static site with no Electron dependency:

```bash
cd frontend
npm install
VITE_API_BASE_URL=https://your-deployed-backend.example.com/api \
VITE_WS_URL=https://your-deployed-backend.example.com \
VITE_GOOGLE_CLIENT_ID=your-client-id \
npm run build
```

Deploy the resulting `out/renderer` (or wherever your build config
points, check `vite.config.ts`'s `build.outDir`) to any static host
(Netlify, Vercel, S3+CloudFront, GitHub Pages, etc.). The app uses
`HashRouter`, so client-side routes (`#/login`, `#/rules`, ...) work on a
plain static host with no server-side rewrite-rule configuration needed.

You'll need the Flask backend running somewhere reachable over HTTPS
(a small VM, Docker container — a `Dockerfile` is mentioned as already
present in your stack overview — or a PaaS). Point `VITE_API_BASE_URL`/
`VITE_WS_URL` at it, and set `CORS_ALLOWED_ORIGINS` on the backend to
your deployed site's origin.
