import { app, BrowserWindow } from 'electron';
import { is } from '@electron-toolkit/utils';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { spawn, ChildProcess } from 'child_process';
import { existsSync } from 'fs';
import { isModelInstalled, getConfiguredModelUrl, downloadAndInstallModel } from './modelSetup';
import { SETUP_WINDOW_HTML } from './setupWindowHtml';

// Fix for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let mainWindow: BrowserWindow | null = null;
let backendProcess: ChildProcess | null = null;

const BACKEND_HOST = '127.0.0.1';
const BACKEND_PORT = 5000;

/**
 * On first run (or any run where the model isn't installed yet), show a
 * small progress window while downloading and unpacking it - so the user
 * never has to open a terminal or run the installer wizard manually just
 * to get detection working. Only runs if NIDS_MODEL_URL was configured
 * at build time (see modelSetup.ts); otherwise this is a no-op and the
 * app proceeds exactly as before (predict endpoint will 503 until the
 * model is installed some other way, e.g. installer/setup_wizard.py).
 */
async function ensureModelDownloaded(): Promise<void> {
  if (isModelInstalled() || !getConfiguredModelUrl()) {
    return;
  }

  const setupWindow = new BrowserWindow({
    width: 420,
    height: 220,
    resizable: false,
    autoHideMenuBar: true,
    webPreferences: {
      // This window only ever loads a local, bundled HTML file we wrote
      // ourselves (never remote/untrusted content), so relaxing isolation
      // here to let it use ipcRenderer directly is an acceptable tradeoff
      // for a small, transient setup screen. The main app window keeps
      // full contextIsolation (see createWindow below).
      nodeIntegration: true,
      contextIsolation: false,
    },
  });
  await setupWindow.loadURL('data:text/html;charset=UTF-8,' + encodeURIComponent(SETUP_WINDOW_HTML));

  try {
    await downloadAndInstallModel((progress) => {
      setupWindow.webContents.send('setup-progress', progress);
    });
    // Briefly show the completed state before closing.
    await new Promise((resolve) => setTimeout(resolve, 600));
  } catch (err) {
    console.error('[model-setup] download failed:', err);
    // Give the user a moment to read the error before continuing anyway -
    // the app is still usable, just without ML predictions until the
    // model is installed some other way.
    await new Promise((resolve) => setTimeout(resolve, 3000));
  } finally {
    setupWindow.close();
  }
}

/**
 * Locate the bundled backend and its Python interpreter.
 *
 * In dev, the developer runs `python run_api.py` themselves (matching the
 * existing dev workflow) - this app never spawns a backend in dev mode.
 *
 * In a packaged build, the backend/ folder is bundled as an extraResource
 * (see electron-builder.yml) and the installer creates a venv inside it
 * at install time (see installer/setup_wizard.py). We just need to find
 * that venv's python executable and launch run_api.py with it.
 */
function resolveBackendPaths(): { backendDir: string; pythonExe: string; runScript: string } | null {
  const backendDir = join(process.resourcesPath, 'backend');
  const runScript = join(backendDir, 'run_api.py');

  const pythonExe =
    process.platform === 'win32'
      ? join(backendDir, 'venv', 'Scripts', 'python.exe')
      : join(backendDir, 'venv', 'bin', 'python');

  if (!existsSync(runScript) || !existsSync(pythonExe)) {
    return null;
  }
  return { backendDir, pythonExe, runScript };
}

function startBackend(): void {
  if (is.dev) {
    console.log('[backend] dev mode - assuming you are running `python run_api.py` yourself');
    return;
  }

  const paths = resolveBackendPaths();
  if (!paths) {
    console.error(
      '[backend] Could not find a provisioned backend venv. Run the installer ' +
        '(installer/setup_wizard.py) to set up the Python environment and model files.'
    );
    return;
  }

  console.log(`[backend] starting ${paths.pythonExe} ${paths.runScript}`);
  backendProcess = spawn(paths.pythonExe, [paths.runScript], {
    cwd: paths.backendDir,
    env: { ...process.env, NIDS_API_HOST: BACKEND_HOST, NIDS_API_PORT: String(BACKEND_PORT) },
    windowsHide: true,
  });

  backendProcess.stdout?.on('data', (data) => console.log(`[backend] ${data}`.trim()));
  backendProcess.stderr?.on('data', (data) => console.error(`[backend] ${data}`.trim()));
  backendProcess.on('exit', (code) => console.log(`[backend] exited with code ${code}`));
}

function stopBackend(): void {
  if (backendProcess && !backendProcess.killed) {
    backendProcess.kill();
    backendProcess = null;
  }
}

/** Poll the health endpoint before loading the renderer, so the user never sees an empty/error screen while the backend is still booting. */
async function waitForBackend(maxAttempts = 30, delayMs = 500): Promise<boolean> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const res = await fetch(`http://${BACKEND_HOST}:${BACKEND_PORT}/api/health`);
      if (res.ok) return true;
    } catch {
      /* backend not up yet - keep polling */
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  return false;
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      // NOTE: the previous version never set a preload script, so
      // contextBridge.exposeInMainWorld calls in preload/index.ts never
      // actually ran and window.api / window.electron were never
      // available to the renderer. Fixed here.
      preload: join(__dirname, '../preload/index.js'),
    },
  });

  if (!is.dev) {
    await ensureModelDownloaded();
    startBackend();
    await waitForBackend();
  }

  if (is.dev && process.env['ELECTRON_RENDERER_URL']) {
    await mainWindow.loadURL(process.env['ELECTRON_RENDERER_URL']);
    mainWindow.webContents.openDevTools();
  } else {
    await mainWindow.loadFile(join(__dirname, '../renderer/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();
});

app.on('window-all-closed', () => {
  stopBackend();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  stopBackend();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
