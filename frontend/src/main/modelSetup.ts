import { app } from 'electron';
import { join } from 'path';
import { existsSync, mkdirSync, createWriteStream, rmSync, readdirSync, renameSync } from 'fs';
import https from 'https';
import http from 'http';
import extract from 'extract-zip';

/**
 * Resolves the same per-user data directory the Python backend uses (see
 * backend/src/appconfig.py::_default_user_data_dir). Both processes must
 * agree on this path without talking to each other first, since this
 * runs *before* the backend process exists yet on a fresh install.
 */
export function getModelDir(): string {
  let base: string;
  if (process.platform === 'win32') {
    base = process.env.APPDATA || join(app.getPath('home'), 'AppData', 'Roaming');
  } else if (process.platform === 'darwin') {
    base = join(app.getPath('home'), 'Library', 'Application Support');
  } else {
    base = process.env.XDG_DATA_HOME || join(app.getPath('home'), '.local', 'share');
  }
  return join(base, 'NIDS', 'models');
}

const REQUIRED_FILES = [
  'random_forest.joblib',
  'preprocessor_scaler.joblib',
  'preprocessor_encoder.joblib',
  'preprocessor_columns.joblib',
];

export function isModelInstalled(): boolean {
  const dir = getModelDir();
  return REQUIRED_FILES.every((f) => existsSync(join(dir, f)));
}

/**
 * The URL to download the model archive from. Configure this per-deployment
 * by adding MAIN_VITE_NIDS_MODEL_URL=<url> to frontend/.env before running
 * `npm run build` - electron-vite exposes any MAIN_VITE_-prefixed variable
 * to the main process bundle via import.meta.env (baked in at build time,
 * unlike process.env, which wouldn't exist for a user launching the
 * packaged app from a shortcut). If unset, auto-download is skipped
 * entirely and the user falls back to the manual
 * `installer/setup_wizard.py --model-dir/--model-url` path.
 */
export function getConfiguredModelUrl(): string | null {
  return (import.meta as any).env?.MAIN_VITE_NIDS_MODEL_URL || null;
}

export interface DownloadProgress {
  phase: 'downloading' | 'extracting' | 'done' | 'error';
  percent: number; // 0-100
  message: string;
}

function followRedirects(url: string, onResponse: (res: any) => void, onError: (err: Error) => void) {
  const lib = url.startsWith('https') ? https : http;
  lib
    .get(url, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        followRedirects(res.headers.location, onResponse, onError);
        return;
      }
      if (res.statusCode !== 200) {
        onError(new Error(`Download failed: HTTP ${res.statusCode}`));
        return;
      }
      onResponse(res);
    })
    .on('error', onError);
}

/**
 * Downloads the model archive and extracts it into the resolved model
 * directory, reporting progress along the way. Safe to call even if
 * NIDS_MODEL_URL isn't set - callers should check getConfiguredModelUrl()
 * first and skip this entirely (falling back to manual install) if null.
 */
export function downloadAndInstallModel(onProgress: (p: DownloadProgress) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const url = getConfiguredModelUrl();
    if (!url) {
      reject(new Error('NIDS_MODEL_URL is not configured'));
      return;
    }

    const modelDir = getModelDir();
    mkdirSync(modelDir, { recursive: true });
    const tmpZipPath = join(modelDir, '_download.zip');
    const tmpExtractDir = join(modelDir, '_extracted');

    onProgress({ phase: 'downloading', percent: 0, message: 'Connecting…' });

    followRedirects(
      url,
      (res) => {
        const total = parseInt(res.headers['content-length'] || '0', 10);
        let downloaded = 0;
        const fileStream = createWriteStream(tmpZipPath);

        res.on('data', (chunk: Buffer) => {
          downloaded += chunk.length;
          const percent = total > 0 ? Math.round((downloaded / total) * 90) : 0; // reserve 90-100% for extraction
          onProgress({
            phase: 'downloading',
            percent,
            message: `Downloading model (${(downloaded / 1_000_000).toFixed(1)}MB${total ? ` / ${(total / 1_000_000).toFixed(1)}MB` : ''})`,
          });
        });

        res.pipe(fileStream);

        fileStream.on('finish', async () => {
          try {
            onProgress({ phase: 'extracting', percent: 92, message: 'Extracting model files…' });
            rmSync(tmpExtractDir, { recursive: true, force: true });
            mkdirSync(tmpExtractDir, { recursive: true });
            await extract(tmpZipPath, { dir: tmpExtractDir });

            // The zip may contain the files directly, or nested in a folder - find them either way.
            const found = findRequiredFiles(tmpExtractDir);
            if (!found) {
              throw new Error('Downloaded archive did not contain the expected model files');
            }
            for (const filename of REQUIRED_FILES) {
              renameSync(join(found, filename), join(modelDir, filename));
            }
            const metricsPath = join(found, 'evaluation_metrics.json');
            if (existsSync(metricsPath)) {
              renameSync(metricsPath, join(modelDir, 'evaluation_metrics.json'));
            }

            rmSync(tmpZipPath, { force: true });
            rmSync(tmpExtractDir, { recursive: true, force: true });

            onProgress({ phase: 'done', percent: 100, message: 'Model installed.' });
            resolve();
          } catch (err: any) {
            onProgress({ phase: 'error', percent: 0, message: err.message });
            reject(err);
          }
        });

        fileStream.on('error', (err) => {
          onProgress({ phase: 'error', percent: 0, message: err.message });
          reject(err);
        });
      },
      (err) => {
        onProgress({ phase: 'error', percent: 0, message: err.message });
        reject(err);
      }
    );
  });
}

/** Searches up to 2 directories deep for a folder containing all REQUIRED_FILES. */
function findRequiredFiles(root: string, depth = 0): string | null {
  if (existsSync(root) && REQUIRED_FILES.every((f) => existsSync(join(root, f)))) {
    return root;
  }
  if (depth >= 2) return null;
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      const found = findRequiredFiles(join(root, entry.name), depth + 1);
      if (found) return found;
    }
  }
  return null;
}
