/**
 * Inlined as a string (rather than a separate .html file) and loaded via
 * a data: URL, so it needs no extra electron-vite build configuration -
 * electron-vite only bundles what's imported from TS entry points, and
 * doesn't copy arbitrary static files out of src/main by default.
 */
export const SETUP_WINDOW_HTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />
<title>Setting up NIDS</title>
<style>
  body {
    margin: 0;
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0d1117;
    color: #c9d1d9;
    font-family: -apple-system, 'Segoe UI', Roboto, sans-serif;
  }
  .card { width: 380px; text-align: center; }
  h1 { font-size: 16px; font-weight: 600; margin-bottom: 6px; }
  p { font-size: 13px; color: #8b949e; margin-bottom: 20px; min-height: 18px; }
  .bar-track { background: #21262d; border-radius: 8px; height: 8px; overflow: hidden; }
  .bar-fill { background: #58a6ff; height: 100%; width: 0%; transition: width 0.2s ease; }
  .percent { margin-top: 10px; font-size: 12px; color: #8b949e; }
  .error { color: #f85149; }
</style>
</head>
<body>
  <div class="card">
    <h1>🛡️ Setting up NIDS</h1>
    <p id="message">Preparing…</p>
    <div class="bar-track"><div class="bar-fill" id="bar"></div></div>
    <div class="percent" id="percent">0%</div>
  </div>
  <script>
    const { ipcRenderer } = require('electron');
    ipcRenderer.on('setup-progress', (_event, data) => {
      document.getElementById('bar').style.width = data.percent + '%';
      document.getElementById('percent').textContent = data.percent + '%';
      const msgEl = document.getElementById('message');
      msgEl.textContent = data.message;
      msgEl.className = data.phase === 'error' ? 'error' : '';
    });
  </script>
</body>
</html>`;
