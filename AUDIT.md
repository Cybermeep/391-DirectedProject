# Code Audit — NIDS Project

Scope: everything under `backend/` and `frontend/` in the uploaded repo
(dataset files, model binaries, venv, and node_modules were already
excluded, as noted). Verification method: full manual read-through of
every module, `py_compile` across the entire backend (clean), a
non-strict `tsc` pass across the entire frontend to catch real logic
errors under the noise of missing `node_modules` type declarations
(clean), and an actually-executed automated unit test suite for the new
rule engine (20/20 passing). I could not run the full Flask/Electron app
end-to-end in this sandbox — no network access to `pip install`/`npm
install` the real dependency set (Scapy, scikit-learn, Flask-SocketIO,
etc. aren't available here). Everything below was found via static
analysis and import-graph tracing.

## App-breaking bugs (would have prevented the app from starting/working at all)

0. **Live capture was never connected to detection at all.** This is
   the single biggest gap, found while preparing the demo. `PacketCapture`
   fully supported a per-packet callback, but `api/routes/capture.py`'s
   `/start` route never passed one - captured packets went into a ring
   buffer and nowhere else. Separately, the existing
   `feature_extraction/` package (`basic_features.py`, `count_features.py`,
   etc.) computes a *different* schema (snake_case keys like `syn_count`,
   `total_duration`) than what the trained model and rule engine expect
   (CICFlowMeter-style keys like `SYN_Flag_Cnt`, `Flow_Duration`) - the
   two were never actually wired together, so even a naive fix wiring the
   existing extractor in would have fed the model garbage.
   → Fixed with three new modules: `ml_pipeline/live_features.py`
   (computes the model's exact 78-field schema from raw packet
   timing/flags - unit-tested with 12 passing tests, no scapy required),
   `core/flow_tracker.py` (groups packets into flows by 5-tuple with
   correct fwd/bwd direction and completion detection - 6 passing tests),
   and `core/detection_pipeline.py` (the orchestrator: capture callback →
   flow tracker → feature computation → rule engine + ML model → alert +
   explanation → websocket). `capture.py`'s `/start` route now wires this
   in. **Important caveat**: `live_features.py`'s schema is a best-effort
   reconstruction (documented unit-convention assumptions - see its
   docstring), not guaranteed byte-for-byte parity with whatever the
   original CICFlowMeter tool computed for the training set. The rule
   engine's results are exact and reliable regardless (you control the
   thresholds); treat live ML confidence numbers as illustrative rather
   than a validated accuracy figure unless you've confirmed parity
   yourself. See `DEMO.md` for how this is handled in a presentation
   (a guaranteed-reliable `/api/predict`-based showcase alongside the
   live capture path).

0b. **Alert deduplication was advertised but never implemented.**
   `AlertStore.create_alert`'s docstring and the project's own feature
   list both mention deduplication, but every call just inserted a new
   row - a single sustained flood would have produced dozens of
   near-identical alerts.
   → Fixed: `create_alert` now bumps `count_occurrences`/`last_seen` on
   an existing active alert (same attack_type + dest_port + rule_id
   within a 30-second window) instead of inserting a duplicate.

0c. **`SeverityScorer` and `AlertDeduplicator` were both fully implemented
   and exported from `alert_management/__init__.py`, but neither was ever
   called from anywhere** - `AlertStore.create_alert` just hardcoded
   `severity` from whatever the caller passed and never deduplicated.
   → `SeverityScorer` is now wired in: `core/alerting.py` uses it to
   compute severity for ML-based alerts (rule-based alerts keep the
   severity you chose when writing the rule). `AlertDeduplicator` was
   **not** wired in - it uses a content-hash as the alert's actual
   `alert_id` (`get_alert_hash()` → `Alert.alert_id`), which conflicts
   with `AlertStore.create_alert`'s own random `uuid4()[:8]` id scheme
   and would need reconciling before use. Instead, `create_alert` gained
   its own lighter-weight, compatible dedup (item 0b above) - matching on
   attack_type + dest_port + rule_id within a time window rather than a
   full-payload hash. If you want `AlertDeduplicator`'s specific
   similarity-hash approach instead, it needs `alert_id` decoupled from
   the hash first.

1. **Missing `predict.py` route.** `api/app.py` imported
   `from .routes import alerts, capture, stats, predict`, but no
   `predict.py` existed and `routes/__init__.py` never exported it. The
   Flask app would throw `ImportError` before serving a single request —
   the backend could not start.
   → Fixed: added `api/routes/predict.py`, wired to the existing (but
   previously unused) `ml_pipeline.InferenceEngine`.

2. **Missing `PyJWT` dependency.** `middleware/auth.py` did `import jwt`
   but `PyJWT` was absent from `requirements.txt` — first login attempt
   would `ImportError`.
   → Fixed: added `PyJWT==2.8.0` (and `google-auth==2.29.0` for the new
   Google sign-in) to `requirements.txt` and `setup.py`.

3. **Electron never launched the backend or loaded the preload script.**
   `main/index.ts` always tried `http://localhost:5173` first (the *dev
   server*) even in a packaged production build, always opened
   DevTools, and — most importantly — never spawned the Python backend
   process at all, and never passed a `preload` path to `BrowserWindow`
   (so `window.api`/`window.electron` from `preload/index.ts` never
   actually existed in the renderer). A packaged install would show a
   blank/broken UI with no detection running.
   → Fixed: dev/prod URL detection via `@electron-toolkit/utils`'
   `is.dev`, `preload` path wired up, and the backend Python process is
   now spawned (from a venv provisioned by the installer, see
   `INSTALL.md`), health-checked via `/api/health` before the renderer
   loads, and torn down on quit.

4. **Frontend WebSocket client could never actually talk to the
   backend.** `services/websocket.ts` used the browser's native
   `WebSocket` class directly against a Flask-SocketIO server.
   Flask-SocketIO speaks the Engine.IO/Socket.IO protocol (an HTTP
   handshake at `/socket.io/...` before any upgrade, plus its own event
   framing) — a raw `new WebSocket('ws://host:port')` skips that
   handshake entirely, so `@socketio.on('subscribe_alerts')` etc. on the
   server would never actually receive the client's messages. Real-time
   alerts were non-functional.
   → Fixed: rewrote the client on top of `socket.io-client` (added to
   `package.json`), which is protocol-compatible.

## Security / correctness bugs

5. **In-memory, unsalted credential store.** The original
   `middleware/auth.py` hardcoded an `admin`/`viewer` dict with unsalted
   SHA-256 password hashes — not persisted across restarts, not real
   accounts, and disconnected from any database.
   → Replaced with a proper `User` table (SQLite via SQLAlchemy),
   Werkzeug PBKDF2 password hashing, and JWT access tokens + revocable
   refresh tokens (see `auth/`).

6. **CORS misconfiguration.** `CORS(app, origins=[...specific origins,
   "*"])` — `flask-cors` treats a literal `"*"` as "allow every origin"
   and effectively ignores the explicit list next to it, so the config
   wasn't doing what it looked like. Also broad for a NIDS agent.
   → Fixed to an explicit, env-overridable origin list
   (`CORS_ALLOWED_ORIGINS`).

7. **`eventlet.monkey_patch()` was never called**, despite
   `async_mode='eventlet'` and background `threading.Thread` use in the
   capture routes. Patching must happen before any other stdlib
   socket/threading import in the process, or SocketIO's eventlet loop
   and the capture threads can fight each other in subtle, hard-to-
   reproduce ways.
   → Fixed: `run_api.py` now calls `eventlet.monkey_patch()` as the
   very first line, before any other import.

8. **`debug=True` and `host='0.0.0.0'` hardcoded.** For a home network
   intrusion detection agent, binding to all interfaces by default and
   always running in debug mode (which also enables the Werkzeug
   debugger — remote code execution if ever exposed) is a real exposure
   risk, and debug's reloader forks a second process that doesn't play
   well with eventlet.
   → Fixed: now env-driven (`NIDS_API_HOST`, `NIDS_API_PORT`,
   `FLASK_DEBUG`), defaults to `127.0.0.1`, reloader forced off.

## Fresh-install / packaging bugs

9. **Relative data paths.** `AlertStore`/`init_database` defaulted to
   `data/alerts.db` — a path relative to the process's current working
   directory. That breaks the moment the app runs from an installed
   location (e.g. `Program Files`, which is typically read-only for a
   non-elevated process) or Electron spawns the backend with a
   different cwd.
   → Fixed: added `appconfig.py`, which resolves a proper
   OS-appropriate per-user data directory (`%APPDATA%\NIDS` on Windows,
   `~/Library/Application Support/NIDS` on macOS, XDG dir on Linux) for
   the SQLite DBs, model files, logs, and auto-generated secrets — all
   independent of where the source/installed code lives.

10. **No mechanism existed to load a trained model at all.** The
    `InferenceEngine` class was fully implemented but never
    instantiated or connected to any route, and there was no defined
    location for the (git-ignored) model files to live on a fresh
    machine.
    → Fixed: `ml_pipeline/model_loader.py` (lazy singleton, clear 503
    with instructions instead of crashing when the model isn't
    installed) + `installer/setup_wizard.py`'s model-install step. See
    `INSTALL.md`.

11. Missing `api/middleware/__init__.py` — worked by accident via
    Python's implicit namespace packages, but is fragile and
    inconsistent with every sibling package having an explicit
    `__init__.py`.
    → Added.

## Minor / noted but not changed
- `sqlalchemy.ext.declarative.declarative_base` is a deprecated import
  path in SQLAlchemy 2.0 (still functional in the pinned 2.0.19, just
  emits a deprecation warning). Left as-is for consistency with the
  existing `alert_management/models.py`, which already used this style.
- `core/packet_capture.py` imports `IP` twice (once from `scapy.all`,
  once from `scapy.layers.inet`) — harmless (same class), just
  redundant.
- `AlertStore`'s `get_session()` opens a new SQLAlchemy engine per call
  rather than reusing a module-level engine — inefficient under load,
  functionally correct for SQLite. Not changed; flagging for a future
  pass if performance becomes a concern.

## What I verified by actually running it
- `python3 -m py_compile` across every backend `.py` file: clean.
- `backend/test_rules_engine.py`: 20/20 passing (parser, whitelist
  enforcement, precedence, AST round-tripping, evaluator).
- `backend/test_live_features.py` (new): 12/12 passing - confirms the
  live feature computation produces exactly the model's 78-field schema,
  correct packet/byte counts, correct flag counts, microsecond-scale
  duration, and - most importantly - confirms a synthetic SYN-flood-shaped
  packet sequence actually trips the example rule shown in the frontend.
- `backend/test_flow_tracker.py` (new): 6/6 passing - confirms both
  directions of a conversation group into one flow, direction is assigned
  relative to the actual initiator (not just IP/port sort order), RST
  completes a flow immediately, idle flows get reaped, and the
  max-active-flows safety cap evicts correctly.
- `backend/test_auth_service.py` (new): written and reviewed, but
  **could not be executed here** — it needs SQLAlchemy, which this
  sandbox has no network access to install. Run it yourself after
  `pip install -r requirements.txt`:
  `cd backend && python -m unittest test_auth_service.py -v`
- A non-strict `tsc` pass across the entire frontend source tree to
  separate real type/logic errors from the expected noise of missing
  `node_modules` (react types etc. aren't installed here). No genuine
  errors found in new or modified files beyond the same "implicit any"
  noise present in the original files.
- I could **not** run the Flask server, Electron app, `npm
  install`/`pip install` the full dependency set, or any scapy-dependent
  code (scapy itself isn't installable here - no network egress) end to
  end. Please run the full test suite and a manual smoke test - ideally
  the demo scripts in `demo/` - on your machine before treating this as
  fully verified.

## Addendum: dashboard rebuild + built-in signatures + theme + model auto-download

Prompted by screenshots of the frontend team's actual live dashboard (a
different, more complete build than the scaffold files initially shared -
see chat history for details on that mismatch). Changes made:

- **Rebuilt the dashboard to match the screenshots, wired to real data**:
  threat trend chart, threat classification donut, AI detection panel,
  signature detection table, and alert log sidebar all now call real
  backend endpoints instead of showing static/fake data. Extended
  `InferenceEngine` to track attack/benign prediction counts and load
  accuracy from `evaluation_metrics.json`; extended `/api/stats/dashboard`
  to return real packet counts alongside alert counts.

- **A second, genuinely different detection mechanism was needed**:
  the screenshot's signature table has Threshold/Window columns (e.g.
  "100 SYNs / 10s"), which implies counting events *across many flows*
  grouped by source IP. The existing AST rule engine only evaluates one
  *completed flow* at a time - and this project's own demo attack scripts
  vary source port per packet, meaning a real flood/scan never
  accumulates inside a single flow. Built `rules/rate_signatures.py`, a
  sliding-window counter engine, seeded all 13 signatures from the
  screenshot, and wired it into `core/detection_pipeline.py` alongside
  (not instead of) the AST engine. 9 tests, all passing - including one
  that caught a real cooldown-logic bug (the very first legitimate alert
  was being suppressed by an off-by-default-value bug) before it would
  have silently broken the live demo.

- **Rule model extended** (`rules/models.py`): added `code`,
  `attack_type`, `threshold`, `window_seconds`, `is_builtin` columns, and
  made `user_id` nullable for global built-in rows. `routes/rules.py` now
  lets any authenticated user toggle a built-in signature on/off (no tier
  gate - it's a pre-validated global detection, not a per-user
  creation), while custom AST rule creation/editing remains
  Enterprise-gated as before. Built-in rows can't be deleted, only
  disabled.

- **Dark/light theme toggle**: `context/ThemeContext.tsx` + a
  `data-theme` attribute + doubled CSS variable sets in `App.css`
  (persisted to localStorage, defaults to system preference). Because
  every earlier component was already built on CSS variables for exactly
  this reason, this was a clean addition rather than a rewrite.

- **Electron self-downloads the model on first launch**: new
  `main/modelSetup.ts` + `main/setupWindowHtml.ts`. If the model isn't
  installed and `MAIN_VITE_NIDS_MODEL_URL` is configured in
  `frontend/.env` (baked in at build time via electron-vite's
  `MAIN_VITE_` prefix convention - verified against current electron-vite
  docs, not assumed), the app shows a small progress window, downloads,
  extracts, and installs the model before starting the backend. Falls
  back silently to the manual `installer/setup_wizard.py` path if
  unconfigured. Added `@types/node` as an explicit devDependency, since
  this main-process code uses `fs`/`https`/`path`/`child_process` and it
  shouldn't be left as an unverified transitive dependency.

- **Verified in this session**: full backend `py_compile` (clean), all
  47 pure-Python backend tests passing (`test_flow_tracker.py`,
  `test_live_features.py`, `test_rules_engine.py`,
  `test_rate_signatures.py`), and a non-strict `tsc` pass across the
  entire frontend (including the new main-process files) with no real
  logic errors - only expected `@types/node`-missing noise from this
  sandbox's throwaway type-check environment, which resolves once
  `npm install` pulls in the newly-added `@types/node` devDependency.
  **Not verified**: `npm install`/build end-to-end, the Electron
  packaging/download flow, or anything scapy-dependent - no network
  access in this sandbox to install those.

## Addendum 2: reconciling against the fuller original codebase upload

You uploaded a second, much more complete export of the original project
(`NIDS-proto.zip` - real venv, real node_modules, real trained model,
plus some files the very first upload was missing). This let me verify
several things I could previously only infer, and confirmed every prior
finding rather than overturning any of them:

- **Systematically diffed every backend file against this version**
  (ignoring CRLF-vs-LF line-ending noise, which accounted for the vast
  majority of the reported diffs). The *only* files with genuine content
  differences are exactly the ones I intentionally changed this whole
  conversation - nothing was silently lost or duplicated.

- **Found two files the first upload was missing entirely**:
  `api/ml_integration.py` and `api/detection_pipeline.py` - a real, if
  broken, earlier attempt at live detection wiring. Read them fully:
  `ml_integration.py` eagerly loads the model from a hardcoded relative
  path (`'src/ml_pipeline/models/random_forest.joblib'` - the exact
  fragile-relative-path problem `appconfig.py` was built to fix) and
  `detection_pipeline.py` wires capture → `FlowBuilder` →
  `extractor.extract_features_from_flow()` → the model. That last step
  feeds the model the *wrong* feature schema (the same
  `feature_extraction/` mismatch documented in Addendum 1) - wrapped in a
  bare `try/except: logger.error(...)`, so every single flow would have
  failed prediction silently, with no alert ever produced and no visible
  error. This confirms rather than contradicts the original "capture was
  never actually wired to working detection" finding - it was
  *attempted*, just non-functional. **Not carried into the final
  version** - `core/detection_pipeline.py` + `ml_pipeline/live_features.py`
  supersede it, matching the model's real 78-feature schema and already
  covered by 47 passing tests.

- **`frontend/package.json` already listed `jwt-decode`,
  `react-router-dom`, and `socket.io-client` as dependencies** - but
  `grep` across every renderer file found **zero uses of any of them**.
  `websocket.ts` still used the broken raw `WebSocket` despite
  `socket.io-client` sitting right there in `node_modules`. This means
  someone had started anticipating the auth/routing/realtime work (matches
  the dev-diary notes: "Added placeholder for user login") but none of it
  was actually implemented in any code I've been given, in any of the
  three uploads. My Login/Register/AuthContext/routing/websocket work
  fills a real, confirmed-empty gap - not a duplicate of anything that
  already existed.

- **Copied the real trained model into the repo**
  (`backend/src/ml_pipeline/models/` - `random_forest.joblib`, three
  preprocessor files, `evaluation_metrics.json`, `confusion_matrix.png`,
  `feature_importance.png`, plus a `random_forest.joblib_metadata.joblib`
  that nothing actually reads at load time). Real numbers, for what it's
  worth: **98.27% accuracy**, 99.56% ROC-AUC, per the metrics file.
  `model_loader.py` now checks this source-tree location automatically
  if the per-user data directory doesn't have the model yet - so running
  from a source checkout "just works" without a separate installer step.
  A packaged/installed build won't have this folder at all (excluded via
  `electron-builder.yml`'s `extraResources` filter), so this convenience
  never leaks into a real install.

- **Did not carry over** `backend/venv/` or `frontend/node_modules/`
  (1.1GB combined, machine-specific, and missing this project's new
  dependencies anyway - `PyJWT`/`google-auth` on the backend,
  `recharts`/`extract-zip` on the frontend). Fresh `pip install`/`npm
  install` against the updated `requirements.txt`/`package.json` is both
  necessary and sufficient - see the command sequence below.

- **Did not carry over** the real `backend/data/alerts.db` (a small,
  schema-compatible file with some prior test alerts in it) - starting
  from a clean database makes for a clearer demo. Available if you want
  it: it's schema-compatible with the current `Alert` model (verified -
  that file's columns were unchanged by anything in this conversation),
  so you could copy it into place manually if you'd rather have
  continuity with earlier testing than a blank slate.

## Addendum 3: final audit — a real, verified bug the real model exposed

With the actual trained model now in the repo (see Addendum 2) and
`scikit-learn` available in this sandbox for the first time (a *different*
version than the pin, as it happens), I could finally test the ML path
directly instead of only reviewing it. This surfaced a genuine bug:

- **Loading the model with a scikit-learn version other than the exact
  one it was trained with fails - but not where you'd expect.**
  `joblib.load()` on `random_forest.joblib` succeeds silently (just a
  `InconsistentVersionWarning`), so `/api/model/status` would happily
  report the model as loaded. The failure only happens on the *first
  real prediction call*, and it's a cryptic internal error -
  `AttributeError: 'DecisionTreeClassifier' object has no attribute
  'monotonic_cst'` - with nothing about "wrong scikit-learn version" in
  it. Reproduced this directly against this project's own model file
  (trained with scikit-learn 1.3.0, tested here under 1.8.0).
  `core/detection_pipeline.py`'s broad `except Exception: ml_result =
  None` means this would silently disable all ML-based detection with
  no visible error anywhere in the live-capture path; only a direct
  `/api/predict` call would surface a (still unhelpful) 500.
  → Fixed two ways: `ml_pipeline/inference.py`'s `predict()` now catches
  this specific `AttributeError` and re-raises a `RuntimeError` that
  names the actual problem and the fix (`pip show scikit-learn` /
  reinstall `==1.3.0`) - this surfaces correctly as a 400 from
  `/api/predict` instead of an opaque 500. `installer/setup_wizard.py`
  now checks the installed scikit-learn version immediately after `pip
  install` and prints a clear warning before you ever get to a demo.
  Both fixes verified: re-ran the exact failure with the fix in place
  and confirmed it now raises the actionable message instead of the raw
  `AttributeError`.

- **Verified the feature schema is exactly right, not just "should be."**
  Compared `preprocessor_columns.joblib` (the real model's expected
  columns, in order) against `rules/ast_nodes.py`'s `FEATURE_FIELDS`
  directly: identical set, identical length, **identical order** - 78
  for 78, no mismatches. Also confirmed `preprocess.py`'s `transform()`
  reindexes by column *name* before scaling (`X = X[self.feature_columns]`),
  so even if a caller's dict had a different key order, it wouldn't
  matter - a safety net I hadn't previously verified.

- **Ran real synthetic flows through the actual model** (a SYN-flood
  shape and an ordinary completed HTTPS-session shape, both built from
  `ml_pipeline/live_features.py`) to sanity-check the whole pipeline
  end-to-end. Blocked by the version mismatch above on both attempts in
  this sandbox (no network access here to install the exact pinned
  scikit-learn==1.3.0) - so I can confirm the *pipeline runs without
  crashing up to that point*, but I cannot personally confirm what the
  real model actually predicts for these shapes. **You should run this
  yourself once your venv is set up correctly** - it's a 10-second
  check and the single most informative test available before a live
  demo:
  ```bash
  cd backend && venv/bin/python -c "
  import sys; sys.path.insert(0, 'src')
  from ml_pipeline.inference import InferenceEngine
  from ml_pipeline.live_features import PacketRecord, compute_flow_features
  engine = InferenceEngine(threshold=0.5)
  engine.load_model('src/ml_pipeline/models/random_forest.joblib', 'src/ml_pipeline/models/preprocessor')
  records = [PacketRecord(timestamp=i*0.01, length=60, direction='fwd', syn=True) for i in range(150)]
  features = compute_flow_features(records, dst_port=8899, protocol=6)
  print(engine.predict(features))
  "
  ```

- **Everything else re-verified in this pass came back clean**: full
  `py_compile` across the backend and `installer/setup_wizard.py`, all
  47 pure-Python tests still passing after these changes, no other
  code path touches the model artifacts in a way that could break
  (`confusion_matrix.png`/`feature_importance.png` are write-only
  outputs of `train.py`, never read at runtime;
  `random_forest.joblib_metadata.joblib` is never read by anything).

## Addendum 4: incorporating the other team's rule-based signature engine

**Update: the real, complete files arrived in a follow-up upload**, correctly named this time (I verified the content actually matched each filename before trusting it, given the pattern so far). The missing piece was `rules.py` - the `Rule` dataclass and `default_rules()` with all 30 real configurations. Installed under `backend/src/rule_engine/`, replacing the inert placeholder documented below.

**Ran their real `test_rule_engine.py`: 43/47 passed on the first run.**
Investigated all 4 failures rather than reporting them as detector bugs
without checking - isolated each one by reproducing it with only the
relevant rules loaded, and printing which `rule_id` actually fired.
Conclusion: **all 30 detectors are correct**. Every failure was the same
root cause: `test_rule_engine.py`'s `fire_test()` helper checked "did any
alert fire from any of the 30 loaded detectors" rather than "did the
specific rule under test fire." A "should NOT fire" assertion for, e.g.,
RULE-002 (Port Scan, repeated hits to the *same* port) sent 20 UDP
packets - which correctly produced zero Port Scan alerts, but also
legitimately triggered UDP Flood (RULE-004, an unrelated detector whose
own low test threshold was incidentally satisfied by the same generic
traffic) - and the test flagged that as "RULE-002 fired," which it
didn't. Verified this exact mechanism for all 4 failures (RULE-002,
RULE-005, RULE-006, RULE-013) by isolating each with only its own rule
loaded and confirming zero alerts, then adding back the full rule set
and printing which `rule_id` fired instead.

**Fixed the test harness** (not the detectors, which needed no changes):
`fire_test()` now accepts an optional `rule_id` parameter to filter
which detector's alerts count toward "fired," and applied it to the 4
affected assertions. Re-ran: **47/47 passing.**

**Final integration**: `core/external_rule_engine.py`'s automatic
switchover confirmed working live - `is_active()` now returns `True`
with 30 active detectors (previously `False` with 0, against the
placeholder). Updated `test_external_rule_engine.py` (its own docstring
had flagged this update as needed the moment real rules arrived) to test
the active engine directly - including a full run of a SYN-flood packet
sequence through the real `RuleEngine`, confirming the alert dict it
produces has every key `AlertStore.create_alert()` expects. All 52 of
this project's own tests plus their 47 now passing together.

**Original placeholder writeup, kept for the record:**



| Uploaded as | Actually contains | Correct name |
|---|---|---|
| `test_rule_engine.py` | Test suite | correct as-is |
| `engine.py` | 30 detector classes (1211 lines) | `detectors.py` |
| `detectors.py` | Package `__init__.py` (18 lines) | `__init__.py` |
| `rules.py` | `RuleEngine` orchestrator (255 lines) | `engine.py` |
| *(never uploaded)* | `Rule` dataclass + `default_rules()` - the 30 actual rule configs | `rules.py` |

Confirmed empirically, not just by reading imports: renamed the three
files correctly and ran their own `test_rule_engine.py` against it -
fails immediately at `[Test 1] Module imports...` with
`ModuleNotFoundError: No module named 'rule_engine.rules'`, since every
other module in the package imports `Rule`/`default_rules` from exactly
that missing file.

**What I did about it:**
- Installed the three real files under their correct names in
  `backend/src/rule_engine/`.
- Wrote `backend/src/rule_engine/rules.py` as an explicit **placeholder**
  - not fabricated data. It defines the `Rule` dataclass (mechanical:
  every field name here comes directly from how `engine.py`/`detectors.py`
  actually reference it - `rule_id`, `name`, `attack_type`, `severity`,
  `threshold`, `time_window`, `cooldown`, `enabled`, `params` - not
  guessed) but `default_rules()` deliberately returns an empty list.
  Making up 30 threshold/window/severity values and presenting them as
  "the other team's engine" would misrepresent real decisions I don't
  have. The placeholder's own docstring explains exactly what the real
  file needs to contain.
- Built `core/external_rule_engine.py`, an adapter that: prefers this
  engine over the built-in `rules/rate_signatures.py` engine
  **automatically, but only once it's actually populated** (checked via
  `get_stats()['active_detectors'] > 0`) - with the current placeholder
  that's False, so the pipeline transparently keeps using the tested
  built-in engine. The moment the real `rules.py` is dropped in, this
  flips to True and the pipeline switches over on its own - no other
  code changes needed. Deliberately does **not** use their
  `connect_alert_store()` (it would bypass this project's dedup-by-IP
  fix and websocket broadcast); instead calls `analyze_packet()` directly
  and routes the resulting alert dicts through the existing
  `AlertStore.create_alert()` path, without regenerating an explanation
  since their `BaseDetector._build_alert()` already produces one.
- Wired it into `core/detection_pipeline.py`'s packet handler and into
  `rules/models.py`'s DB seeding (so the dashboard's Signature Detection
  table populates from their `default_rules()` once real, instead of the
  built-in catalog) and into `api/routes/rules.py`'s enable/disable sync.
- Copied their real `test_rule_engine.py` into `backend/` as-is.

**Verified in this pass**: the package imports cleanly and initializes
with 0 active detectors (confirmed - no crash, no silent fake data).
Added `test_external_rule_engine.py` (4 tests, all passing) confirming
the adapter is correctly inert with the placeholder - `is_active()`
False, `analyze_packet()` a safe no-op even with garbage input. Full
backend `py_compile` clean; all 51 tests (47 existing + 4 new) passing.

**Still needed from you**: the real `rules.py` - specifically, whatever
file defines `class Rule` and `def default_rules()` with the actual 30
rule configurations. Once you have it, drop it in at
`backend/src/rule_engine/rules.py` (replacing the placeholder) and
nothing else needs to change - not the adapter, not the seeding, not the
frontend. Their own `test_rule_engine.py` will also then be able to run
past `[Test 1]` for the first time.



## Addendum 5: live-debugging fixes from your actual first run

Real bugs found once this actually ran on real hardware, not caught by anything static analysis or unit tests could have shown:

- **`eventlet.monkey_patch()` genuinely froze the whole server during capture.**
  By default it patches Python's `threading` module process-wide, turning
  every `threading.Thread` - including the one running scapy's blocking
  `sniff()` - into a cooperative greenlet sharing one real OS thread with
  the Flask/SocketIO event loop. Scapy's packet read goes through Npcap
  via a C-level blocking call that eventlet can't make cooperative, so a
  quiet interface could wedge the entire server, not just the capture
  thread - every other request (like clicking Stop) would hang
  indefinitely. Fixed: `run_api.py` now calls
  `eventlet.monkey_patch(thread=False)`, leaving real OS threads for
  `threading.Thread` while still patching what Flask-SocketIO actually
  needs (sockets/SSL). Confirmed fixed on your machine.

- **`/api/capture/interfaces` used scapy's generic `get_if_list()`**,
  which returns raw device GUIDs on Windows - useless to a user and
  exactly why the dropdown looked empty/unusable. Switched to
  `scapy.arch.windows.get_windows_if_list()` (Windows-specific,
  confirmed against your actual machine's real output - "Wi-Fi",
  "Ethernet", etc.), filtering out virtual/filter pseudo-adapters that
  never see real traffic.

- **`AlertDetail` (the "View Alert" panel) had no visible bug in its own
  logic - the layout it depended on no longer existed.** Its CSS assumed
  a `height: 100%` flex-row layout from the original two-column
  Dashboard, which the rebuild (see earlier addenda) replaced with a
  two-column CSS grid. Rendered as an unplaced third grid child, it
  likely collapsed to zero height or landed off-screen - not a crash,
  just invisible. Converted to a proper fixed-position modal overlay
  (backdrop + centered card, click-outside-to-close) instead of relying
  on grid placement it was never actually given.

- **Archive was write-only.** "Archive" set `status='resolved'` but
  nothing ever showed resolved alerts again - the backend's `/api/alerts`
  already supported `?status=` filtering (no backend change needed);
  added an Active/Archived toggle to the Alert Log panel, plus a
  Restore action (`status='active'` is already an accepted value on the
  existing status-update route).

- **Downgrade to Free tier didn't exist at all** - only upgrade was ever
  built. Added `downgrade_tier()` (auth_service.py) +
  `POST /api/auth/downgrade` + frontend wiring. Immediate, no payment
  step. Every tier-gated feature (custom rules, AI panel) already checks
  `user.tier` dynamically, so downgrading re-locks everything
  automatically with no separate "revert perks" logic needed.

- **Model installation was invisible and lazy.** The dev-fallback
  copy-from-source-tree logic only ever ran inside `get_inference_engine()`,
  itself only called lazily on an actual prediction - meaning a user
  could upgrade to a paid tier and never actually get the model
  installed unless something happened to trigger a prediction first, with
  zero feedback either way. Added `POST /api/model/install` (an explicit,
  no-prediction-required trigger for the same logic) and a one-click
  `ModelInstallModal` shown automatically right after a successful
  upgrade - but *only* if `/api/model/status` reports it isn't already
  loaded, so a downgrade-then-re-upgrade cycle (model already installed
  from before) never shows the popup again and the AI panel simply
  re-enables on its own via the existing tier check.

Verified: full backend `py_compile` clean, all 52 tests still passing,
non-strict `tsc` pass across the entire frontend with no real errors
beyond expected `@types/node` noise from this sandbox's throwaway
type-check environment.



## Addendum 6: five new features (severity donut, rule performance, export, tiered retention, attack timeline)

- **Severity donut**: `/api/stats/severity_distribution` already existed
  but was never wired to anything - added `SeverityDonut.tsx` alongside
  the existing attack-type donut. No backend changes needed.

- **Per-rule performance table**: built from real persisted alert
  history (`Alert.rule_id`, already stored on every alert), not an
  in-memory counter - survives restarts and reflects everything ever
  detected. `Alert` (alerts.db) and `Rule` (app.db) are separate SQLite
  files, so this queries each and merges by rule_id/code in Python
  rather than a cross-database SQL join, which SQLite can't do directly.
  New `AlertStore.get_rule_performance()` + `GET /api/stats/rule_performance`.

- **CSV export**: `GET /api/alerts/export?days=N`, gated behind the
  `export_data` tier feature (already defined in `appconfig.TIER_LIMITS`,
  never actually enforced by any endpoint until now). Extended
  `AlertStore.get_alerts()` with an optional `since` datetime filter to
  support this (and the tiered retention below).

- **Tiered historical retention, for real** - two parts:
  1. `core/packet_stats.py` was pure in-memory, resetting every restart -
     meaning a paid tier's "30/365 days of history" promise was never
     actually true for the packet-count trend line. Rewrote it to
     persist to a new `packet_hourly_stats` table in app.db, loaded on
     startup and flushed periodically (throttled to once per 30s, not
     once per packet - a DB write per packet would bottleneck under a
     real flood). Flushing overwrites each hour's total rather than
     computing a delta - safe and idempotent, since a past hour's total
     never changes once that hour has ended.
  2. `/api/stats/dashboard` now accepts `?hours=N`, capped by the
     requesting user's actual tier (`@optional_token` added so an
     anonymous request is conservatively treated as free-tier). Fixed a
     real bug while in there: the timeline query used a fixed
     `limit=50` regardless of window size, silently undercounting any
     range with more than 50 alerts in it - now scales with the
     requested window via the new `since` filter.
  3. `ThreatTrendChart.tsx` previously just sliced the same fixed
     24-hour array for every timeframe button - now actually requests
     the corresponding range and shows a clear message when the user's
     tier caps what's available, with an upgrade link.

- **Attack timeline / correlation view**: new `AlertStore.get_correlated_alerts()`
  groups recent alerts by source IP (a real attack often shows up as a
  sequence - port scan, then brute force a minute later - not isolated
  unrelated events), new `GET /api/alerts/timeline` route, and a new
  `/timeline` page with an expandable chain view per source IP.

Also fixed while touching the same code: `getDashboardStats()`'s return
type in `api.ts` had its own stale inline type from before the
`threats_detected`/`total_packets` timeline shape was introduced several
addenda ago - now correctly uses the `DashboardStats` interface.

Verified: full backend `py_compile` clean, all 52 tests still passing,
non-strict `tsc` pass across the entire frontend with no real errors.
**Not executable-tested**: anything requiring SQLAlchemy (the new
`packet_hourly_stats` persistence, the cross-database rule-performance
merge) - same sandbox limitation as everywhere else in this project;
these are correct by code review and consistent with patterns already
verified elsewhere (e.g. `rules.models`' identical Base/session reuse
pattern), but not executed.



## Suggested follow-ups (not changed, flagging for your judgment)

- `/api/predict` and `/api/model/status` are intentionally left
  unauthenticated (so `demo/predict_showcase.py` and quick smoke tests
  don't require a login first) - fine for a local desktop app talking
  only to `127.0.0.1`, but reconsider before exposing the backend
  publicly for the website-deployment path; wrap them in
  `@token_required` at that point.
- `core/detection_pipeline.py` calls `AlertStore()`/`ExplanationGenerator()`
  fresh on every alert rather than reusing a shared instance - fine for
  demo/moderate traffic, worth pooling if you later stress-test with a
  sustained high-volume flood.
