# L3 Log Analyzer – Code Flow

## Project Structure

```
ue_journey/
├── main.py               ← PyInstaller entry point (double-click .exe)
├── app.py                ← Flask application (routes + analysis logic)
├── constants.py          ← Enums, regex patterns, milestone definitions
├── l3_bin_reader.py      ← Binary log file reader / converter
├── rrm_parser.py         ← RRM log parser
├── l3_rrm_correlator.py  ← L3 ↔ RRM event correlator
├── app.spec              ← PyInstaller spec (builds .exe)
├── requirements.txt      ← Runtime pip dependencies
├── static/               ← CSS, images
├── templates/            ← Jinja2 HTML templates
├── uploads/              ← User session folders (runtime, writable)
├── generated_logs/       ← Exported text logs (runtime, writable)
├── converted/            ← Converted binary logs (runtime, writable)
└── docs/
    └── CODE_FLOW.md      ← This file
```

---

## 1. Application Startup

```
double-click L3_Log_Analyzer.exe
        │
        ▼
   main.py  __main__
        │
        ├─ _resource_path()   → resolves templates/ and static/ inside the .exe bundle (sys._MEIPASS)
        ├─ _data_dir()        → resolves uploads/, generated_logs/, converted/ next to the .exe (writable)
        ├─ sets APP_RESOURCE_DIR and APP_DATA_DIR env vars
        ├─ imports app.py     → Flask app is created with correct folder paths
        ├─ spawns threading.Thread(_open_browser) → opens http://127.0.0.1:5000 after 1.5 s
        └─ app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)
```

---

## 2. Flask App Initialization (`app.py` module level)

```
app.py import
    │
    ├─ _resource_path() / _data_dir()  → PyInstaller-safe path helpers
    ├─ Flask(__name__, template_folder=..., static_folder=...)  → explicit paths for frozen exe
    ├─ UPLOAD_FOLDER / GENERATED_LOGS_FOLDER / CONVERTED_FOLDER  → absolute paths via _data_dir()
    ├─ os.makedirs(...)  → create runtime folders on first run
    └─ global state variables:
         ue_data_map, rrc_counts, insights_global, valid_indices_global,
         rre_mapping_results, rre_edge_cases_global, drx_messages,
         last_analysis_snapshot, bt_df, crash, analysis_progress
```

---

## 3. Upload & Session Management

```
GET /  →  redirect to /upload
          │
          ▼
       upload_page()  [GET]
          │
          ├─ _session_directories()   → lists uploads/session_* sorted by mtime
          ├─ _enforce_session_limit() → removes oldest sessions beyond MAX_SAVED_SESSIONS (5)
          └─ renders upload.html      → shows upload form + previous sessions

POST /upload
          │
          ├─ [File Upload]  multipart files saved to uploads/session_<timestamp>/
          │
          └─ [SCP Remote]   server_path = user@host:/remote/dir
                            └─ spawns _scp_download_and_analyze_worker() in a thread
                                   └─ redirects to /progress_page (polling)
```

---

## 4. Analysis Pipeline

### 4a. Local Folder Analysis

```
GET /analyze_logs/<folder>
        │
        ├─ resolves folder path (absolute or relative to UPLOAD_FOLDER)
        ├─ copies chosen files to a new session folder
        ├─ initialises analysis_progress dict
        └─ spawns analysis in a background thread → renders progress.html

Background thread:
        ├─ count_rrc_messages(folder)          → counts raw RRC message occurrences
        ├─ merge_logs_for_ue_journey(folder)   → returns combined UE data map
        │       └─ per file: process_logs_for_ue_journey(file)  (see §4b)
        ├─ detect_rre_edge_cases(folder)       → RRE triggers without UE context
        ├─ map_edge_cases_to_previous_ue()     → CRNTI correlation
        ├─ detect_rre_mappings(combined_map)   → RRE current ↔ previous UE map
        ├─ detect_drx_messages_from_rrm()      → DRX events from RRM logs
        ├─ generate_insights(combined_map)     → per-UE problem heuristics
        ├─ compute_drop_rates(rrc_counts)      → RRC_SUCCESS_RATE metric
        ├─ parse_cell_setup_status(folder)     → cell-level milestone tracking
        └─ populates last_analysis_snapshot and live global state
```

### 4b. Per-File Log Parser (`process_logs_for_ue_journey`)

```
process_logs_for_ue_journey(filepath)
        │
        ├─ reads file line by line; detects backtrace (bt_df / crash)
        ├─ builds DataFrame of rows: [Date, Time, File, Line, Message, LogLine]
        │
        ├─ Phase 1: split log into star-delimited raw blocks
        │           (separator: *************)
        │
        ├─ Phase 2: assign each raw block to its UE(s)
        │           ue_re matches: UE:<n>  |  UE INDEX = <n>  |  ue_index = <n>
        │           • 1 UE → assign whole block
        │           • Multi-UE → split block at UE-change boundaries
        │           • No UE ref → store under key 'no_ue_index' (dropped later)
        │
        └─ Phase 3: deduplicate identical blocks per UE (hash-based)
           returns {"ue_blocks": {ue_index: [[rows], ...]}, "crash": bool}
```

### 4c. SCP Remote Download Worker (`_scp_download_and_analyze_worker`)

```
_scp_download_and_analyze_worker(username, hostname, remote_dir, password, ...)
        │
        ├─ paramiko SSH connect
        ├─ ls L3_EVENT_X.dbg* RRM_EVENT_X.dbg*    → list remote files
        ├─ _filter_files_by_time_range()            → optional [start_dt, end_dt] filter
        ├─ sftp.get() each file → session_folder
        └─ runs the same analysis pipeline as local (§4a)
```

---

## 5. Progress Polling

```
Client (browser)          Server
    │                        │
    ├─ GET /progress_page  → progress.html (JS polling loop)
    │
    ├─ GET /progress  ─────► jsonify(analysis_progress)
    │   (every 1 s)           {active, current, total, message, completed, error, ...}
    │
    └─ when completed=True → JS redirects to analysis_progress['next_url']
                             (default: /results)
```

---

## 6. Results & Data Pages

| Route | Template | Data Source |
|---|---|---|
| `/results` | `index.html` | `ue_data_map`, `rrc_counts`, `insights_global` |
| `/ue_summary` | `ue_summary.html` | `generate_ue_summary(data_map)` |
| `/ue_stats` (POST) | `ue_stats.html` | per-UE message extraction, sequence diagram |
| `/milestones` (POST) | `milestones.html` | `extract_ue_milestones()` |
| `/rrc_counters` | `rrc_counters.html` | `rrc_counts`, `compute_drop_rates()` |
| `/search_data` | `search_data.html` | grep over `ue_data_map` messages |
| `/ho_mapping` | `ho_mapping.html` | `build_ho_maci_mapping()` (mac_i correlation) |
| `/rre_results` | `rre_results.html` | `rre_mapping_results`, `rre_edge_case_mappings_global` |
| `/drx_status` | `drx_status.html` | `drx_messages` organised by UE |
| `/rrm_debug` | `rrm_debug.html` | `rrm_parser` stats, `l3_rrm_correlator` |

---

## 7. Key Analysis Functions

### UE Classification

```
generate_ue_summary(data_map)
    ├─ for each UE: single-pass message scan
    ├─ S1AP handover  → S1AP_MSG: HANDOVER REQUEST present
    ├─ X2AP handover  → has_x2ap_ho_req OR has_uecc_trg_ho (not S1AP)
    └─ Direct attach  → neither
```

### HO Mapping (mac_i correlation)

```
build_ho_maci_mapping()
    ├─ Step 1: source UE → mac_i  (Value of U32 mac_i = <N>)
    ├─ Step 2: target UE → short_mac_i  (Value of U16 target_cell_short_mac_i = <N>)
    └─ Step 3: match source ↔ target by truncating mac_i to 16-bit (& 0xFFFF)
```

### RRE Mapping (CRNTI correlation)

```
detect_rre_mappings(combined_map)
    ├─ Phase 1: find all RRE trigger events ([RNTI:<n>] RRC CONNECTIONREESTABLISHMENT REQUEST)
    │            extract CRNTI, PCI, timestamp, failure cause
    ├─ Phase 2 (Pass 1): 30-second window search for previous UE with same CRNTI
    └─ Phase 2 (Pass 2): full session exhaustive search if window search fails
```

### Cell Setup Milestones

```
parse_cell_setup_status(folder)
    ├─ scans L3_EVENT_X* files for milestone patterns (from constants.CELL_SETUP_MILESTONES)
    ├─ per-cell tracking: cell_setup_req → cell_configured timestamp
    └─ overall_status: 'success' | 'partial' | 'failure'
```

---

## 8. PyInstaller Packaging Flow

```
pyinstaller app.spec
        │
        ├─ Analysis:
        │     main.py   ← entry point
        │     collect_all(pandas, paramiko, flask, werkzeug, jinja2, cryptography)
        │     datas: templates/, static/, constants.py, l3_bin_reader.py,
        │            rrm_parser.py, l3_rrm_correlator.py
        │
        ├─ PYZ:  compresses all .pyc
        │
        └─ EXE:  dist/L3_Log_Analyzer.exe  (single file, console=True)
                  at runtime → extracts to sys._MEIPASS (temp dir)
                             → writable data next to .exe (_data_dir)
```

---

## 9. Security Notes

- The app binds only to `127.0.0.1` (loopback) — not accessible from the network.
- `debug=False` and `use_reloader=False` are enforced — no Werkzeug debugger PIN exposure.
- File uploads are restricted to the session folder; path traversal is mitigated by `unquote` + explicit `os.path.join` with `UPLOAD_FOLDER` prefix checks.
- SCP passwords are handled in memory only; never written to disk.
