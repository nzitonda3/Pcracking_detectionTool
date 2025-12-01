# Pcracking_detectionTool

Lightweight Flask app to simulate password cracking audits and detection. The project integrates a small PCFG analysis, a John the Ripper (JTR) audit wrapper, and detection/simulation utilities. It stores results in a local SQLite database (`pcdt.db`).

**Quick overview**
- Web app: `app.py` (Flask). Admin UI available at `/admin`.
- DB helpers: `database.py` (creates tables, helper functions).
- JTR wrapper: `jtr_utils.py` — does a fast Python dictionary attack against a configured wordlist (if present) and falls back to invoking John incremental mode if needed.
- PCFG analysis: `pcfg_utils.py` (simple heuristics and storage).
- Detection & simulation: `detection.py`, `simulate_engine.py`.

Requirements
------------
- Python 3.8+
- See `requirements.txt` for Python packages (install into a venv).
- John the Ripper (system binary) is OPTIONAL but recommended for incremental/cracking fallback. The app uses a Python-based dictionary scan first when a wordlist is configured.

Install
-------
1. Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. (Optional) Install John the Ripper via your distro package manager (for incremental fallback):

```bash
# Debian/Ubuntu (if available):
sudo apt update && sudo apt install john
```

Prepare a wordlist (recommended)
--------------------------------
The app looks for a wordlist configured in the DB under `JTR_WORDLIST` or at `/usr/share/wordlists/rockyou.txt` by default. To use your local copy (for example `~/Downloads/rockyou.txt`), copy it to the system path or set the DB config:

```bash
# Copy to system location (recommended):
sudo mkdir -p /usr/share/wordlists
sudo cp ~/Downloads/rockyou.txt /usr/share/wordlists/rockyou.txt

# Or configure the DB to point to your copy (no copy required):
python3 -c "import sys; sys.path.insert(0,'/home/ubuntu/pcdt'); from database import set_config; set_config('JTR_WORDLIST','/home/ubuntu/Downloads/rockyou.txt')"
```

Configuration
-------------
- `JTR_WORDLIST` (DB config): path to a wordlist used by the Python dictionary scan.
- `JTR_MAX_SECONDS_PER_USER` (DB config): per-user timeout (seconds) for the JTR/incremental fallback. The app default is 30 seconds.

To set these via the DB programmatically (example):

```bash
python3 -c "import sys; sys.path.insert(0,'/home/ubuntu/pcdt'); from database import set_config; set_config('JTR_MAX_SECONDS_PER_USER','30'); set_config('JTR_WORDLIST','/usr/share/wordlists/rockyou.txt')"
```

Running the app
---------------
Start the Flask app locally:

```bash
FLASK_APP=app.py flask run --host=0.0.0.0 --port=5000
# or
python3 app.py
```

Open the admin UI at `http://localhost:5000/admin` (login with the admin account created on first run: `admin` / `AdminPass123!`). Use the admin pages to run simulations or audits.

JTR behavior specifics
----------------------
- The app first tries a small hard-coded `common_passwords` fast-path (very quick).
- If `JTR_WORDLIST` is configured and exists, the app performs a Python-based dictionary scan of that file and compares SHA-512 hashes directly (fast and reliable for dictionary lookups).
- If no usable wordlist is found, the app falls back to invoking the `john` binary in `--incremental` mode. Note: some system John builds may not support `Raw-SHA512` format; in that case the Python dictionary path is the reliable path.

Data and audit_time
-------------------
- JTR results are saved to the `jtr_results` table in `pcdt.db`.
- `audit_time` is stored as milliseconds (integer) representing elapsed time for that user's audit run. Small values (e.g., `64`) are 64 ms; larger values reflect longer runs or timeouts.

Schema migration note
---------------------
If `pcdt.db` already exists with an older schema the `init_db()` will not automatically alter existing tables. If you need the `jtr_results.audit_time` column to be an INTEGER on an existing DB, I can perform a migration (create a new table, copy rows, replace the old table).

Testing and utilities
---------------------
- `run_full_audit_all_users()` in `jtr_utils.py` runs a full audit for every user and stores results; it's invoked by the admin UI "Run audit" button.
- `simulate_attack.html` lets you run simulated login attacks for detection testing.

Security/Privacy
----------------
- This project stores password hashes (SHA-512) and may temporarily store plaintext for PCFG analysis; the plaintext is deleted after analysis. Use caution when running with real user data.

Questions / Next steps
---------------------
- Want me to add a `method` column to `jtr_results` to indicate `python_dict` vs `john_incremental`? I can add that and migrate the DB.
- Want the migration to convert existing `audit_time` to integers and normalize the column type? I can run it now if you approve.
