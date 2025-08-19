# APK Safety Analyzer (Flask)

A simple web app to upload an APK and perform basic static checks using Androguard. It reports metadata, permissions, URLs, components, certificates, and a lightweight risk score. The main page features a modern, corporate-style intro and graphical charts for results.

## Features
- Basic APK parsing with Androguard
- Lists dangerous and all permissions
- Extracts URLs (manifest and filenames)
- Shows activities, services, receivers
- Shows coarse certificate info
- Simple risk score and label (Low/Medium/High)
- Graphical charts (Chart.js): Risk donut, Permissions donut, Components bar

## Tech Stack
- Backend: Python (Flask)
- Frontend: HTML, CSS, Vanilla JS (+ Chart.js for charts)

## Project Structure
- `app.py` — Flask server and analysis logic
- `templates/index.html` — Frontend page (uploader, intro hero, results + charts)
- `static/styles.css` — Styles (dark, polished theme)
- `static/app.js` — Client logic for upload, rendering results, and charts
- `uploads/` — Auto-created folder for uploaded files
- `requirements.txt` — Python dependencies

## Setup (Windows, PowerShell)
1) Create and activate a virtual environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2) Install dependencies
```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

3) Run the app
```powershell
python app.py
```
App will run at: http://127.0.0.1:5000/

## Usage
1) Open the app in your browser.
2) Drag & drop an `.apk` or click the drop area to select a file.
3) Click Analyze. The hero intro hides and results appear with:
   - Summary and recommendation
   - Charts for risk, permissions, and components
   - Detailed lists (permissions, URLs, activities, services, receivers, certificates)
4) Expand Raw JSON for audit-ready details.

## Notes
- Analysis is static and basic; it is NOT a full malware analysis. For production use, combine with dynamic analysis and additional heuristics.
- APK size limit is set to 100 MB. Adjust in `app.py` via `app.config["MAX_CONTENT_LENGTH"]` if needed.
- If Androguard fails on some APKs, ensure `lxml` and `pycryptodome` are installed and your Python is 3.9–3.11.
- VirusTotal integration has been removed to simplify the app. SHA-256 is still computed for display if needed.

## Troubleshooting
- If you see "Androguard is not installed" in results, (re)install requirements inside the virtual environment.
- On PowerShell execution policy errors when activating venv, run PowerShell as Administrator and:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Then re-run the activation command.
