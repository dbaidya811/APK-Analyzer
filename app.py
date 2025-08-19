import os
import re
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

# Optional: try to import androguard, but keep friendly error if missing
try:
    from androguard.core.bytecodes.apk import APK
    ANDRO_OK = True
except Exception:  # pragma: no cover
    ANDRO_OK = False


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"apk"}

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)


@app.errorhandler(RequestEntityTooLarge)
def handle_413(e):
    return jsonify({"ok": False, "error": "File too large. Max allowed is 100 MB."}), 413


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def to_jsonable(o: Any) -> Any:
    """Recursively convert objects to JSON-serializable structures.
    - dict -> dict with jsonable values
    - list/tuple/set -> list
    - Path -> str
    - bytes -> utf-8 string (errors ignored)
    - other objects -> str(o)
    """
    from collections.abc import Mapping, Iterable

    if o is None or isinstance(o, (bool, int, float, str)):
        return o
    if isinstance(o, Path):
        return str(o)
    if isinstance(o, bytes):
        try:
            return o.decode("utf-8", errors="ignore")
        except Exception:
            return str(o)
    if isinstance(o, Mapping):
        return {str(k): to_jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [to_jsonable(i) for i in o]
    # Fallback: string representation
    try:
        return str(o)
    except Exception:
        return repr(o)


def analyze_apk(apk_path: Path) -> Dict[str, Any]:
    if not ANDRO_OK:
        return {
            "ok": False,
            "error": "Androguard is not installed. Please install dependencies from requirements.txt",
        }

    try:
        a = APK(str(apk_path))
    except Exception as e:
        return {"ok": False, "error": f"Failed to parse APK: {e}"}

    findings: Dict[str, Any] = {"ok": True}

    # Basic metadata
    findings["package_name"] = a.get_package()
    findings["app_name"] = a.get_app_name()
    findings["version_name"] = a.get_androidversion_name()
    findings["version_code"] = a.get_androidversion_code()

    # Debuggable flag
    try:
        findings["debuggable"] = bool(a.is_debuggable())
    except Exception:
        findings["debuggable"] = None

    # Permissions
    permissions = sorted(set(a.get_permissions() or []))
    findings["permissions"] = permissions

    dangerous_perm_prefixes = (
        "android.permission.SEND_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.CALL_PHONE",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.CAMERA",
    )
    dangerous_perms = [p for p in permissions if any(p.startswith(dp) for dp in dangerous_perm_prefixes)]
    findings["dangerous_permissions"] = sorted(dangerous_perms)

    # Receivers / Services that may indicate background behavior
    try:
        findings["receivers"] = a.get_receivers() or []
    except Exception:
        findings["receivers"] = []

    try:
        findings["services"] = a.get_services() or []
    except Exception:
        findings["services"] = []

    try:
        findings["activities"] = a.get_activities() or []
    except Exception:
        findings["activities"] = []

    # URL extraction from manifest and files (very lightweight)
    urls: List[str] = []
    url_regex = re.compile(r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)

    # Search in manifest xml
    try:
        manifest_xml = a.get_android_manifest_xml().toxml() if hasattr(a.get_android_manifest_xml(), 'toxml') else str(a.get_android_manifest_xml())
        urls += url_regex.findall(manifest_xml or "")
    except Exception:
        pass

    # Search in file names within APK
    try:
        for f in a.get_files():
            if isinstance(f, str):
                urls += url_regex.findall(f)
    except Exception:
        pass

    # Deduplicate urls
    urls = sorted(set(urls))
    findings["urls"] = urls

    # Cert info (coarse)
    try:
        certs = a.get_certificates()
        cert_list = []
        for c in (certs or []):
            try:
                issuer = getattr(c, "issuer", None)
                subject = getattr(c, "subject", None)
                serial = getattr(c, "serial_number", None)
                cert_list.append({
                    "issuer": str(issuer) if issuer is not None else None,
                    "subject": str(subject) if subject is not None else None,
                    "serial_number": str(serial) if serial is not None else None,
                })
            except Exception:
                cert_list.append(str(c))
        findings["certificates"] = cert_list
    except Exception:
        findings["certificates"] = []

    # Very simple risk scoring
    risk = 0
    reasons = []

    if findings.get("debuggable"):
        risk += 1
        reasons.append("App is debuggable (should be disabled in release builds)")
    if len(dangerous_perms) >= 3:
        risk += 2
        reasons.append("Multiple dangerous permissions declared")
    elif len(dangerous_perms) > 0:
        risk += 1
        reasons.append("Some dangerous permissions declared")
    if len(urls) > 10:
        risk += 1
        reasons.append("Lots of embedded URLs (possible trackers/endpoints)")
    if any("SYSTEM_ALERT_WINDOW" in p for p in dangerous_perms):
        risk += 1
        reasons.append("Can draw over other apps (SYSTEM_ALERT_WINDOW)")
    if any("REQUEST_INSTALL_PACKAGES" in p for p in dangerous_perms):
        risk += 1
        reasons.append("Can request to install packages (side-loading)")

    # Cap and map to label
    risk = max(0, min(10, risk))
    if risk <= 2:
        label = "Low"
    elif risk <= 5:
        label = "Medium"
    else:
        label = "High"

    findings["risk_score"] = risk
    findings["risk_label"] = label
    findings["risk_reasons"] = reasons

    # Final recommendation based on risk
    if label == "High":
        recommendation = "Install caution is advised (High risk)."
        recommendation_reason = "Dangerous permissions or behavior detected. Avoid installing from untrusted sources."
    elif label == "Medium":
        recommendation = "Recommended installation (Medium risk)."
        recommendation_reason = "Multiple risk factors detected. Verify the source and review permissions before installation."
    else:
        recommendation = "Generally safe (Low risk)."
        recommendation_reason = "No significant risk factors detected. Verify the source."

    findings["recommendation"] = recommendation
    findings["recommendation_reason"] = recommendation_reason

    return findings


@app.route("/", methods=["GET"]) 
def index():
    return render_template("index.html")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


 


@app.route("/upload", methods=["POST"]) 
def upload():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"ok": False, "error": "No selected file"}), 400

    if not allowed_file(file.filename):
        return jsonify({"ok": False, "error": "Only .apk files are allowed"}), 400

    filename = secure_filename(file.filename)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    save_name = f"{ts}_{filename}"
    save_path = UPLOAD_DIR / save_name
    file.save(str(save_path))

    results = analyze_apk(save_path)
    results["filename"] = filename

    # Optionally compute SHA-256 if you want to display it later (VT removed)
    try:
        results["sha256"] = sha256_file(save_path)
    except Exception:
        pass

    # Ensure JSON-serializable
    safe_results = to_jsonable(results)
    return jsonify(safe_results)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
