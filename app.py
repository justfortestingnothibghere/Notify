# app.py
import os
import json
import hashlib
import zipfile
import secrets
import shutil
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, session, send_from_directory, abort, flash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ========================= CONFIG =========================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(BASE_DIR, "static", "uploads")
DB_DIR = os.path.join(BASE_DIR, "database")
DOMAIN = "teamdev.sbs"

# Hardcoded Admin - CHANGE THIS IN PRODUCTION!
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "TeamDev2025!@#Secure"  # CHANGE THIS!

# DO NOT SET SERVER_NAME HERE WHEN USING CUSTOM DOMAINS ON RENDER
# Remove this line completely for Render.com + wildcard domains
# app.config["SERVER_NAME"] = "teamdev.sbs"   ← REMOVED (this was breaking everything)

os.makedirs(UPLOAD_ROOT, exist_ok=True)
os.makedirs(DB_DIR, exist_ok=True)

DB = {
    "users": os.path.join(DB_DIR, "users.json"),
    "sites": os.path.join(DB_DIR, "sites.json"),
    "analytics": os.path.join(DB_DIR, "analytics.json"),
    "logs": os.path.join(DB_DIR, "logs.json")
}

for path in DB.values():
    if not os.path.exists(path):
        default = {} if "analytics" not in path and "logs" not in path else ([] if "logs" in path else {})
        with open(path, "w") as f:
            json.dump(default, f, indent=2)

# ========================= HELPERS =========================
def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {} if "analytics" not in path and "logs" not in path else []

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def get_users(): return load_json(DB["users"])
def get_sites(): return load_json(DB["sites"])
def get_analytics(): return load_json(DB["analytics"])
def get_logs(): return load_json(DB["logs"])

def save_users(d): save_json(DB["users"], d)
def save_sites(d): save_json(DB["sites"], d)
def save_analytics(d): save_json(DB["analytics"], d)
def save_logs(d): save_json(DB["logs"], d)

def log_action(user, action, details=""):
    logs = get_logs()
    logs.append({
        "user": user or "anonymous",
        "action": action,
        "details": str(details),
        "time": datetime.now().isoformat(),
        "ip": request.remote_addr if request else "unknown"
    })
    save_logs(logs[-1000:])  # Keep last 1000 logs

def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()

# ========================= DYNAMIC SUBDOMAIN HANDLING =========================
def get_subdomain():
    host = request.host.lower()
    if host.endswith(f".{DOMAIN}"):
        return host[:-len(f".{DOMAIN}")].split(":")[0]  # Remove port if any
    return None

# ========================= ROUTES =========================
@app.route("/")
def home():
    subdomain = get_subdomain()
    if subdomain:
        return serve_site(subdomain, "")
    return render_template("index.html")  # Main marketing page

@app.route("/<path:path>")
def catch_all(path):
    subdomain = get_subdomain()
    if subdomain:
        return serve_site(subdomain, path)
    # If no subdomain, treat as main site routes (dashboard, login, etc.)
    return redirect("/")

# ========================= AUTH =========================
@app.route("/auth/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Missing credentials", "error")
            return redirect("/auth/login")

        # Admin Login
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["user"] = ADMIN_USERNAME
            session["is_admin"] = True
            log_action(ADMIN_USERNAME, "admin_login_success")
            return redirect("/admin")

        users = get_users()
        user_data = users.get(username, {})

        if user_data.get("banned"):
            flash("Account is banned", "error")
        elif user_data and user_data["password"] == hash_password(password):
            session["user"] = username
            session["is_admin"] = user_data.get("is_admin", False)
            log_action(username, "login_success")
            return redirect("/dashboard")
        else:
            flash("Invalid username or password", "error")
            log_action(None, "login_failed", f"User: {username}")

    return render_template("login.html")

@app.route("/auth/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not all([username, email, password]):
            flash("All fields required", "error"); return redirect("/auth/signup")
        if len(password) < 6:
            flash("Password must be 6+ chars", "error"); return redirect("/auth/signup")
        if not username.replace("-", "").isalnum():
            flash("Username: letters, numbers, - only", "error"); return redirect("/auth/signup")

        users = get_users()
        if username in users:
            flash("Username already taken", "error"); return redirect("/auth/signup")

        users[username] = {
            "email": email,
            "password": hash_password(password),
            "created_at": datetime.now().strftime("%Y-%m-%d"),
            "is_admin": False,
            "banned": False,
            "warnings": []
        }
        save_users(users)
        log_action("system", "user_signup", username)
        flash("Account created! Please login.", "success")
        return redirect("/auth/login")

    return render_template("signup.html")

@app.route("/auth/logout")
def logout():
    user = session.get("user", "unknown")
    session.clear()
    log_action(user, "logout")
    return redirect("/")

# ========================= USER DASHBOARD =========================
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/auth/login")

    all_sites = get_sites()
    user_sites = [s for s in all_sites.values() if s["owner"] == session["user"]]
    return render_template("dashboard.html", username=session["user"], sites=user_sites, DOMAIN=DOMAIN)

# === REPLACE ONLY THIS ROUTE IN YOUR app.py ===
@app.route("/dashboard/upload", methods=["GET", "POST"])
def upload_site():
    if "user" not in session:
        return redirect("/auth/login")

    if request.method == "POST":
        sitename = request.form.get("sitename", "").strip().lower()
        
        if not sitename or not sitename.replace("-", "").replace("_", "").isalnum():
            flash("Invalid sitename: only letters, numbers, - and _ allowed", "error")
            return redirect("/dashboard/upload")

        if any(s["sitename"] == sitename for s in get_sites().values()):
            flash("Sitename already taken!", "error")
            return redirect("/dashboard/upload")

        upload_dir = os.path.join(UPLOAD_ROOT, sitename)
        os.makedirs(upload_dir, exist_ok=True)

        files = request.files.getlist("files[]")
        paths = request.form.getlist("paths[]")

        if not files or len(files) == 0:
            shutil.rmtree(upload_dir, ignore_errors=True)
            flash("No files uploaded", "error")
            return redirect("/dashboard/upload")

        uploaded_files = 0
        for file, relative_path in zip(files, paths):
            if file.filename == '' or file.filename == '.':
                continue

            # Clean and build full path
            relative_path = relative_path.replace("\\", "/").strip("/")
            safe_path = os.path.join(upload_dir, relative_path)
            safe_dir = os.path.dirname(safe_path)

            os.makedirs(safe_dir, exist_ok=True)

            # Security: prevent directory traversal
            if not os.path.abspath(safe_path).startswith(os.path.abspath(upload_dir)):
                continue

            file.save(safe_path)
            uploaded_files += 1

        if uploaded_files == 0:
            shutil.rmtree(upload_dir, ignore_errors=True)
            flash("No valid files were uploaded", "error")
            return redirect("/dashboard/upload")

        # Save site info
        sites = get_sites()
        sites[str(len(sites))] = {
            "sitename": sitename,
            "owner": session["user"],
            "uploaded_at": datetime.now().isoformat(),
            "paused": False,
            "banned": False
        }
        save_sites(sites)
        log_action(session["user"], "folder_uploaded", f"{sitename} ({uploaded_files} files)")

        flash(f"Site deployed successfully! → https://{sitename}.{DOMAIN}", "success")
        return redirect("/dashboard")

    return render_template("upload.html", DOMAIN=DOMAIN)

@app.route("/dashboard/delete/<sitename>", methods=["POST"])
def delete_site(sitename):
    if "user" not in session:
        return abort(403)
    sites = get_sites()
    new_sites = {k: v for k, v in sites.items() if not (v["sitename"] == sitename and v["owner"] == session["user"])}
    if len(new_sites) < len(sites):
        save_sites(new_sites)
        shutil.rmtree(os.path.join(UPLOAD_ROOT, sitename), ignore_errors=True)
        log_action(session["user"], "site_deleted", sitename)
        flash("Site deleted successfully", "success")
    return redirect("/dashboard")

@app.route("/dashboard/toggle/<sitename>", methods=["POST"])
def toggle_site(sitename):
    if "user" not in session:
        return abort(403)
    sites = get_sites()
    for site in sites.values():
        if site["sitename"] == sitename and site["owner"] == session["user"]:
            site["paused"] = not site.get("paused", False)
            save_sites(sites)
            log_action(session["user"], "site_toggled", f"{sitename} → {'paused' if site['paused'] else 'resumed'}")
            break
    return redirect("/dashboard")

# ========================= SITE SERVING (Main Fix) =========================
def serve_site(sitename, subpath=""):
    sites = get_sites()
    site = next((s for s in sites.values() if s["sitename"] == sitename), None)

    if not site or site.get("banned") or site.get("paused"):
        return render_template("404.html", sitename=sitename), 404

    file_path = os.path.join(UPLOAD_ROOT, sitename, subpath) if subpath else os.path.join(UPLOAD_ROOT, sitename)
    dir_path = os.path.dirname(file_path) if os.path.basename(file_path) else file_path

    # Log visit
    analytics = get_analytics()
    analytics.setdefault(sitename, []).append({
        "ip": request.remote_addr,
        "path": request.full_path,
        "ua": request.headers.get("User-Agent"),
        "time": datetime.now().isoformat()
    })
    analytics[sitename] = analytics[sitename][-1000:]  # Limit per site
    save_analytics(analytics)

    if os.path.isfile(file_path):
        return send_from_directory(dir_path, os.path.basename(file_path))
    if os.path.isdir(file_path):
        index_path = os.path.join(file_path, "index.html")
        if os.path.isfile(index_path):
            return send_from_directory(file_path, "index.html")
    return render_template("404.html", sitename=sitename), 404

# ========================= ADMIN PANEL =========================
@app.route("/admin")
def admin_panel():
    if session.get("user") != ADMIN_USERNAME or not session.get("is_admin"):
        flash("Access denied", "error")
        return redirect("/auth/login")

    return render_template("admin.html",
        users=get_users(),
        sites=list(get_sites().values()),
        logs=get_logs()[-200:],
        total_users=len(get_users()),
        total_sites=len(get_sites())
    )

# ========================= RUN =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
