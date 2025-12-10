# app.py
import os
import json
import hashlib
import zipfile
import secrets
import shutil
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, session, send_from_directory, abort, flash, request

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ========================= CONFIG =========================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(BASE_DIR, "static", "uploads")
DB_DIR = os.path.join(BASE_DIR, "database")
DOMAIN = "teamdev.sbs"

# Hardcoded Admin (CHANGE THIS PASSWORD!)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "TeamDev2025!@#Secure"   # CHANGE THIS!

app.config["SERVER_NAME"] = "teamdev.sbs"

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
    with open(path, "r") as f: return json.load(f)
def save_json(path, data): 
    with open(path, "w") as f: json.dump(data, f, indent=2)

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
    logs.append({"user": user or "system", "action": action, "details": details, "time": datetime.now().isoformat()})
    save_logs(logs[-1000:])

def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()

# ========================= ROUTES =========================
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/auth/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]

        # Admin login
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["user"] = ADMIN_USERNAME
            session["is_admin"] = True
            log_action(ADMIN_USERNAME, "admin_login")
            return redirect("/admin")

        users = get_users()
        user = users.get(username)
        if user and not user.get("banned") and user["password"] == hash_password(password):
            session["user"] = username
            session["is_admin"] = user.get("is_admin", False)
            log_action(username, "login")
            return redirect("/dashboard")
        flash("Invalid credentials or banned account", "error")
    return render_template("login.html")

@app.route("/auth/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        email = request.form["email"].strip()
        password = request.form["password"]
        if len(password) < 6:
            flash("Password too short", "error"); return redirect("/auth/signup")

        users = get_users()
        if username in users:
            flash("Username taken", "error"); return redirect("/auth/signup")

        users[username] = {
            "email": email, "password": hash_password(password),
            "created_at": datetime.now().strftime("%Y-%m-%d"),
            "is_admin": False, "banned": False, "warnings": []
        }
        save_users(users)
        log_action("system", "signup", username)
        flash("Account created! Login now", "success")
        return redirect("/auth/login")
    return render_template("signup.html")

@app.route("/auth/logout")
def logout():
    log_action(session.get("user"), "logout")
    session.clear()
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    if "user" not in session: return redirect("/auth/login")
    sites = [s for s in get_sites().values() if s["owner"] == session["user"]]
    return render_template("dashboard.html", username=session["user"], sites=sites, DOMAIN=DOMAIN)

@app.route("/dashboard/upload", methods=["GET", "POST"])
def upload_site():
    if "user" not in session: return redirect("/auth/login")
    if request.method == "POST":
        sitename = request.form["sitename"].strip().lower()
        if not sitename.replace("-", "").isalnum():
            flash("Only letters, numbers and - allowed", "error")
            return redirect("/dashboard/upload")

        if any(s["sitename"] == sitename for s in get_sites().values()):
            flash("Sitename already taken!", "error")
            return redirect("/dashboard/upload")

        file = request.files["file"]
        if not file.filename.endswith(".zip"):
            flash("Only .zip files allowed", "error")
            return redirect("/dashboard/upload")

        path = os.path.join(UPLOAD_ROOT, sitename)
        os.makedirs(path, exist_ok=True)
        with zipfile.ZipFile(file) as z:
            z.extractall(path)

        get_sites()[str(len(get_sites()))] = {
            "sitename": sitename, "owner": session["user"],
            "uploaded_at": datetime.now().isoformat(),
            "paused": False, "banned": False
        }
        save_sites(get_sites())
        log_action(session["user"], "upload", sitename)
        flash(f"Site live → https://{sitename}.{DOMAIN}", "success")
        return redirect("/dashboard")
    return render_template("upload.html")

@app.route("/dashboard/delete/<sitename>", methods=["POST"])
def delete_site(sitename):
    if "user" not in session: return abort(403)
    sites = {k:v for k,v in get_sites().items() if v["sitename"] != sitename or v["owner"] != session["user"]}
    save_sites(sites)
    shutil.rmtree(os.path.join(UPLOAD_ROOT, sitename), ignore_errors=True)
    flash("Site deleted", "info")
    return redirect("/dashboard")

@app.route("/dashboard/toggle/<sitename>", methods=["POST"])
def toggle_site(sitename):
    if "user" not in session: return abort(403)
    for s in get_sites().values():
        if s["sitename"] == sitename and s["owner"] == session["user"]:
            s["paused"] = not s.get("paused", False)
            save_sites(get_sites())
            break
    return redirect("/dashboard")

# ========================= SITE SERVING (SUBDOMAIN) =========================
@app.route("/", subdomain="<sitename>")
@app.route("/<path:subpath>", subdomain="<sitename>")
def subdomain_site(sitename, subpath=""):
    return serve_site(sitename, subpath)

@app.route("/<sitename>")
@app.route("/<sitename>/<path:subpath>")
def serve_site(sitename, subpath=""):
    site = next((s for s in get_sites().values() if s["sitename"] == sitename), None)
    if not site or site.get("banned") or site.get("paused"):
        return render_template("404.html", sitename=sitename), 404

    path = os.path.join(UPLOAD_ROOT, sitename, subpath) if subpath else os.path.join(UPLOAD_ROOT, sitename)
    
    # Analytics
    analytics = get_analytics()
    analytics.setdefault(sitename, []).append({
        "ip": request.remote_addr, "path": request.path,
        "ua": request.headers.get("User-Agent"), "time": datetime.now().isoformat()
    })
    save_analytics(analytics)

    if os.path.isfile(path):
        return send_from_directory(os.path.dirname(path), os.path.basename(path))
    if os.path.isdir(path) and os.path.isfile(os.path.join(path, "index.html")):
        return send_from_directory(path, "index.html")
    return render_template("404.html", sitename=sitename), 404

# ========================= ADMIN =========================
@app.route("/admin")
def admin_panel():
    if session.get("user") != ADMIN_USERNAME:
        return redirect("/auth/login")
    return render_template("admin.html",
        users=get_users(), sites=list(get_sites().values()),
        logs=get_logs()[-100:], total_users=len(get_users()), total_sites=len(get_sites())
    )

# (Add ban/warn routes if you want – same as before)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
