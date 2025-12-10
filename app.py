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

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "TeamDev2025!@#Secure"

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

# ========================= SUBDOMAIN HANDLING =========================
def get_subdomain():
    host = request.host.lower()
    sub = None
    if host.endswith(f".{DOMAIN}"):
        sub = host[:-len(f".{DOMAIN}")].split(":")[0]
    print(f"[DEBUG] HOST: {host} | SUBDOMAIN: {sub}")
    return sub

# ========================= ROUTES =========================
@app.route("/")
def home():
    subdomain = get_subdomain()
    if subdomain:
        return serve_site(subdomain, "")
    return render_template("index.html")

@app.route("/<path:path>")
def catch_all(path):
    subdomain = get_subdomain()
    if subdomain:
        return serve_site(subdomain, path)
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
            flash("Username already taken!", "error"); return redirect("/auth/signup")

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

# ========================= DASHBOARD =========================
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/auth/login")
    all_sites = get_sites()
    user_sites = [s for s in all_sites.values() if s["owner"] == session["user"]]
    return render_template("dashboard.html", username=session["user"], sites=user_sites, DOMAIN=DOMAIN)

# ========================= UPLOAD SITE =========================
@app.route("/dashboard/upload", methods=["GET", "POST"])
def upload_site():
    if "user" not in session:
        return redirect("/auth/login")

    if request.method == "POST":
        sitename = request.form.get("sitename", "").strip().lower()
        
        if not sitename or not sitename.replace("-", "").replace("_", "").isalnum():
            flash("Invalid sitename", "error")
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
            if file.filename in ('', '.'):
                continue
            relative_path = relative_path.replace("\\", "/").strip("/")
            safe_path = os.path.join(upload_dir, relative_path)
            safe_dir = os.path.dirname(safe_path)
            os.makedirs(safe_dir, exist_ok=True)
            if not os.path.abspath(safe_path).startswith(os.path.abspath(upload_dir)):
                continue
            file.save(safe_path)
            uploaded_files += 1

        if uploaded_files == 0:
            shutil.rmtree(upload_dir, ignore_errors=True)
            flash("No valid files uploaded", "error")
            return redirect("/dashboard/upload")

        # Flatten if zip contains a top-level folder
        for entry in os.listdir(upload_dir):
            entry_path = os.path.join(upload_dir, entry)
            if os.path.isdir(entry_path):
                for root, dirs, files_ in os.walk(entry_path):
                    for f in files_:
                        src = os.path.join(root, f)
                        dst = os.path.join(upload_dir, os.path.relpath(src, entry_path))
                        shutil.move(src, dst)
                shutil.rmtree(entry_path)

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

# ========================= SITE SERVING =========================
def serve_site(sitename, subpath=""):
    sites = get_sites()
    site = next((s for s in sites.values() if s["sitename"] == sitename), None)

    if not site or site.get("banned") or site.get("paused"):
        return render_template("404.html", sitename=sitename), 404

    # Default path
    file_path = os.path.join(UPLOAD_ROOT, sitename, subpath)
    print(f"[DEBUG] SERVE_SITE: file_path={file_path}")

    if os.path.isdir(file_path):
        index_path = os.path.join(file_path, "index.html")
        if os.path.isfile(index_path):
            return send_from_directory(file_path, "index.html")
    elif os.path.isfile(file_path):
        dir_path = os.path.dirname(file_path)
        return send_from_directory(dir_path, os.path.basename(file_path))

    # Check for index.html at root if subpath empty
    root_index = os.path.join(UPLOAD_ROOT, sitename, "index.html")
    if os.path.isfile(root_index):
        return send_from_directory(os.path.join(UPLOAD_ROOT, sitename), "index.html")

    print(f"[DEBUG] 404: {file_path}")
    return render_template("404.html", sitename=sitename), 404

# ========================= ERROR ROUTE /er =========================
@app.route("/dashboard/logs")
def error_route():
    subdomain = get_subdomain()
    if not subdomain:
        return "No subdomain detected."

    site_dir = os.path.join(UPLOAD_ROOT, subdomain)
    if not os.path.exists(site_dir):
        return f"No files uploaded for site {subdomain}"

    all_files = []
    for root, dirs, files in os.walk(site_dir):
        for f in files:
            all_files.append(os.path.relpath(os.path.join(root, f), site_dir))
    return "<br>".join(all_files) or "No files found"

@app.route("/admin")
def admin_panel():
    if session.get("user") != ADMIN_USERNAME or not session.get("is_admin"):
        flash("Access denied", "error")
        return redirect("/auth/login")

    users = get_users()
    sites = list(get_sites().values())

    # Count sites per user
    from collections import Counter
    owner_counts = Counter(s["owner"] for s in sites)
    active_sites = sum(1 for s in sites if not s.get("paused") and not s.get("banned"))
    banned_users = sum(1 for u in users.values() if u.get("banned"))

    return render_template("admin.html",
        users=users,
        sites=sites,
        logs=get_logs()[-50:],
        total_users=len(users),
        total_sites=len(sites),
        active_sites=active_sites,
        banned_users=banned_users,
        user_site_count=owner_counts,
        DOMAIN=DOMAIN
    )


# ========================= ADMIN ACTIONS =========================
@app.route("/admin/ban_user/<username>")
def ban_user(username):
    if not is_admin(): return redirect("/auth/login")
    users = get_users()
    if username in users:
        users[username]["banned"] = True
        save_users(users)
        log_action(session["user"], "admin_ban_user", username)
        flash(f"User {username} banned")
    return redirect("/admin")

@app.route("/admin/unban_user/<username>")
def unban_user(username):
    if not is_admin(): return redirect("/auth/login")
    users = get_users()
    if username in users:
        users[username]["banned"] = False
        save_users(users)
        log_action(session["user"], "admin_unban_user", username)
    return redirect("/admin")

@app.route("/admin/pause_site/<sitename>")
def pause_site(sitename):
    if not is_admin(): return redirect("/auth/login")
    sites = get_sites()
    for k, s in sites.items():
        if s["sitename"] == sitename:
            sites[k]["paused"] = True
            save_sites(sites)
            log_action(session["user"], "admin_pause_site", sitename)
            break
    return redirect("/admin")

@app.route("/admin/resume_site/<sitename>")
def resume_site(sitename):
    if not is_admin(): return redirect("/auth/login")
    sites = get_sites()
    for k, s in sites.items():
        if s["sitename"] == sitename:
            sites[k]["paused"] = False
            save_sites(sites)
            log_action(session["user"], "admin_resume_site", sitename)
            break
    return redirect("/admin")

@app.route("/admin/delete_site/<sitename>")
def delete_site(sitename):
    if not is_admin(): return redirect("/auth/login")
    sites = get_sites()
    new_sites = {}
    deleted = False
    for k, s in sites.items():
        if s["sitename"] == sitename:
            shutil.rmtree(os.path.join(UPLOAD_ROOT, sitename), ignore_errors=True)
            log_action(session["user"], "admin_delete_site", f"{sitename} by {s['owner']}")
            deleted = True
        else:
            new_sites[k] = s
    if deleted:
        save_sites(new_sites)
        flash(f"Site {sitename} deleted permanently")
    return redirect("/admin")

@app.route("/admin/export/users")
def export_users():
    if not is_admin(): abort(403)
    return app.response_class(
        json.dumps(get_users(), indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=users.json"}
    )

@app.route("/admin/export/sites")
def export_sites():
    if not is_admin(): abort(403)
    return app.response_class(
        json.dumps(list(get_sites().values()), indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=sites.json"}
    )

@app.route("/admin/clear-logs")
def clear_logs():
    if not is_admin(): abort(403)
    save_logs([])
    log_action(session["user"], "admin_clear_logs")
    return redirect("/admin")

# Helper
def is_admin():
    return session.get("user") == ADMIN_USERNAME and session.get("is_admin")


# ========================= RUN =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
