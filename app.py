# app.py
import os
import json
import hashlib
import zipfile
import secrets
import shutil
from datetime import datetime
from flask import Flask, request, render_template_string, redirect, url_for, session, send_from_directory, abort, flash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# ----------------------------------------------------------------------
# PATHS & DB
# ----------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(BASE_DIR, "static", "uploads")
DB_DIR = os.path.join(BASE_DIR, "database")

os.makedirs(UPLOAD_ROOT, exist_ok=True)
os.makedirs(DB_DIR, exist_ok=True)

DB = {
    "users": os.path.join(DB_DIR, "users.json"),
    "sites": os.path.join(DB_DIR, "sites.json"),
    "analytics": os.path.join(DB_DIR, "analytics.json"),
    "logs": os.path.join(DB_DIR, "logs.json")
}

# Initialize DB
for path in DB.values():
    if not os.path.exists(path):
        default = {} if "analytics" not in path and "logs" not in path else []
        with open(path, "w") as f:
            json.dump(default, f, indent=2)

def load_json(path): 
    with open(path, "r") as f: 
        return json.load(f)
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
        "user": user,
        "action": action,
        "details": details,
        "timestamp": datetime.now().isoformat()
    })
    save_logs(logs[-1000:])  # Keep last 1000 logs

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

# ----------------------------------------------------------------------
# MAINTENANCE MODE
# ----------------------------------------------------------------------
MAINTENANCE = False

@app.before_request
def check_maintenance():
    if MAINTENANCE and request.path not in ['/admin', '/auth/login', '/auth/logout'] and 'admin' not in session:
        return render_template_string(TEMPLATES["maintenance"]), 503

# ----------------------------------------------------------------------
# AUTH
# ----------------------------------------------------------------------
@app.route("/auth/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        email = request.form["email"].strip()
        password = request.form["password"]

        users = get_users()
        if username in users:
            flash("Username already exists!")
            return redirect(url_for("signup"))

        users[username] = {
            "email": email,
            "password": hash_password(password),
            "created_at": datetime.now().strftime("%Y-%m-%d"),
            "is_admin": False,
            "banned": False,
            "warnings": []
        }
        save_users(users)
        log_action("system", "signup", f"New user: {username}")
        flash("Account created! Please login.")
        return redirect(url_for("login"))

    return render_template_string(TEMPLATES["signup"])

@app.route("/auth/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        users = get_users()
        user = users.get(username)

        if user and not user.get("banned") and user["password"] == hash_password(password):
            session["user"] = username
            session["is_admin"] = user.get("is_admin", False)
            log_action(username, "login")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials or banned account.")
    return render_template_string(TEMPLATES["login"])

@app.route("/auth/logout")
def logout():
    user = session.get("user")
    if user:
        log_action(user, "logout")
    session.clear()
    return redirect(url_for("home"))

# ----------------------------------------------------------------------
# HOME & PAGES
# ----------------------------------------------------------------------
@app.route("/")
def home():
    return render_template_string(TEMPLATES["index"])

@app.route("/pricing")
def pricing():
    return render_template_string(TEMPLATES["pricing"])

@app.route("/projects")
def projects():
    return render_template_string(TEMPLATES["projects"])

# ----------------------------------------------------------------------
# USER DASHBOARD
# ----------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    username = session["user"]
    users = get_users()
    user_data = users.get(username, {})
    sites = [s for s in get_sites().values() if s["owner"] == username and not s.get("paused", False)]
    paused = [s for s in get_sites().values() if s["owner"] == username and s.get("paused", False)]

    return render_template_string(TEMPLATES["dashboard"],
        username=username, sites=sites, paused=paused, warnings=user_data.get("warnings", []))

# ----------------------------------------------------------------------
# UPLOAD SITE
# ----------------------------------------------------------------------
@app.route("/dashboard/upload", methods=["GET", "POST"])
def upload_site():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        sitename = request.form["sitename"].strip().lower()
        if not sitename.replace("-", "").replace("_", "").isalnum():
            flash("Invalid sitename. Use letters, numbers, - _")
            return redirect(url_for("upload_site"))

        sites = get_sites()
        if any(s["sitename"] == sitename for s in sites.values()):
            flash("Sitename already taken!")
            return redirect(url_for("upload_site"))

        upload_dir = os.path.join(UPLOAD_ROOT, sitename)
        os.makedirs(upload_dir, exist_ok=True)

        file = request.files["file"]
        if file.filename.endswith(".zip"):
            with zipfile.ZipFile(file) as z:
                z.extractall(upload_dir)
        else:
            file.save(os.path.join(upload_dir, file.filename))

        # Auto-find index.html
        index_found = any(
            f.lower() == "index.html"
            for root, _, files in os.walk(upload_dir)
            for f in files
        )

        sites[str(len(sites))] = {
            "sitename": sitename,
            "owner": session["user"],
            "uploaded_at": datetime.now().isoformat(),
            "paused": False,
            "banned": False,
            "index_found": index_found
        }
        save_sites(sites)
        log_action(session["user"], "upload_site", sitename)
        flash(f"Site '{sitename}' uploaded!")
        return redirect(url_for("dashboard"))

    return render_template_string(TEMPLATES["upload"])

# ----------------------------------------------------------------------
# SITE ACTIONS
# ----------------------------------------------------------------------
@app.route("/dashboard/delete/<sitename>", methods=["POST"])
def delete_site(sitename):
    if "user" not in session: return "No", 403
    sites = get_sites()
    site = next((s for s in sites.values() if s["sitename"] == sitename and s["owner"] == session["user"]), None)
    if not site: return "Not found", 404

    # Remove from DB
    new_sites = {k: v for k, v in sites.items() if v["sitename"] != sitename}
    save_sites(new_sites)

    # Remove files
    path = os.path.join(UPLOAD_ROOT, sitename)
    if os.path.exists(path):
        shutil.rmtree(path)

    log_action(session["user"], "delete_site", sitename)
    flash(f"Site '{sitename}' deleted.")
    return redirect(url_for("dashboard"))

@app.route("/dashboard/pause/<sitename>", methods=["POST"])
def pause_site(sitename):
    if "user" not in session: return "No", 403
    sites = get_sites()
    for k, s in sites.items():
        if s["sitename"] == sitename and s["owner"] == session["user"]:
            s["paused"] = not s.get("paused", False)
            save_sites(sites)
            action = "paused" if s["paused"] else "unpaused"
            log_action(session["user"], action + "_site", sitename)
            break
    return redirect(url_for("dashboard"))

@app.route("/dashboard/rename/<old>", methods=["POST"])
def rename_site(old):
    if "user" not in session: return "No", 403
    new = request.form["new_name"].strip().lower()
    if not new.replace("-", "").replace("_", "").isalnum():
        flash("Invalid name")
        return redirect(url_for("dashboard"))

    sites = get_sites()
    if any(s["sitename"] == new for s in sites.values()):
        flash("Name taken")
        return redirect(url_for("dashboard"))

    for k, s in sites.items():
        if s["sitename"] == old and s["owner"] == session["user"]:
            old_path = os.path.join(UPLOAD_ROOT, old)
            new_path = os.path.join(UPLOAD_ROOT, new)
            if os.path.exists(old_path):
                os.rename(old_path, new_path)
            s["sitename"] = new
            save_sites(sites)
            log_action(session["user"], "rename_site", f"{old} → {new}")
            break
    return redirect(url_for("dashboard"))

# ----------------------------------------------------------------------
# ANALYTICS
# ----------------------------------------------------------------------
@app.route("/dashboard/analytics/<sitename>")
def site_analytics(sitename):
    if "user" not in session:
        return redirect(url_for("login"))

    sites = get_sites()
    if not any(s["sitename"] == sitename and s["owner"] == session["user"] for s in sites.values()):
        return "Not yours", 403

    data = get_analytics().get(sitename, [])
    total = len(data)
    unique = len({d["ip"] for d in data})
    paths = {}
    for d in data:
        paths[d["path"]] = paths.get(d["path"], 0) + 1

    return render_template_string(TEMPLATES["analytics"],
        sitename=sitename, total=total, unique=unique, paths=paths, recent=data[-20:])

# ----------------------------------------------------------------------
# SERVE USER SITES
# ----------------------------------------------------------------------
@app.route("/<sitename>")
@app.route("/<sitename>/<path:subpath>")
def serve_site(sitename, subpath=""):
    sites = get_sites()
    site = next((s for s in sites.values() if s["sitename"] == sitename), None)
    if not site or site.get("banned") or site.get("paused"):
        return render_template_string(TEMPLATES["404"]), 404

    site_path = os.path.join(UPLOAD_ROOT, sitename)
    if not os.path.exists(site_path):
        return render_template_string(TEMPLATES["404"]), 404

    # Log visit
    analytics = get_analytics()
    if sitename not in analytics:
        analytics[sitename] = []
    analytics[sitename].append({
        "ip": request.remote_addr,
        "path": "/" + subpath,
        "ua": request.headers.get("User-Agent", ""),
        "ref": request.referrer or "direct",
        "timestamp": datetime.now().isoformat()
    })
    save_analytics(analytics)

    full_path = os.path.join(site_path, subpath) if subpath else site_path

    if os.path.isfile(full_path):
        return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path))

    index_path = os.path.join(full_path, "index.html")
    if os.path.isfile(index_path):
        return send_from_directory(full_path, "index.html")

    return render_template_string(TEMPLATES["404"]), 404

# ----------------------------------------------------------------------
# ADMIN PANEL
# ----------------------------------------------------------------------
@app.route("/admin")
def admin_panel():
    if not session.get("is_admin"):
        return "Access Denied", 403

    users = get_users()
    sites = get_sites()
    logs = get_logs()
    return render_template_string(TEMPLATES["admin"],
        users=users, sites=sites, logs=logs[-50:], maintenance=MAINTENANCE)

@app.route("/admin/toggle_maintenance", methods=["POST"])
def toggle_maintenance():
    if not session.get("is_admin"): return "No", 403
    global MAINTENANCE
    MAINTENANCE = not MAINTENANCE
    log_action(session["user"], "maintenance", "ON" if MAINTENANCE else "OFF")
    return redirect(url_for("admin_panel"))

@app.route("/admin/ban_site/<sitename>", methods=["POST"])
def ban_site(sitename):
    if not session.get("is_admin"): return "No", 403
    sites = get_sites()
    for k, s in sites.items():
        if s["sitename"] == sitename:
            s["banned"] = not s.get("banned", False)
            save_sites(sites)
            action = "banned" if s["banned"] else "unbanned"
            log_action(session["user"], action + "_site", sitename)
            break
    return redirect(url_for("admin_panel"))

@app.route("/admin/ban_user/<username>", methods=["POST"])
def ban_user(username):
    if not session.get("is_admin"): return "No", 403
    users = get_users()
    if username in users:
        users[username]["banned"] = not users[username].get("banned", False)
        save_users(users)
        action = "banned" if users[username]["banned"] else "unbanned"
        log_action(session["user"], action + "_user", username)
    return redirect(url_for("admin_panel"))

@app.route("/admin/warn_user/<username>", methods=["POST"])
def warn_user(username):
    if not session.get("is_admin"): return "No", 403
    message = request.form["message"]
    users = get_users()
    if username in users:
        users[username].setdefault("warnings", []).append({
            "msg": message,
            "by": session["user"],
            "at": datetime.now().isoformat()[:19]
        })
        save_users(users)
        log_action(session["user"], "warned_user", f"{username}: {message}")
    return redirect(url_for("admin_panel"))

@app.route("/admin/make_admin/<username>", methods=["POST"])
def make_admin(username):
    if not session.get("is_admin"): return "No", 403
    users = get_users()
    if username in users:
        users[username]["is_admin"] = True
        save_users(users)
        log_action(session["user"], "promoted_admin", username)
    return redirect(url_for("admin_panel"))

# ----------------------------------------------------------------------
# 404
# ----------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template_string(TEMPLATES["404"]), 404

# ----------------------------------------------------------------------
# TEMPLATES (Embedded - Replace with real files later)
# ----------------------------------------------------------------------
TEMPLATES = {
    "index": open("templates/index.html", "r", encoding="utf-8").read() if os.path.exists("templates/index.html") else """
    <h1>Platform Render</h1><p>Host static sites at <code>sites.teamdev.sbs/yoursite</code></p>
    <a href="/auth/signup">Signup</a> | <a href="/auth/login">Login</a>
    """,

    "pricing": open("templates/pricing.html", "r", encoding="utf-8").read() if os.path.exists("templates/pricing.html") else """
    <h1>Pricing</h1><p>Free tier: 5 sites</p><p>Pro: Unlimited - $5/mo</p>
    """,

    "projects": open("templates/projects.html", "r", encoding="utf-8").read() if os.path.exists("templates/projects.html") else """
    <h1>Featured Projects</h1><p>Coming soon...</p>
    """,

    "login": open("templates/login.html", "r", encoding="utf-8").read() if os.path.exists("templates/login.html") else """
    <form method="post"><input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button>Login</button></form><a href="/auth/signup">Signup</a>
    """,

    "signup": open("templates/signup.html", "r", encoding="utf-8").read() if os.path.exists("templates/signup.html") else """
    <form method="post"><input name="username" placeholder="Username" required>
    <input name="email" type="email" placeholder="Email" required>
    <input name="password" type="password" placeholder="Password" required>
    <button>Signup</button></form>
    """,

    "dashboard": open("templates/dashboard.html", "r", encoding="utf-8").read() if os.path.exists("templates/dashboard.html") else """
    <h1>Dashboard - {{ username }}</h1>
    {% if warnings %}<p style="color:red">Warnings: {{ warnings|length }}</p>{% endif %}
    <a href="/dashboard/upload">Upload Site</a> | <a href="/auth/logout">Logout</a>
    <h2>Active Sites</h2>
    {% for s in sites %}
    <p><b>{{ s.sitename }}</b> - 
       <a href="https://sites.teamdev.sbs/{{ s.sitename }}" target="_blank">View</a> |
       <a href="/dashboard/analytics/{{ s.sitename }}">Analytics</a> |
       <form method="post" action="/dashboard/pause/{{ s.sitename }}" style="display:inline">
         <button>{{ 'Unpause' if s.paused else 'Pause' }}</button>
       </form> |
       <form method="post" action="/dashboard/delete/{{ s.sitename }}" style="display:inline">
         <button style="color:red">Delete</button>
       </form>
    </p>
    {% endfor %}
    """,

    "upload": open("templates/upload.html", "r", encoding="utf-8").read() if os.path.exists("templates/upload.html") else """
    <form method="post" enctype="multipart/form-data">
      <input name="sitename" placeholder="myblog" required>
      <input type="file" name="file" accept=".zip,.html" required>
      <button>Upload</button>
    </form>
    """,

    "analytics": open("templates/analytics.html", "r", encoding="utf-8").read() if os.path.exists("templates/analytics.html") else """
    <h1>Analytics: {{ sitename }}</h1>
    <p>Total Views: {{ total }} | Unique: {{ unique }}</p>
    <h3>Paths</h3><ul>{% for p,c in paths.items() %}<li>{{ p }}: {{ c }}</li>{% endfor %}</ul>
    """,

    "admin": open("templates/admin.html", "r", encoding="utf-8").read() if os.path.exists("templates/admin.html") else """
    <h1>Admin Panel</h1>
    <form method="post" action="/admin/toggle_maintenance">
      <button>{{ 'Disable' if maintenance else 'Enable' }} Maintenance</button>
    </form>
    <h2>Users</h2>
    {% for u,d in users.items() %}
    <p><b>{{ u }}</b> - {{ d.email }} 
       {% if d.banned %}(BANNED){% endif %}
       <form method="post" action="/admin/ban_user/{{ u }}" style="display:inline">
         <button>{{ 'Unban' if d.banned else 'Ban' }}</button>
       </form>
       <form method="post" action="/admin/warn_user/{{ u }}" style="display:inline">
         <input name="message" placeholder="Warning" size="20">
         <button>Warn</button>
       </form>
    </p>
    {% endfor %}
    """,

    "404": open("404.html", "r", encoding="utf-8").read() if os.path.exists("404.html") else """
    <h1>404 - Site Not Found</h1>
    """,

    "maintenance": """
    <h1>Maintenance Mode</h1><p>Platform Render is under maintenance. Back soon!</p>
    """
}

# ----------------------------------------------------------------------
# RUN
# ----------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
