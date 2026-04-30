from flask import Flask, request, redirect, jsonify, make_response, render_template_string
import datetime
import time
import os
import re
import json
from collections import Counter

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAP_LOG = os.path.join(BASE_DIR, "traps.log")
os.makedirs(os.path.dirname(TRAP_LOG) or '.', exist_ok=True)

# --- STATS FOR BACKEND ---
stats = {
    'visits': 0,
    'logins': 0,
    'attacks': 0,
    'last_attack': None
}

# --- BANK TRACKING LOGIC ---
def log_event(level, action):
    global stats
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open("bank_honeypot.log", "a", encoding="utf-8") as f:
        log_entry = f"[{timestamp}] IP: {ip} | Level: {level} | Action: {action} | Agent: {user_agent}\n"
        f.write(log_entry)
    
    if 'login' in action.lower():
        stats['logins'] += 1
    if level == 'CRITICAL':
        stats['attacks'] += 1
        stats['last_attack'] = timestamp
    
    color = "\033[91m" if level == "CRITICAL" else "\033[93m"
    print(f"{color}[{level}] {ip} -> {action}\033[0m")

# ═══════════════════════════════════════════════════════════════════
#  HONEYPOT TRAP SYSTEM
# ═══════════════════════════════════════════════════════════════════

TRAPS = [
    "/admin", "/login", "/wp-admin", "/wp-login.php",
    "/.env", "/api/users", "/phpmyadmin", "/config",
    "/backup", "/shell", "/db", "/secret", "/panel",
    "/administrator", "/user/login", "/site/admin",
]

def log_trap(ip, path, method, data=None, ua=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "time": ts, "ip": ip, "path": path,
        "method": method, "data": data or {}, "ua": ua or ""
    }
    with open(TRAP_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"  [TRAP] {ts} | {ip} -> {path} | {method}")

def get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()

def parse_trap_log():
    entries = []
    if not os.path.exists(TRAP_LOG):
        return entries
    with open(TRAP_LOG, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except:
                    pass
    return entries

def trap_handler(path):
    ip = get_ip()
    method = request.method
    data = {}
    
    if method == "POST":
        for k, v in request.form.items():
            data[k] = v
        try:
            jd = request.get_json(silent=True, force=True)
            if jd and isinstance(jd, dict):
                data.update(jd)
        except:
            pass
    
    ua = request.headers.get("User-Agent", "")
    log_trap(ip, "/" + path, method, data, ua)
    
    if "env" in path:
        return _fake_env()
    if "admin" in path or "panel" in path:
        return _fake_admin()
    if "login" in path:
        return _fake_login()
    if "api" in path or "users" in path:
        return _fake_api()
    if "phpmyadmin" in path or "db" in path:
        return _fake_db()
    return _fake_config()

# Register trap routes
for _trap in TRAPS:
    _p = _trap.lstrip("/")
    app.add_url_rule(
        _trap,
        endpoint="trap_" + re.sub(r'\W+', '_', _p) or "trap_root",
        view_func=lambda p=_p: trap_handler(p),
        methods=["GET", "POST"]
    )

# --- FAKE TRAP PAGES ---
def _fake_admin():
    return '''<!DOCTYPE html>
<html><head><title>Admin Login</title>
<style>*{margin:0;padding:0;box-sizing:border-box;}
body{background:#1a1a2e;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;}
.box{background:#16213e;border:1px solid #0f3460;border-radius:8px;padding:40px;width:380px;text-align:center;}
h2{color:#e94560;margin-bottom:6px;font-size:20px;}.sub{color:#888;font-size:12px;margin-bottom:24px;}
input{width:100%;padding:10px 14px;margin-bottom:12px;background:#0f3460;border:1px solid #1a4080;border-radius:4px;color:#fff;outline:none;}
button{width:100%;padding:11px;background:#e94560;border:none;border-radius:4px;color:#fff;font-weight:600;cursor:pointer;}
button:hover{background:#c73652;}</style></head>
<body><div class="box"><h2>Administration Panel</h2><p class="sub">Authorized personnel only</p>
<form method="POST"><input name="username" placeholder="Username"/><input name="password" type="password" placeholder="Password"/>
<button type="submit">Sign In</button></form></div></body></html>'''

def _fake_login():
    return '''<!DOCTYPE html>
<html><head><title>Login</title>
<style>*{margin:0;padding:0;box-sizing:border-box;}
body{background:#f0f2f5;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;}
.box{background:#fff;border-radius:8px;padding:40px;width:360px;box-shadow:0 2px 20px rgba(0,0,0,.1);}
h2{color:#1a1a2e;margin-bottom:4px;font-size:22px;}.sub{color:#888;font-size:12px;margin-bottom:24px;}
input{width:100%;padding:10px 12px;margin-bottom:16px;border:1.5px solid #e0e0e0;border-radius:4px;outline:none;}
input:focus{border-color:#4a90e2;}
button{width:100%;padding:11px;background:#4a90e2;border:none;border-radius:4px;color:#fff;font-weight:600;cursor:pointer;}
button:hover{background:#357abd;}</style></head>
<body><div class="box"><h2>Welcome back</h2><p class="sub">Sign in to your account</p>
<form method="POST"><input name="email" placeholder="you@example.com" type="email"/>
<input name="password" type="password" placeholder="••••••••"/><button type="submit">Login</button></form></div></body></html>'''

def _fake_env():
    return (
        "APP_NAME=PortfolioApp\nAPP_ENV=production\nAPP_KEY=base64:xK9mN2pL4qR7sT1uV3wX5yZ8aB0cD6eF\n"
        "DB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=portfolio_db\n"
        "DB_USERNAME=root\nDB_PASSWORD=Sup3rS3cr3tP@ss!\n"
        "JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n"
    ), 200, {"Content-Type": "text/plain"}

def _fake_api():
    return jsonify([
        {"id": 1, "name": "Admin", "email": "admin@portfolio.dev", "role": "admin"},
        {"id": 2, "name": "John", "email": "john@portfolio.dev", "role": "editor"},
    ])

def _fake_db():
    return '''<!DOCTYPE html>
<html><head><title>phpMyAdmin</title>
<style>body{background:#eee;font-family:sans-serif;font-size:13px;}
.bar{background:#3a6ea5;color:#fff;padding:8px 16px;font-weight:bold;}
.c{padding:16px;}p{color:#c00;font-weight:bold;}
table{border-collapse:collapse;background:#fff;}th{background:#3a6ea5;color:#fff;padding:8px;}
td{padding:8px;border:1px solid #ddd;}</style></head>
<body><div class="bar">phpMyAdmin 5.2.1</div>
<div class="c"><p>Error: Access denied for user 'root'@'localhost'</p>
<table><tr><th>Database</th><th>Tables</th><th>Size</th></tr>
<tr><td>portfolio_db</td><td>12</td><td>4.2 MB</td></tr></table></div></body></html>'''

def _fake_config():
    return (
        "# App Config — DO NOT SHARE\n[database]\nhost=127.0.0.1\nport=3306\n"
        "name=portfolio_db\nuser=db_admin\npass=Ch@ng3M3N0w!\n"
    ), 200, {"Content-Type": "text/plain"}


# --- HQ Dashboard API ---
@app.route("/hq/data")
def hq_data():
    entries = parse_trap_log()
    ips = [e["ip"] for e in entries]
    paths = [e["path"] for e in entries]
    methods = [e["method"] for e in entries]
    
    creds = []
    for e in entries:
        d = e.get("data", {})
        if not isinstance(d, dict):
            continue
        u = (d.get("username") or d.get("email") or d.get("user") or d.get("log") or "")
        p = (d.get("password") or d.get("pass") or d.get("pwd") or "")
        if u or p:
            creds.append({"ip": e["ip"], "user": str(u), "pass": str(p), "path": e["path"], "time": e["time"]})
    
    return jsonify({
        "total": len(entries),
        "unique_ips": len(set(ips)),
        "post_hits": methods.count("POST"),
        "get_hits": methods.count("GET"),
        "recent": list(reversed(entries[-100:])),
        "top_ips": Counter(ips).most_common(10),
        "top_paths": Counter(paths).most_common(10),
        "credentials": creds[-30:],
        "cred_count": len(creds),
    })

@app.route("/hq/clear", methods=["POST"])
def hq_clear():
    open(TRAP_LOG, "w").close()
    return jsonify({"ok": True})

@app.route("/hq/simulate", methods=["POST"])
def hq_simulate():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "203.0.113.45")
    user = data.get("user", "admin")
    pw = data.get("pass", "admin123")
    path = data.get("path", "/admin")
    ua = "Mozilla/5.0 SimulatedAttacker/1.0"
    log_trap(ip, path, "GET", {}, ua)
    log_trap(ip, path, "POST", {"username": user, "password": pw}, ua)
    return jsonify({"ok": True})

# --- HQ DASHBOARD ---
@app.route("/hq")
def hq():
    return render_template_string(HQ_DASHBOARD)


# ═══════════════════════════════════════════════════════════════════
#  EXISTING BANK SYSTEM ROUTES (UNCHANGED)
# ═══════════════════════════════════════════════════════════════════

# --- 1. THE DECEPTIVE HEADER (Server Spoofing) ---
@app.after_request
def apply_caching(response):
    response.headers["Server"] = "Apache/2.2.8 (Win32) mod_ssl/2.2.8 OpenSSL/0.9.8g"
    return response

# --- 2. THE ENTRY POINT (Hacker Search Result) ---
@app.route('/')
def index():
    global stats
    stats['visits'] += 1
    log_event("INFO", "Accessed Root - Searching for Entry Point")
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ZU-BANK - Secure Banking Portal</title>
        <style>
            body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; margin: 0; padding: 0; }
            .container { max-width: 800px; margin: 50px auto; padding: 20px; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
            h2 { color: #2c3e50; text-align: center; }
            p { text-align: center; color: #7f8c8d; }
            ul { list-style: none; padding: 0; text-align: center; }
            li { margin: 20px 0; }
            a { display: inline-block; padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
            a:hover { background: #2980b9; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>ZU-BANK: Core-API Terminal v2.0.4</h2>
            <p>Secure Banking Portal - Operational Status: Active</p>
            <hr>
            <ul>
                <li><a href="/v2/admin/login">Admin Login Portal</a></li>
                <li><a href="/v2/api/docs">API Documentation</a></li>
            </ul>
        </div>
    </body>
    </html>
    '''

# --- 3. THE SQL INJECTION TRAP (Login) ---
@app.route('/v2/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('u')
        pw = request.form.get('p')
        log_event("CRITICAL", f"Login Attempt - User: {user}")
        
        if "'" in user or "OR" in user.upper():
            return redirect('/v2/admin/dashboard?session=authorized_bypass')
        
        return "<h1>401 Unauthorized</h1>"
    
    return '''<!DOCTYPE html>
    <html lang="en">
    <head>
        <title>ZU-BANK - Admin Login</title>
        <style>
            body { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); display: flex; justify-content: center; align-items: center; height: 100vh; font-family: Arial; }
            .login-box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); text-align: center; width: 300px; }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { width: 100%; padding: 10px; background: #e74c3c; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #c0392b; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h3>Internal Bank Login</h3>
            <form method="POST">
                <input name="u" placeholder="User ID" required><br>
                <input name="p" type="password" placeholder="Password" required><br>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>'''

# --- 4. API DOCS ---
@app.route('/v2/api/docs')
def api_docs():
    log_event("INFO", "Accessed API Docs")
    return '''<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>ZU-BANK API Documentation</title>
        <style>
            body { font-family: Arial; background: #f4f4f4; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
            h2 { color: #2c3e50; }
            code { background: #ecf0f1; padding: 2px 4px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>ZU-BANK API Documentation v2.0.4</h2>
            <ul>
                <li><code>GET /</code> - Main portal</li>
                <li><code>POST /v2/admin/login</code> - Admin authentication</li>
            </ul>
            <a href="/">Back to Portal</a>
        </div>
    </body>
    </html>'''

# --- 5. THE INFINITE LOOP (The Time-Waster) ---
@app.route('/v2/admin/dashboard')
def dashboard():
    log_event("INFO", "Hacker trapped in Dashboard Loop")
    return '''<!DOCTYPE html>
    <html>
    <head>
        <title>ZU-BANK - Admin Dashboard</title>
        <style>
            body { background: #f4f4f4; display: flex; justify-content: center; align-items: center; height: 100vh; }
            .dashboard { background: white; padding: 40px; border-radius: 10px; text-align: center; width: 400px; }
            .bar { width: 100%; height: 20px; background: #ecf0f1; border-radius: 10px; margin: 20px 0; overflow: hidden; }
            .fill { height: 100%; background: linear-gradient(90deg, #3498db, #2ecc71); width: 0%; }
        </style>
    </head>
    <body>
        <div class="dashboard">
            <h2>Bypass Successful</h2>
            <p>Fetching Master Ledger...</p>
            <div class="bar"><div class="fill" id="progress-bar"></div></div>
            <p id="percent">0%</p>
        </div>
        <script>
            let n = 0;
            const bar = document.getElementById('progress-bar');
            setInterval(() => {
                if(n < 99) { 
                    n++; 
                    bar.style.width = n + '%'; 
                    document.getElementById('percent').textContent = n + '%'; 
                } else { 
                    alert("FATAL ERROR: Decryption Key Revoked by Admin."); 
                    window.location.href = '/'; 
                }
            }, 150);
        </script>
    </body>
    </html>'''

# --- 6. HONEYPOT INTERFACE (Log Viewer) ---
@app.route('/honeypot/logs')
def honeypot_logs():
    try:
        with open("bank_honeypot.log", "r", encoding="utf-8") as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        log_lines = ["No logs available yet."]
    
    logs = []
    for line in log_lines:
        if line.strip():
            parts = line.split(' | ')
            if len(parts) >= 4:
                logs.append({'timestamp': parts[0].replace('[', '').replace(']', ''), 'ip': parts[1].replace('IP: ', ''), 'level': parts[2].replace('Level: ', ''), 'action': parts[3].replace('Action: ', '')})
    
    table_rows = ''
    for log in logs:
        level_class = 'critical' if log['level'] == 'CRITICAL' else 'info'
        table_rows += f'<tr><td>{log["timestamp"]}</td><td>{log["ip"]}</td><td class="{level_class}">{log["level"]}</td><td>{log["action"]}</td></tr>'
    
    return f'''<!DOCTYPE html>
    <html>
    <head>
        <title>Honeypot Control Center</title>
        <style>
            body {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; font-family: Arial; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 15px; padding: 20px; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background: #f8f9fa; font-weight: 600; }}
            .critical {{ color: #e74c3c; font-weight: bold; }}
            .info {{ color: #3498db; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Honeypot Control Center</h1>
                <p>Monitor and analyze security threats in real-time</p>
            </div>
            <table>
                <thead><tr><th>Timestamp</th><th>IP</th><th>Level</th><th>Action</th></tr></thead>
                <tbody>{table_rows}</tbody>
            </table>
            <a href="/" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 5px;">Back to Bank Portal</a>
            <a href="/hq" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #27ae60; color: white; text-decoration: none; border-radius: 5px; margin-left: 10px;">Open HQ Dashboard</a>
        </div>
    </body>
    </html>'''

# --- BACKEND ADMIN INTERFACE ---
@app.route('/backend/login', methods=['GET', 'POST'])
def backend_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == 'admin123':
            return redirect('/backend/dashboard?auth=admin123')
        else:
            return '<h1>Invalid Password</h1><a href="/backend/login">Try Again</a>'
    
    return '''<!DOCTYPE html>
    <html>
    <head>
        <title>Backend Admin Login</title>
        <style>
            body { background: #34495e; display: flex; justify-content: center; align-items: center; height: 100vh; font-family: Arial; }
            .login-box { background: white; padding: 40px; border-radius: 10px; width: 300px; text-align: center; }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { width: 100%; padding: 10px; background: #e74c3c; color: white; border: none; border-radius: 5px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h3>Honeypot Backend Login</h3>
            <form method="POST">
                <input name="password" type="password" placeholder="Admin Password" required>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>'''

@app.route('/backend/dashboard')
def backend_dashboard():
    if request.args.get('auth') != 'admin123':
        return redirect('/backend/login')
    
    try:
        with open("bank_honeypot.log", "r", encoding="utf-8") as f:
            logs = f.read().split('\n')[-10:]
            logs = '\n'.join(logs)
    except FileNotFoundError:
        logs = "No logs available yet."
    
    return f'''<!DOCTYPE html>
    <html>
    <head>
        <title>Backend Dashboard</title>
        <style>
            body {{ background: #ecf0f1; padding: 20px; font-family: Arial; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            h2 {{ color: #2c3e50; text-align: center; }}
            .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
            .stat {{ background: white; padding: 20px; border-radius: 10px; flex: 1; margin: 0 10px; text-align: center; }}
            .stat h3 {{ color: #3498db; }}
            .stat p {{ font-size: 24px; color: #2c3e50; margin: 10px 0; }}
            .logs {{ background: white; padding: 20px; border-radius: 10px; margin-top: 20px; }}
            pre {{ background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Honeypot Backend Dashboard</h2>
            <div class="stats">
                <div class="stat"><h3>Total Visits</h3><p>{stats['visits']}</p></div>
                <div class="stat"><h3>Login Attempts</h3><p>{stats['logins']}</p></div>
                <div class="stat"><h3>Attacks Detected</h3><p>{stats['attacks']}</p></div>
                <div class="stat"><h3>Last Attack</h3><p>{stats['last_attack'] or 'None'}</p></div>
            </div>
            <div class="logs">
                <h3>Recent Bank Logs</h3>
                <pre>{logs}</pre>
            </div>
            <a href="/honeypot/logs">View Full Logs</a> | <a href="/">Back to Honeypot</a> | <a href="/hq">Open HQ</a>
        </div>
    </body>
    </html>'''


# ═══════════════════════════════════════════════════════════════════
#  HQ DASHBOARD HTML (HONEYPOT MONITORING)
# ═══════════════════════════════════════════════════════════════════

HQ_DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>HQ — Honeypot Command Center</title>
<style>
:root{
  --bg:#060a0e; --s1:#0b1015; --s2:#0f1820;
  --border:#162016; --green:#00ff88; --red:#ff4455; --amber:#ffaa00;
  --text:#b0d0b0; --text2:#3d6a3d;
  --mono:'Share Tech Mono',monospace; --sans:'Rajdhani',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:monospace;font-size:12px;}
body{display:flex;flex-direction:column;}

.topbar{display:flex;align-items:center;justify-content:space-between;padding:12px 18px;border-bottom:1px solid var(--border);background:var(--s1);}
.brand{display:flex;align-items:center;gap:8px;font-size:16px;font-weight:bold;color:var(--green);}
.top-right{display:flex;gap:12px;}
.top-pill{padding:3px 10px;border:1px solid var(--border);border-radius:2px;font-size:9px;}
.dot{width:6px;height:6px;border-radius:50%;background:var(--green);display:inline-block;margin-right:4px;animation:blink 1s infinite;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}

.main{display:flex;flex:1;overflow:hidden;}
.sidebar{width:200px;background:var(--s1);border-right:1px solid var(--border);overflow-y:auto;padding:10px 0;}
.nav-lbl{font-size:8px;letter-spacing:2px;color:var(--text2);padding:8px 14px 3px;text-transform:uppercase;}
.nb{width:100%;padding:8px 14px;border:none;background:none;color:var(--text2);font-family:monospace;font-size:10px;text-align:left;cursor:pointer;border-left:2px solid transparent;transition:all .15s;}
.nb:hover{background:rgba(0,255,136,.05);color:var(--text);}
.nb.active{background:rgba(0,255,136,.08);color:var(--green);border-left-color:var(--green);}

.content{flex:1;overflow-y:auto;padding:18px;}
.pg-title{font-size:18px;color:var(--green);letter-spacing:2px;margin-bottom:3px;font-weight:bold;}
.pg-sub{font-size:9px;color:var(--text2);margin-bottom:16px;}

.cards{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;}
.card{background:var(--s1);border:1px solid var(--border);border-radius:4px;padding:12px 14px;flex:1;min-width:150px;}
.card::after{content:'';display:block;width:100%;height:2px;margin:-12px -14px 8px;border-radius:2px 2px 0 0;}
.card.r::after{background:var(--red);}
.card.a::after{background:var(--amber);}
.card.g::after{background:var(--green);}
.card-lbl{font-size:8px;color:var(--text2);letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;}
.card-val{font-size:30px;font-weight:bold;color:inherit;}
.card.r .card-val{color:var(--red);}
.card.a .card-val{color:var(--amber);}
.card.g .card-val{color:var(--green);}

.panel{background:var(--s1);border:1px solid var(--border);border-radius:4px;overflow:hidden;margin-bottom:12px;}
.ph{padding:8px 12px;background:var(--s2);border-bottom:1px solid var(--border);font-size:8px;letter-spacing:2px;color:var(--text2);text-transform:uppercase;display:flex;justify-content:space-between;}
.pb{padding:2px 6px;border-radius:2px;background:rgba(0,255,136,.08);color:var(--green);}

.feed{max-height:220px;overflow-y:auto;}
.feed::-webkit-scrollbar{width:3px;}
.feed::-webkit-scrollbar-thumb{background:var(--border);}
.feed-hdr{display:grid;grid-template-columns:130px 95px 90px 65px 1fr;padding:5px 12px;font-size:8px;letter-spacing:1px;color:var(--text2);background:var(--s2);border-bottom:1px solid var(--border);text-transform:uppercase;}
.feed-row{display:grid;grid-template-columns:130px 95px 90px 65px 1fr;padding:5px 12px;border-bottom:1px solid rgba(22,32,22,.5);font-size:10px;}
.feed-row:hover{background:rgba(0,255,136,.02);}

.empty{text-align:center;padding:24px;color:var(--text2);font-size:10px;}
.btn{padding:7px 16px;border:none;border-radius:2px;background:transparent;border:1px solid var(--border);color:var(--text2);font-family:monospace;font-size:11px;cursor:pointer;margin-bottom:16px;}
.btn:hover{border-color:var(--amber);color:var(--amber);}

.tl-item{padding:6px 10px;background:var(--s2);border:1px solid var(--border);border-radius:3px;margin-bottom:4px;font-size:10px;}
.tl-item.POST{border-left:2px solid var(--red);}
.tl-item.GET{border-left:2px solid var(--text2);}

#toasts{position:fixed;top:14px;right:14px;z-index:10000;}
.toast{background:var(--s2);border:1px solid var(--red);border-left:3px solid var(--red);padding:8px 12px;border-radius:2px;font-size:10px;margin-bottom:5px;max-width:280px;animation:tin .3s;}
@keyframes tin{from{opacity:0;transform:translateX(10px)}to{opacity:1;transform:none}}
</style>
</head>
<body>
<div id="toasts"></div>

<div class="topbar">
  <div class="brand"><span class="dot"></span>HONEYPOT HQ</div>
  <div class="top-right">
    <div class="top-pill"><span class="dot"></span>TRAPS ACTIVE</div>
    <span id="clock">--:--:--</span>
  </div>
</div>

<div class="main">
  <nav class="sidebar">
    <div class="nav-lbl">Monitor</div>
    <button class="nb active" onclick="showPage('dash')">Dashboard</button>
    <button class="nb" onclick="showPage('feed')">Live Feed</button>
    <button class="nb" onclick="showPage('attackers')">Attackers</button>
  </nav>

  <div class="content">
    <div class="page active" id="page-dash">
      <div class="pg-title">DASHBOARD</div>
      <div class="pg-sub">REAL-TIME TRAP MONITORING</div>
      
      <div class="cards">
        <div class="card r"><div class="card-lbl">Total Traps Hit</div><div class="card-val" id="c-total">0</div></div>
        <div class="card a"><div class="card-lbl">Unique IPs</div><div class="card-val" id="c-ips">0</div></div>
        <div class="card g"><div class="card-lbl">GET Probes</div><div class="card-val" id="c-get">0</div></div>
        <div class="card r"><div class="card-lbl">POST Attacks</div><div class="card-val" id="c-post">0</div></div>
      </div>

      <div class="panel">
        <div class="ph"><span>Recent Trap Hits</span><span class="pb" id="feed-badge">0</span></div>
        <div class="feed-hdr"><span>Timestamp</span><span>IP</span><span>Trap Path</span><span>Method</span><span>User-Agent</span></div>
        <div class="feed" id="mini-feed"><div class="empty">No intrusions yet</div></div>
      </div>
    </div>

    <div class="page" id="page-feed">
      <div class="pg-title">LIVE FEED</div>
      <div class="pg-sub">ALL TRAP HITS</div>
      <button class="btn" onclick="clearLogs()">CLEAR LOGS</button>
      <div class="panel">
        <div class="ph"><span>Event Stream</span></div>
        <div class="feed" style="max-height:500px;" id="full-feed"><div class="empty">Waiting...</div></div>
      </div>
    </div>

    <div class="page" id="page-attackers">
      <div class="pg-title">ATTACKER IPS</div>
      <div class="pg-sub">SORTED BY ACTIVITY</div>
      <div class="panel">
        <div id="att-list"><div class="empty">No attackers yet</div></div>
      </div>
    </div>
  </div>
</div>

<script>
function showPage(n){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nb').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+n).classList.add('active');
  document.querySelector('.nb[onclick="showPage(\''+n+'\')"]').classList.add('active');
}

document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-GB');
setInterval(()=>{document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-GB');},1000);

function feedRow(e){
  return `<div class="feed-row">
    <span>${e.time}</span>
    <span style="color:#44aaff">${e.ip}</span>
    <span style="color:#ffaa00">${e.path}</span>
    <span style="color:${e.method==='POST'?'#ff4455':'#3d6a3d'}">${e.method}</span>
    <span style="color:#3d6a3d">${(e.ua||'').substring(0,35)}</span>
  </div>`;
}

async function poll(){
  try{
    const d=await fetch('/hq/data').then(r=>r.json());
    document.getElementById('c-total').textContent=d.total;
    document.getElementById('c-ips').textContent=d.unique_ips;
    document.getElementById('c-get').textContent=d.get_hits;
    document.getElementById('c-post').textContent=d.post_hits;
    document.getElementById('feed-badge').textContent=d.total+' HITS';
    
    const mf=document.getElementById('mini-feed');
    mf.innerHTML=d.recent.length?d.recent.map(feedRow).join(''):'<div class="empty">No intrusions yet</div>';
    
    const ff=document.getElementById('full-feed');
    ff.innerHTML=d.recent.length?d.recent.map(feedRow).join(''):'<div class="empty">No events</div>';
    
    const byIp={};
    d.recent.forEach(e=>{
      if(!byIp[e.ip])byIp[e.ip]={hits:0,posts:0};
      byIp[e.ip].hits++;
      if(e.method==='POST')byIp[e.ip].posts++;
    });
    const ips=Object.entries(byIp).sort((a,b)=>b[1].hits-a[1].hits);
    const al=document.getElementById('att-list');
    if(!ips.length){al.innerHTML='<div class="empty">No attackers</div>';return;}
    al.innerHTML='<div style="max-height:500px;overflow-y:auto;padding:10px;">'+
      ips.map(([ip,s])=>`<div class="tl-item"><span style="color:#44aaff">${ip}</span> <span style="color:#ff4455">${s.posts}</span> POST | <span style="color:#3d6a3d">${s.hits-s.posts}</span> GET</div>`).join('')+
      '</div>';
  }catch(e){console.warn('poll error',e);}
}

async function clearLogs(){
  if(!confirm('Clear all logs?'))return;
  await fetch('/hq/clear',{method:'POST'});
  poll();
}

poll();
setInterval(poll,2000);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    print("🛡️  HONEYPOT SYSTEM STARTING ON PORT 5000...")
    print("   Bank Portal:  http://127.0.0.1:5000")
    print("   Backend:      http://127.0.0.1:5000/backend/login (pwd: admin123)")
    print("   Honeypot HQ:  http://127.0.0.1:5000/hq")
    print("   Active Traps: /admin /login /wp-admin /.env /phpmyadmin /api/users")
    app.run(host='127.0.0.1', port=5000, debug=False)
