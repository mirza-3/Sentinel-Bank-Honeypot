from flask import Flask, request, redirect, jsonify, make_response, render_template_string, render_template
import datetime
import time
import os
import re
import json
from collections import Counter

app = Flask(__name__, template_folder='templates')
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

# ═══════════════════════════════════════════════════════════════════
#  HONEYPOT TRAP SYSTEM (Silent Monitoring)
# ═══════════════════════════════════════════════════════════════════

TRAPS = [
    "/admin", "/login", "/wp-admin", "/wp-login.php",
    "/.env", "/api/users", "/phpmyadmin", "/config",
    "/backup", "/shell", "/db", "/secret", "/panel",
    "/administrator", "/user/login", "/site/admin",
]

def log_trap(ip, path, method, data=None, ua=None):
    """Log trap hits to JSON file"""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "time": ts, "ip": ip, "path": path,
        "method": method, "data": data or {}, "ua": ua or ""
    }
    with open(TRAP_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"  [TRAP] {ts} | {ip} -> {path} | {method}")

def get_ip():
    """Extract client IP"""
    return request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()

def bank_trap(path, method, data=None, ua=None):
    """Record bank-system access attempts in the honeypot trap log."""
    ua = ua or request.headers.get("User-Agent", "")
    log_trap(get_ip(), path, method, data or {}, ua)


def parse_trap_log():
    """Parse trap log JSON file"""
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
    """Handle all trap route hits"""
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
    
    # Return appropriate fake page based on trap type
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

# Register all trap routes
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
        "APP_NAME=PortfolioApp\nAPP_ENV=production\nAPP_KEY=base64:xK9mN2pL4qR7sT1uV3wX5yZ\n"
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
        "# App Config — DO NOT SHARE\n[database]\nhost=127.0.0.1\n"
        "name=portfolio_db\nuser=db_admin\npass=Ch@ng3M3N0w!\n"
    ), 200, {"Content-Type": "text/plain"}

# --- HQ DASHBOARD API ROUTES ---
@app.route("/hq/data")
def hq_data():
    """API endpoint for HQ dashboard data"""
    entries = parse_trap_log()
    ips = [e["ip"] for e in entries]
    paths = [e["path"] for e in entries]
    methods = [e["method"] for e in entries]
    
    creds = []
    for e in entries:
        d = e.get("data", {})
        if not isinstance(d, dict):
            continue
        u = (d.get("username") or d.get("email") or d.get("user") or "")
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
    """Clear all trap logs"""
    open(TRAP_LOG, "w").close()
    return jsonify({"ok": True})

@app.route("/hq/simulate", methods=["POST"])
def hq_simulate():
    """Simulate an attack for testing"""
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
    """Professional honeypot HQ dashboard"""
    return render_template_string(HQ_DASHBOARD_HTML)



# --- HACKER TRACKING LOGIC ---
def log_event(level, action):
    global stats
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open("bank_honeypot.log", "a", encoding="utf-8") as f:
        log_entry = f"[{timestamp}] IP: {ip} | Level: {level} | Action: {action} | Agent: {user_agent}\n"
        f.write(log_entry)
    
    # Update stats
    if 'login' in action.lower():
        stats['logins'] += 1
    if level == 'CRITICAL':
        stats['attacks'] += 1
        stats['last_attack'] = timestamp
    
    # Terminal par visual alerts
    color = "\033[91m" if level == "CRITICAL" else "\033[93m"
    print(f"{color}[{level}] {ip} -> {action}\033[0m")

# --- 1. THE DECEPTIVE HEADER (Server Spoofing) ---
@app.after_request
def apply_caching(response):
    # Hacker ko lagega purana Apache server hai
    response.headers["Server"] = "Apache/2.2.8 (Win32) mod_ssl/2.2.8 OpenSSL/0.9.8g"
    return response

# --- 2. THE ENTRY POINT (Hacker Search Result) ---
@app.route('/')
def index():
    global stats
    stats['visits'] += 1
    log_event("INFO", "Accessed Root - Searching for Entry Point")
    bank_trap(request.path, "GET")
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ZU-BANK - Secure Banking Portal</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #333; }
            
            /* Header */
            .header-top {
                background: #f8f9fa;
                padding: 12px 0;
                border-bottom: 1px solid #e9ecef;
                font-size: 14px;
            }
            .header-top-content {
                max-width: 1400px;
                margin: 0 auto;
                padding: 0 40px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .header-top-left, .header-top-right {
                display: flex;
                gap: 30px;
                align-items: center;
            }
            .header-top-left a, .header-top-right a {
                text-decoration: none;
                color: #666;
                transition: color 0.3s;
            }
            .header-top-left a:hover, .header-top-right a:hover {
                color: #2563eb;
            }
            .btn-login { background: #2563eb; color: white !important; padding: 8px 20px; border-radius: 4px; }
            .btn-login:hover { background: #1d47a5 !important; }
            
            /* Main Header */
            .header-main {
                background: white;
                padding: 20px 0;
                border-bottom: 1px solid #e9ecef;
            }
            .header-content {
                max-width: 1400px;
                margin: 0 auto;
                padding: 0 40px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .logo {
                font-size: 24px;
                font-weight: bold;
                color: #2563eb;
                text-decoration: none;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .logo-icon {
                width: 50px;
                height: 50px;
                background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
                border-radius: 8px;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: bold;
            }
            
            /* Navigation */
            .nav {
                display: flex;
                gap: 40px;
                list-style: none;
            }
            .nav a {
                text-decoration: none;
                color: #333;
                font-weight: 500;
                transition: color 0.3s;
                display: flex;
                align-items: center;
                gap: 5px;
            }
            .nav a:hover {
                color: #2563eb;
            }
            
            /* Hero Section */
            .hero {
                background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
                position: relative;
                overflow: hidden;
                height: 600px;
                display: flex;
                align-items: center;
            }
            .hero::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 600"><defs><pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,.05)" stroke-width="1"/></pattern></defs><rect width="1200" height="600" fill="url(%23grid)" /></svg>');
                opacity: 0.5;
            }
            
            .hero-content {
                max-width: 1400px;
                margin: 0 auto;
                padding: 0 40px;
                width: 100%;
                display: flex;
                justify-content: space-between;
                align-items: center;
                position: relative;
                z-index: 2;
            }
            
            .hero-text {
                color: white;
                flex: 1;
            }
            .hero-text h1 {
                font-size: 56px;
                margin-bottom: 20px;
                font-weight: 700;
                line-height: 1.2;
            }
            .hero-text h1 .highlight {
                color: #fbbf24;
            }
            .hero-text p {
                font-size: 20px;
                margin-bottom: 30px;
                opacity: 0.95;
                font-weight: 300;
            }
            
            .btn-hero {
                display: inline-block;
                background: #fbbf24;
                color: #1f2937;
                padding: 14px 40px;
                border-radius: 4px;
                text-decoration: none;
                font-weight: 600;
                transition: all 0.3s;
                border: none;
                cursor: pointer;
                font-size: 16px;
            }
            .btn-hero:hover {
                background: #f59e0b;
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(0,0,0,0.2);
            }
            
            .hero-image {
                flex: 1;
                display: flex;
                justify-content: center;
                align-items: center;
                position: relative;
            }
            
            .card-image {
                width: 300px;
                height: 200px;
                background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
                border-radius: 12px;
                padding: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                border: 2px solid #fbbf24;
                position: relative;
                transform: perspective(1000px) rotateY(-10deg);
            }
            
            .card-content {
                color: white;
                height: 100%;
                display: flex;
                flex-direction: column;
                justify-content: space-between;
            }
            
            .card-logo {
                font-weight: bold;
                font-size: 14px;
                opacity: 0.8;
            }
            
            .card-chip {
                width: 50px;
                height: 40px;
                background: #fbbf24;
                border-radius: 4px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: bold;
                font-size: 12px;
                color: #1f2937;
            }
            
            .card-bottom {
                display: flex;
                justify-content: space-between;
                align-items: flex-end;
            }
            
            .card-number {
                font-size: 18px;
                letter-spacing: 2px;
                font-weight: 500;
            }
            
            .card-contactless {
                font-size: 12px;
            }
            
            /* Cookie Banner */
            .cookie-banner {
                position: fixed;
                bottom: 0;
                left: 0;
                right: 0;
                background: #1f2937;
                color: white;
                padding: 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                z-index: 1000;
                box-shadow: 0 -2px 10px rgba(0,0,0,0.1);
            }
            
            .cookie-text {
                flex: 1;
                font-size: 14px;
                line-height: 1.6;
            }
            
            .cookie-text a {
                color: #fbbf24;
                text-decoration: none;
            }
            
            .cookie-buttons {
                display: flex;
                gap: 15px;
                margin-left: 30px;
            }
            
            .btn-cookie {
                padding: 10px 25px;
                border: 1px solid white;
                border-radius: 4px;
                background: transparent;
                color: white;
                cursor: pointer;
                transition: all 0.3s;
                font-weight: 600;
            }
            
            .btn-cookie.accept {
                background: white;
                color: #1f2937;
            }
            
            .btn-cookie:hover {
                opacity: 0.9;
            }
            
            /* Responsive */
            @media (max-width: 768px) {
                .header-top-content, .header-content, .hero-content {
                    padding: 0 20px;
                    flex-direction: column;
                    gap: 10px;
                }
                .nav { gap: 20px; font-size: 14px; }
                .hero-text h1 { font-size: 32px; }
                .hero-image { display: none; }
                .cookie-banner { flex-direction: column; gap: 15px; text-align: center; }
                .cookie-buttons { margin-left: 0; }
            }
        </style>
    </head>
    <body>
        <!-- Header Top -->
        <div class="header-top">
            <div class="header-top-content">
                <div class="header-top-left">
                    <span>☎ +1-800-ZU-BANK</span>
                    <a href="/contact">Contact Us</a>
                </div>
                <div class="header-top-right">
                    <a href="/info">En</a>
                    <a href="#theme">🌙</a>
                    <a href="/v2/admin/login" class="btn-login">Login</a>
                </div>
            </div>
        </div>
        
        <!-- Main Header -->
        <div class="header-main">
            <div class="header-content">
                <a href="/" class="logo">
                    <div class="logo-icon">ZU</div>
                    <span>ZU-BANK</span>
                </a>
                <ul class="nav">
                    <li><a href="/about">About Us</a></li>
                    <li><a href="/personal-banking">Personal Banking</a></li>
                    <li><a href="/business-banking">Business Banking</a></li>
                    <li><a href="/information">Information</a></li>
                    <li><a href="/careers">Careers</a></li>
                    <li><a href="#search">🔍</a></li>
                </ul>
            </div>
        </div>
        
        <!-- Hero Section -->
        <div class="hero">
            <div class="hero-content">
                <div class="hero-text">
                    <h1>ZU-BANK <span class="highlight">Premium Debit Card</span></h1>
                    <p>Experience the future of secure banking with advanced financial solutions.</p>
                    <button class="btn-hero" onclick="location.href='/personal-banking';">Explore Services</button>
                </div>
                <div class="hero-image">
                    <div class="card-image">
                        <div class="card-content">
                            <div class="card-logo">ZU-BANK<br>Premium</div>
                            <div class="card-chip">CHIP</div>
                            <div class="card-bottom">
                                <div>
                                    <div class="card-number">•••• •••• •••• 5678</div>
                                    <div class="card-contactless">💳 Contactless</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Cookie Banner -->
        <div class="cookie-banner">
            <div class="cookie-text">
                ZU-BANK uses cookies to enhance your browsing experience. <a href="/information">Learn more</a>
            </div>
            <div class="cookie-buttons">
                <button class="btn-cookie" onclick="this.parentElement.parentElement.style.display='none';">Decline</button>
                <button class="btn-cookie accept" onclick="this.parentElement.parentElement.style.display='none';">Accept</button>
            </div>
        </div>
        
        <script>
            function bank_trap(element) {
                // Trap tracking (honeypot logging)
                console.log('Action tracked');
            }
        </script>
    </body>
    </html>
    '''

# --- 3. THE SQL INJECTION TRAP (Login) ---
@app.route('/v2/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('u')
        pw = request.form.get('p')
        log_event("CRITICAL", f"Login Attempt (Possible SQLi/Brute Force) - User: {user} | Pass: {pw}")
        bank_trap(request.path, "POST", {"user": user, "pass": pw})
        
        # Fake Success: Agar hacker ' OR '1'='1' use kare toh
        if "'" in user or "OR" in user.upper():
            return redirect('/v2/admin/dashboard?session=authorized_bypass')
        
        return '''<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login Failed</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%); display: flex; justify-content: center; align-items: center; height: 100vh; }
                .error-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); text-align: center; max-width: 400px; }
                h2 { color: #d32f2f; margin-bottom: 15px; }
                p { color: #666; margin-bottom: 20px; }
                a { display: inline-block; background: #2563eb; color: white; padding: 10px 30px; text-decoration: none; border-radius: 4px; transition: background 0.3s; }
                a:hover { background: #1d47a5; }
            </style>
        </head>
        <body>
            <div class="error-box">
                <h2>Login Failed</h2>
                <p>Invalid credentials. Please try again.</p>
                <a href="/v2/admin/login">← Back to Login</a>
            </div>
        </body>
        </html>'''

    bank_trap(request.path, "GET")
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ZU-BANK - Secure Login</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%); 
                display: flex; 
                justify-content: center; 
                align-items: center; 
                height: 100vh;
                margin: 0;
            }
            
            .login-container {
                background: white;
                border-radius: 12px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                width: 100%;
                max-width: 420px;
                padding: 50px;
            }
            
            .login-header {
                text-align: center;
                margin-bottom: 40px;
            }
            
            .logo-small {
                width: 60px;
                height: 60px;
                background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
                border-radius: 8px;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: bold;
                font-size: 24px;
                margin: 0 auto 20px;
            }
            
            .login-header h2 {
                color: #2563eb;
                font-size: 28px;
                margin-bottom: 10px;
            }
            
            .login-header p {
                color: #999;
                font-size: 14px;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            label {
                display: block;
                color: #333;
                font-weight: 600;
                margin-bottom: 8px;
                font-size: 14px;
            }
            
            input {
                width: 100%;
                padding: 12px 15px;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                font-size: 14px;
                transition: all 0.3s;
                font-family: 'Segoe UI', sans-serif;
            }
            
            input:focus {
                outline: none;
                border-color: #2563eb;
                box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
            }
            
            .remember-forgot {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 25px;
                font-size: 14px;
            }
            
            .remember-forgot a {
                color: #2563eb;
                text-decoration: none;
                transition: color 0.3s;
            }
            
            .remember-forgot a:hover {
                color: #1d47a5;
            }
            
            .btn-login-submit {
                width: 100%;
                padding: 13px;
                background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
            }
            
            .btn-login-submit:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(37, 99, 235, 0.3);
            }
            
            .btn-login-submit:active {
                transform: translateY(0);
            }
            
            .login-footer {
                text-align: center;
                margin-top: 25px;
                color: #999;
                font-size: 13px;
            }
            
            .security-note {
                background: #f0f3ff;
                border-left: 4px solid #2563eb;
                padding: 12px;
                border-radius: 4px;
                font-size: 12px;
                color: #555;
                margin-top: 20px;
            }
            
            .security-note strong {
                color: #2563eb;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <div class="logo-small">ZU</div>
                <h2>ZU-BANK</h2>
                <p>Secure Login Portal</p>
            </div>
            
            <form method="POST">
                <div class="form-group">
                    <label for="username">User ID or Email</label>
                    <input type="text" id="username" name="u" placeholder="Enter your User ID" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="p" placeholder="••••••••" required>
                </div>
                
                <div class="remember-forgot">
                    <label style="margin: 0; font-weight: 400;">
                        <input type="checkbox" style="width: auto; margin-right: 6px;">
                        Remember me
                    </label>
                    <a href="#forgot">Forgot Password?</a>
                </div>
                
                <button type="submit" class="btn-login-submit">Secure Login</button>
            </form>
            
            <div class="security-note">
                <strong>🔒 Security Tip:</strong> Never share your password with anyone. We never ask for your password via email.
            </div>
            
            <div class="login-footer">
                <p><a href="/" style="color: #2563eb; text-decoration: none;">← Back to Home</a></p>
            </div>
        </div>
    </body>
    </html>
    '''

# --- 4. THE DATA EXFILTRATION TRAP (CLI/Curl Target) ---
@app.route('/v2/api/db-backup')
def db_backup():
    log_event("CRITICAL", "Directory Traversal Attempt: Accessing DB-BACKUP")
    bank_trap(request.path, "GET")
    # Hacker terminal par 'curl' karega toh usse ye fake error milega
    return make_response("Error: Connection Reset by Peer (Firewall Rule 409)", 403)

# --- API DOCS ---
@app.route('/v2/api/docs')
def api_docs():
    log_event("INFO", "Accessed API Docs")
    bank_trap(request.path, "GET")
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ZU-BANK API Documentation</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
            h2 { color: #2c3e50; text-align: center; }
            h3 { color: #34495e; }
            p { color: #7f8c8d; }
            code { background: #ecf0f1; padding: 2px 4px; border-radius: 3px; }
            a { color: #3498db; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>ZU-BANK API Documentation v2.0.4</h2>
            <p>Welcome to the ZU-BANK Core API. This API provides secure access to banking operations.</p>
            <h3>Endpoints</h3>
            <ul>
                <li><code>GET /</code> - Main portal</li>
                <li><code>POST /v2/admin/login</code> - Admin authentication</li>
                <li><code>GET /v2/admin/dashboard</code> - Admin dashboard</li>
                <li><code>GET /v2/api/db-backup</code> - Database backup (restricted)</li>
            </ul>
            <p>For more information, contact system administrator.</p>
            <a href="/">Back to Portal</a>
        </div>
    </body>
    </html>
    '''

# --- PROFESSIONAL SUB PAGES (All with honeypot tracking) ---

@app.route('/about')
def about():
    """About Us Page"""
    log_event("INFO", "Visited About Us Page")
    bank_trap(request.path, "GET")
    return render_template('about.html')

@app.route('/personal-banking')
def personal_banking():
    """Personal Banking Page"""
    log_event("INFO", "Visited Personal Banking Page")
    bank_trap(request.path, "GET")
    return render_template('personal_banking.html')

@app.route('/business-banking')
def business_banking():
    """Business Banking Page"""
    log_event("INFO", "Visited Business Banking Page")
    bank_trap(request.path, "GET")
    return render_template('business_banking.html')

@app.route('/information')
def information():
    """Information & Resources Page"""
    log_event("INFO", "Visited Information Page")
    bank_trap(request.path, "GET")
    return render_template('information.html')

@app.route('/careers')
def careers():
    """Careers Page"""
    log_event("INFO", "Visited Careers Page")
    bank_trap(request.path, "GET")
    return render_template('careers.html')

# --- 5. THE INFINITE LOOP (The Time-Waster) ---
@app.route('/v2/admin/dashboard')
def dashboard():
    log_event("INFO", "Hacker trapped in Dashboard Loop")
    bank_trap(request.path, "GET")
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ZU-BANK - Admin Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f4f4f4; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .dashboard { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); text-align: center; width: 400px; }
            h2 { color: #27ae60; }
            p { color: #7f8c8d; }
            .progress { margin: 20px 0; }
            .bar { width: 100%; height: 20px; background: #ecf0f1; border-radius: 10px; overflow: hidden; }
            .fill { height: 100%; background: linear-gradient(90deg, #3498db, #2ecc71); width: 0%; transition: width 0.1s; }
        </style>
    </head>
    <body>
        <div class="dashboard">
            <h2>Bypass Successful</h2>
            <p>Fetching Master Ledger...</p>
            <div class="progress">
                <div class="bar">
                    <div class="fill" id="progress-bar"></div>
                </div>
                <p id="percent">0%</p>
            </div>
        </div>
        <script>
            let n = 0;
            const bar = document.getElementById('progress-bar');
            const percent = document.getElementById('percent');
            setInterval(() => {
                if(n < 99) { 
                    n++; 
                    bar.style.width = n + '%'; 
                    percent.textContent = n + '%'; 
                } else { 
                    alert("FATAL ERROR: Decryption Key Revoked by Admin."); 
                    window.location.href = '/'; 
                }
            }, 150);
        </script>
    </body>
    </html>
    '''

# --- 6. HONEYPOT INTERFACE (Log Viewer) ---
@app.route('/honeypot/logs')
def honeypot_logs():
    try:
        with open("bank_honeypot.log", "r", encoding="utf-8") as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        log_lines = ["No logs available yet."]
    
    # Parse logs in    Move app_enhanced.py → app.pyto a list of dicts for table display
    logs = []
    for line in log_lines:
        if line.strip():
            parts = line.split(' | ')
            if len(parts) >= 4:
                timestamp = parts[0].replace('[', '').replace(']', '')
                ip = parts[1].replace('IP: ', '')
                level = parts[2].replace('Level: ', '')
                action = parts[3].replace('Action: ', '')
                agent = parts[4].replace('Agent: ', '') if len(parts) > 4 else ''
                logs.append({'timestamp': timestamp, 'ip': ip, 'level': level, 'action': action, 'agent': agent})
    
    # Generate table rows
    table_rows = ''
    for log in logs:
        level_class = 'critical' if log['level'] == 'CRITICAL' else 'info'
        table_rows += f'''
        <tr>
            <td>{log['timestamp']}</td>
            <td>{log['ip']}</td>
            <td class="{level_class}">{log['level']}</td>
            <td>{log['action']}</td>
            <td>{log['agent'][:50]}...</td>
        </tr>
        '''
    
    return f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Honeypot Control Center</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
                padding: 20px;
                color: #333;
            }}
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                background: white;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #2c3e50, #34495e);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 2.5em;
                font-weight: 300;
            }}
            .header p {{
                margin: 10px 0 0 0;
                opacity: 0.8;
            }}
            .stats {{
                display: flex;
                justify-content: space-around;
                padding: 20px;
                background: #f8f9fa;
                border-bottom: 1px solid #dee2e6;
            }}
            .stat {{
                text-align: center;
                flex: 1;
            }}
            .stat h3 {{
                margin: 0;
                color: #495057;
                font-size: 0.9em;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
            .stat p {{
                margin: 5px 0 0 0;
                font-size: 2em;
                font-weight: bold;
                color: #007bff;
            }}
            .content {{
                padding: 30px;
            }}
            .actions {{
                margin-bottom: 20px;
                text-align: center;
            }}
            .btn {{
                display: inline-block;
                padding: 10px 20px;
                margin: 0 10px;
                background: #007bff;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                transition: background 0.3s;
            }}
            .btn:hover {{
                background: #0056b3;
            }}
            .btn-secondary {{
                background: #6c757d;
            }}
            .btn-secondary:hover {{
                background: #545b62;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #dee2e6;
            }}
            th {{
                background: #f8f9fa;
                font-weight: 600;
                color: #495057;
                text-transform: uppercase;
                font-size: 0.8em;
                letter-spacing: 1px;
            }}
            tr:hover {{
                background: #f8f9fa;
            }}
            .critical {{
                color: #dc3545;
                font-weight: bold;
            }}
            .info {{
                color: #17a2b8;
            }}
            .footer {{
                background: #f8f9fa;
                padding: 20px;
                text-align: center;
                border-top: 1px solid #dee2e6;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Honeypot Control Center</h1>
                <p>Monitor and analyze security threats in real-time</p>
            </div>
            <div class="stats">
                <div class="stat">
                    <h3>Total Events</h3>
                    <p>{len(logs)}</p>
                </div>
                <div class="stat">
                    <h3>Critical Alerts</h3>
                    <p>{sum(1 for log in logs if log['level'] == 'CRITICAL')}</p>
                </div>
                <div class="stat">
                    <h3>Unique IPs</h3>
                    <p>{len(set(log['ip'] for log in logs))}</p>
                </div>
                <div class="stat">
                    <h3>Active Monitoring</h3>
                    <p>ONLINE</p>
                </div>
            </div>
            <div class="content">
                <div class="actions">
                    <a href="/backend/dashboard?auth=admin123" class="btn">Admin Dashboard</a>
                    <a href="/" class="btn btn-secondary">Bank Portal</a>
                </div>
                <h2>Security Event Log</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>IP Address</th>
                            <th>Level</th>
                            <th>Action</th>
                            <th>User Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows}
                    </tbody>
                </table>
            </div>
            <div class="footer">
                <p>&copy; 2026 ZU-Bank Honeypot System | Real-time threat monitoring active</p>
            </div>
        </div>
    </body>
    </html>
    '''

# --- BACKEND ADMIN INTERFACE ---
@app.route('/backend/login', methods=['GET', 'POST'])
def backend_login():
    print("Backend login accessed")
    if request.method == 'POST':
        password = request.form.get('password')
        bank_trap(request.path, 'POST', {'password': password})
        print(f"Password entered: {password}")
        if password == 'admin123':  # Simple hardcoded password
            print("Password correct, redirecting to dashboard")
            return redirect('/backend/dashboard?auth=admin123')
        else:
            print("Password incorrect")
            return '<h1>Invalid Password</h1><a href="/backend/login">Try Again</a>'

    bank_trap(request.path, 'GET')
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Backend Admin Login</title>
        <style>
            body { font-family: Arial, sans-serif; background: #34495e; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .login-box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); text-align: center; width: 300px; }
            h3 { color: #2c3e50; margin-bottom: 20px; }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #e74c3c; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #c0392b; }
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
    </html>
    '''

@app.route('/backend/dashboard')
def backend_dashboard():
    print("Dashboard accessed")
    bank_trap(request.path, 'GET')
    # Simple auth check
    auth = request.args.get('auth')
    print(f"Auth param: {auth}")
    if auth != 'admin123':
        print("Auth failed, redirecting to login")
        return redirect('/backend/login')
    
    try:
        with open("bank_honeypot.log", "r", encoding="utf-8") as f:
            logs = f.read().split('\n')[-10:]  # Last 10 lines
            logs = '\n'.join(logs)
    except FileNotFoundError:
        logs = "No logs available yet."
    
    return f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Backend Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #ecf0f1; margin: 0; padding: 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            h2 {{ color: #2c3e50; text-align: center; }}
            .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
            .stat {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); text-align: center; flex: 1; margin: 0 10px; }}
            .stat h3 {{ color: #3498db; margin: 0; }}
            .stat p {{ font-size: 24px; color: #2c3e50; margin: 10px 0; }}
            .logs {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); margin-top: 20px; }}
            pre {{ background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; }}
            a {{ display: inline-block; margin: 10px; padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }}
            a:hover {{ background: #2980b9; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Honeypot Backend Dashboard</h2>
            <div class="stats">
                <div class="stat">
                    <h3>Total Visits</h3>
                    <p>{stats['visits']}</p>
                </div>
                <div class="stat">
                    <h3>Login Attempts</h3>
                    <p>{stats['logins']}</p>
                </div>
                <div class="stat">
                    <h3>Attacks Detected</h3>
                    <p>{stats['attacks']}</p>
                </div>
                <div class="stat">
                    <h3>Last Attack</h3>
                    <p>{stats['last_attack'] or 'None'}</p>
                </div>
            </div>
            <div class="logs">
                <h3>Recent Logs</h3>
                <pre>{logs}</pre>
            </div>
            <a href="/honeypot/logs">View Full Logs</a>
            <a href="/">Back to Honeypot</a>
        </div>
    </body>
    </html>
    '''


# ═══════════════════════════════════════════════════════════════════
#  PROFESSIONAL HQ DASHBOARD HTML
# ═══════════════════════════════════════════════════════════════════

HQ_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>HQ — Honeypot Command Center</title>
<style>
:root{
  --bg:#060a0e; --s1:#0b1015; --s2:#0f1820;
  --border:#162016; --green:#00ff88; --red:#ff4455; --amber:#ffaa00;
  --text:#b0d0b0; --text2:#3d6a3d;
}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:monospace;font-size:12px;}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,255,136,.01) 3px,rgba(0,255,136,.01) 4px);pointer-events:none;z-index:9999;}

.layout{display:grid;grid-template-columns:220px 1fr;grid-template-rows:52px 1fr;height:100vh;overflow:hidden;}

.topbar{grid-column:1/-1;display:flex;align-items:center;justify-content:space-between;padding:0 18px;border-bottom:1px solid var(--border);background:var(--s1);}
.brand{display:flex;align-items:center;gap:8px;font-size:16px;font-weight:bold;color:var(--green);}
.brand-icon{font-size:18px;}
.top-right{display:flex;align-items:center;gap:12px;}
.top-pill{display:flex;align-items:center;gap:5px;padding:3px 10px;border-radius:2px;border:1px solid var(--border);font-size:9px;letter-spacing:1px;}
.dot{width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 5px var(--green);animation:blink 1.2s infinite;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
#clock{font-size:11px;color:var(--text2);}

.sidebar{background:var(--s1);border-right:1px solid var(--border);padding:10px 0;overflow-y:auto;}
.nav-lbl{font-size:8px;letter-spacing:2px;color:var(--text2);padding:8px 14px 3px;text-transform:uppercase;}
.nb{display:flex;align-items:center;gap:7px;padding:8px 14px;border:none;background:none;color:var(--text2);font-family:monospace;font-size:10px;text-align:left;width:100%;cursor:pointer;border-left:2px solid transparent;transition:all .15s;letter-spacing:.5px;}
.nb:hover{background:rgba(0,255,136,.05);color:var(--text);}
.nb.active{background:rgba(0,255,136,.08);color:var(--green);border-left-color:var(--green);}

.main{overflow-y:auto;background:var(--bg);}
.page{display:none;padding:18px;}
.page.active{display:block;animation:fi .2s ease;}
@keyframes fi{from{opacity:0}to{opacity:1}}

.pg-title{font-size:18px;color:var(--green);letter-spacing:2px;margin-bottom:3px;font-weight:bold;}
.pg-sub{font-size:9px;color:var(--text2);margin-bottom:16px;}

.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:16px;}
.card{background:var(--s1);border:1px solid var(--border);border-radius:4px;padding:12px 14px;overflow:hidden;}
.card::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;}
.card.g::after{background:var(--green);}
.card.r::after{background:var(--red);}
.card.a::after{background:var(--amber);}
.card-lbl{font-size:8px;color:var(--text2);letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;}
.card-val{font-size:30px;font-weight:bold;line-height:1;}
.card.g .card-val{color:var(--green);}
.card.r .card-val{color:var(--red);}
.card.a .card-val{color:var(--amber);}

.panel{background:var(--s1);border:1px solid var(--border);border-radius:4px;overflow:hidden;margin-bottom:12px;}
.ph{display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--s2);border-bottom:1px solid var(--border);}
.pt{font-size:8px;letter-spacing:2px;color:var(--text2);text-transform:uppercase;}
.pb{font-size:8px;padding:2px 6px;border-radius:2px;background:rgba(0,255,136,.08);color:var(--green);}

.feed{max-height:220px;overflow-y:auto;}
.feed::-webkit-scrollbar{width:3px;}
.feed::-webkit-scrollbar-thumb{background:var(--border);}
.feed-hdr{display:grid;grid-template-columns:130px 95px 90px 65px 1fr;padding:5px 12px;font-size:8px;letter-spacing:1px;color:var(--text2);background:var(--s2);border-bottom:1px solid var(--border);text-transform:uppercase;}
.feed-row{display:grid;grid-template-columns:130px 95px 90px 65px 1fr;padding:5px 12px;border-bottom:1px solid rgba(22,32,22,.5);font-size:10px;}
.feed-row:hover{background:rgba(0,255,136,.02);}
.ft{color:var(--text2);}
.fi2{color:#44aaff;}
.fp{color:var(--amber);}
.fm-GET{color:var(--text2);}
.fm-POST{color:var(--red);}
.fua{color:var(--text2);font-size:9px;}

.empty{text-align:center;padding:24px;color:var(--text2);font-size:10px;}
.btn{padding:7px 16px;border:none;border-radius:2px;background:transparent;border:1px solid var(--border);color:var(--text2);font-family:monospace;font-size:11px;cursor:pointer;margin-bottom:16px;}
.btn:hover{border-color:var(--amber);color:var(--amber);}

.tl-item{padding:6px 10px;background:var(--s2);border:1px solid var(--border);border-radius:3px;margin-bottom:4px;font-size:9px;}
.tl-item.POST{border-left:2px solid var(--red);}
.tl-item.GET{border-left:2px solid var(--text2);}

#toasts{position:fixed;top:14px;right:14px;z-index:10000;display:flex;flex-direction:column;gap:5px;}
.toast{background:var(--s2);border:1px solid var(--red);border-left:3px solid var(--red);padding:8px 12px;border-radius:2px;font-size:10px;max-width:280px;animation:tin .3s;}
@keyframes tin{from{opacity:0;transform:translateX(10px)}to{opacity:1;transform:none}}
.toast-t{color:var(--red);font-size:8px;letter-spacing:1px;margin-bottom:2px;}
</style>
</head>
<body>
<div id="toasts"></div>

<div class="layout">
  <header class="topbar">
    <div class="brand">
      <div class="brand-icon">&#11041;</div>
      <div class="brand" style="flex-direction:column;gap:2px;font-size:14px;">
        <div style="line-height:1;">HONEYPOT HQ</div>
        <div style="font-size:8px;color:var(--text2);letter-spacing:2px;">INSPECTION MONITOR</div>
      </div>
    </div>
    <div class="top-right">
      <div class="top-pill"><div class="dot"></div><span>TRAPS ACTIVE</span></div>
      <a href="/" style="color:var(--text2);text-decoration:none;font-size:9px;padding:4px 10px;border:1px solid var(--border);border-radius:2px;">📜 Bank</a>
      <span id="clock">--:--:--</span>
    </div>
  </header>

  <nav class="sidebar">
    <div class="nav-lbl">Monitor</div>
    <button class="nb active" onclick="showPage('dash')"><span>■</span> Dashboard</button>
    <button class="nb" onclick="showPage('feed')"><span>◉</span> Live Feed</button>
    <button class="nb" onclick="showPage('creds')"><span>⚠</span> Credentials</button>
    <button class="nb" onclick="showPage('attackers')"><span>◆</span> Attackers</button>
  </nav>

  <main class="main">
    <div class="page active" id="page-dash">
      <div class="pg-title">DASHBOARD</div>
      <div class="pg-sub">REAL-TIME TRAP MONITORING — AUTO-REFRESH 2s</div>
      <button class="btn" onclick="clearLogs()">✕ CLEAR LOGS</button>
      
      <div class="cards">
        <div class="card r"><div class="card-lbl">Total Hits</div><div class="card-val" id="c-total">0</div></div>
        <div class="card a"><div class="card-lbl">Unique IPs</div><div class="card-val" id="c-ips">0</div></div>
        <div class="card g"><div class="card-lbl">GET Probes</div><div class="card-val" id="c-get">0</div></div>
        <div class="card r"><div class="card-lbl">POST Attacks</div><div class="card-val" id="c-post">0</div></div>
        <div class="card a"><div class="card-lbl">Creds Captured</div><div class="card-val" id="c-creds">0</div></div>
      </div>

      <div class="panel">
        <div class="ph"><span class="pt">Recent Trap Hits</span><span class="pb" id="feed-badge">0 HITS</span></div>
        <div class="feed-hdr"><span>Timestamp</span><span>IP</span><span>Trap</span><span>Method</span><span>User-Agent</span></div>
        <div class="feed" id="mini-feed"><div class="empty">No intrusions yet</div></div>
      </div>

      <div class="panel">
        <div class="ph"><span class="pt">Captured Credentials</span><span class="pb" id="dash-cred-badge">0</span></div>
        <div class="feed-hdr" style="grid-template-columns:110px 95px 80px 1fr 1fr;"><span>Time</span><span>IP</span><span>Trap</span><span>Username</span><span>Password</span></div>
        <div class="feed" id="dash-creds"><div class="empty">No credentials captured</div></div>
      </div>
    </div>

    <div class="page" id="page-feed">
      <div class="pg-title">LIVE FEED</div>
      <div class="pg-sub">ALL TRAP HITS IN REAL-TIME</div>
      <div class="panel">
        <div class="ph"><span class="pt">Event Stream</span></div>
        <div class="feed" style="max-height:600px;" id="full-feed"><div class="empty">Waiting for events...</div></div>
      </div>
    </div>

    <div class="page" id="page-creds">
      <div class="pg-title">CAPTURED CREDENTIALS</div>
      <div class="pg-sub">USERNAMES & PASSWORDS FROM TRAP SUBMISSIONS</div>
      <div class="panel">
        <div class="ph"><span class="pt">Credential Log</span></div>
        <div class="feed-hdr" style="grid-template-columns:110px 95px 80px 1fr 1fr;"><span>Time</span><span>IP</span><span>Trap</span><span>Username</span><span>Password</span></div>
        <div class="feed" style="max-height:600px;" id="creds-feed"><div class="empty">No credentials captured</div></div>
      </div>
    </div>

    <div class="page" id="page-attackers">
      <div class="pg-title">ATTACKER IPS</div>
      <div class="pg-sub">SORTED BY ACTIVITY LEVEL</div>
      <div class="panel">
        <div id="att-list"><div class="empty">No attackers yet</div></div>
      </div>
    </div>
  </main>
</div>

<script>
function showPage(n){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nb').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+n).classList.add('active');
  const nb = document.querySelector('.nb[onclick="showPage(\''+n+'\')"]');
  if(nb) nb.classList.add('active');
}

document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-GB');
setInterval(()=>{document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-GB');},1000);

function feedRow(e){
  return `<div class="feed-row">
    <span class="ft">${e.time}</span>
    <span class="fi2">${e.ip}</span>
    <span class="fp">${e.path}</span>
    <span class="fm-${e.method}">${e.method}</span>
    <span class="fua">${(e.ua||'').substring(0,35)}</span>
  </div>`;
}

function credRow(c){
  return `<div class="feed-row" style="grid-template-columns:110px 95px 80px 1fr 1fr;">
    <span style="color:var(--text2);font-size:9px;">${c.time}</span>
    <span style="color:#44aaff">${c.ip}</span>
    <span style="color:var(--amber)">${c.path}</span>
    <span style="color:#00ff88">${c.user||'—'}</span>
    <span style="color:#ff4455">${c.pass||'—'}</span>
  </div>`;
}

async function poll(){
  try{
    const d=await fetch('/hq/data').then(r=>r.json());
    document.getElementById('c-total').textContent=d.total;
    document.getElementById('c-ips').textContent=d.unique_ips;
    document.getElementById('c-get').textContent=d.get_hits;
    document.getElementById('c-post').textContent=d.post_hits;
    document.getElementById('c-creds').textContent=d.cred_count||0;
    document.getElementById('feed-badge').textContent=d.total+' HITS';
    document.getElementById('dash-cred-badge').textContent=(d.cred_count||0)+' CAPTURED';
    
    const mf=document.getElementById('mini-feed');
    mf.innerHTML=d.recent.length?d.recent.map(feedRow).join(''):'<div class="empty">No intrusions yet</div>';
    
    const ff=document.getElementById('full-feed');
    ff.innerHTML=d.recent.length?d.recent.map(feedRow).join(''):'<div class="empty">No events yet</div>';
    
    const cf=document.getElementById('creds-feed');
    cf.innerHTML=d.credentials.length?d.credentials.map(credRow).join(''):'<div class="empty">No credentials captured</div>';
    
    const dcf=document.getElementById('dash-creds');
    dcf.innerHTML=d.credentials.slice(-5).reverse().map(credRow).join('')||'<div class="empty">No credentials captured</div>';
    
    const byIp={};
    d.recent.forEach(e=>{
      if(!byIp[e.ip])byIp[e.ip]={hits:0,posts:0,paths:new Set()};
      byIp[e.ip].hits++;
      if(e.method==='POST')byIp[e.ip].posts++;
      byIp[e.ip].paths.add(e.path);
    });
    const ips=Object.entries(byIp).sort((a,b)=>b[1].hits-a[1].hits);
    const al=document.getElementById('att-list');
    if(!ips.length){al.innerHTML='<div class="empty">No attackers yet</div>';return;}
    al.innerHTML='<div style="padding:10px;"><div style="display:flex;flex-wrap:wrap;gap:8px;">'+
      ips.slice(0,20).map(([ip,s])=>`<div class="tl-item" style="flex:1;min-width:180px;">
        <div style="color:#44aaff;margin-bottom:4px;">${ip}</div>
        <div style="font-size:9px;color:var(--text2);">Hits: <span style="color:var(--amber);">${s.hits}</span> | POST: <span style="color:#ff4455;">${s.posts}</span> | Paths: <span style="color:var(--green);">${s.paths.size}</span></div>
      </div>`).join('')+
      '</div></div>';
  }catch(e){console.warn('poll error',e);}
}

async function clearLogs(){
  if(!confirm('Clear all trap logs? This cannot be undone.'))return;
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
    print("🛡️  ZU-BANK HONEYPOT STARTING ON PORT 5000...")
    app.run(host='0.0.0.0', port=5000)