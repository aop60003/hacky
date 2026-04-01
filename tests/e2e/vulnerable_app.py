"""Intentionally vulnerable Flask app for E2E testing VIBEE-Hacker."""

from flask import Flask, request, redirect, make_response

app = Flask(__name__)
app.secret_key = "super_secret_key_123"  # Hardcoded secret

# --- HOME ---
@app.route("/")
def home():
    return """<html>
<head><meta name="generator" content="WordPress 5.0"></head>
<body>
<h1>Vulnerable Test App</h1>
<a href="/search?q=test">Search</a>
<a href="/login">Login</a>
<a href="/profile/1">Profile</a>
<form action="/comment" method="POST">
    <textarea name="comment"></textarea>
    <input name="name" type="text">
    <input type="submit">
</form>
<script>fetch('/api/users')</script>
<script src="/static/app.js"></script>
</body></html>"""

# --- SQL INJECTION (error-based) ---
@app.route("/search")
def search():
    q = request.args.get("q", "")
    if "'" in q:
        return "You have an error in your SQL syntax near '" + q + "'", 500
    return f"<html><body>Results for: {q}</body></html>"

# --- XSS (reflected) ---
@app.route("/comment", methods=["POST"])
def comment():
    name = request.form.get("name", "")
    comment = request.form.get("comment", "")
    return f"<html><body><p>Comment by {name}: {comment}</p></body></html>"

# --- OPEN REDIRECT ---
@app.route("/redirect")
def open_redir():
    url = request.args.get("url", "/")
    return redirect(url)

# --- IDOR ---
@app.route("/profile/<int:user_id>")
def profile(user_id):
    users = {1: "Alice", 2: "Bob", 3: "Charlie"}
    name = users.get(user_id, "Unknown")
    return f'{{"id": {user_id}, "name": "{name}", "email": "{name.lower()}@test.com"}}'

# --- MISSING HEADERS ---
@app.route("/api/users")
def api_users():
    resp = make_response('[{"id":1,"name":"Alice","email":"alice@test.com","password":"hashed_pw"}]')
    resp.headers["Content-Type"] = "application/json"
    # Missing: CSP, X-Frame-Options, HSTS, X-Content-Type-Options
    return resp

# --- DEBUG ENDPOINT ---
@app.route("/debug")
def debug_info():
    return "<html><body>Traceback (most recent call last):\n  File 'app.py', line 42\nDjango Debug Mode</body></html>"

# --- SENSITIVE FILE ---
@app.route("/.env")
def env_file():
    return "DB_PASSWORD=supersecret123\nAPI_KEY=sk_test_abc123def456ghi789\nSECRET_KEY=mysecret"

@app.route("/.git/config")
def git_config():
    return "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/test/repo.git"

# --- CORS MISCONFIGURATION ---
@app.route("/api/data")
def cors_data():
    origin = request.headers.get("Origin", "")
    resp = make_response('{"data": "sensitive"}')
    resp.headers["Access-Control-Allow-Origin"] = origin  # Reflects any origin!
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

# --- STATIC JS with API key ---
@app.route("/static/app.js")
def static_js():
    return 'var apiKey = "abcdefghijklmnopqrstuvwxyz123456";\nfetch("/api/users");'

# --- LOGIN (weak) ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == "admin" and password == "admin":
            resp = make_response("Welcome to the dashboard! <a href='/logout'>Logout</a>")
            resp.set_cookie("session", "abc123", httponly=False)  # Missing Secure, SameSite
            return resp
        return "Invalid credentials", 401
    return '<html><form method="POST"><input name="username"><input name="password" type="password"><button>Login</button></form></html>'

# --- SSL/CORS info in headers ---
@app.after_request
def add_headers(response):
    response.headers["Server"] = "Apache/2.4.49 (Ubuntu)"
    response.headers["X-Powered-By"] = "PHP/7.4.3"
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5555, debug=False)
