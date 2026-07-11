"""
VulnShop — Aplicación Flask intencionalmente vulnerable para prácticas de DAST.

ADVERTENCIA: Este código contiene vulnerabilidades INTENCIONALES con fines educativos.
NO desplegar en producción ni en sistemas accesibles públicamente.
"""

from flask import Flask, request, render_template, redirect, make_response, session
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = "supersecretkey123"


@app.after_request
def add_fake_server_headers(response):
    # CWE-200: Information Disclosure — headers que revelan tecnología obsoleta
    response.headers["Server"] = "Apache/2.2.14 (Win32)"
    response.headers["X-Powered-By"] = "PHP/5.3.3"
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/search")
def search():
    # CWE-79: XSS Reflected (GET)
    # Markup() desactiva el auto-escape de Jinja2 — el input del usuario se renderiza como HTML
    query = request.args.get("q", "")
    safe_query = Markup(query)
    return render_template("search.html", query=safe_query)


@app.route("/comment", methods=["GET", "POST"])
def comment():
    result = None
    if request.method == "POST":
        # CWE-79: XSS Reflected (POST)
        name = Markup(request.form.get("name", ""))
        message = Markup(request.form.get("message", ""))
        result = {"name": name, "message": message}
    return render_template("comment.html", result=result)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        response = make_response(redirect("/profile"))
        # CWE-113: Header Injection — sin sanitizar \r\n en el valor del header
        response.headers["X-Logged-User"] = username
        session["user"] = username
        return response
    return render_template("login.html")


@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    # CWE-601: Open Redirect + CWE-113: CRLF Injection
    # Sin validar dominio ni sanitizar saltos de línea
    response = make_response("", 302)
    response.headers["Location"] = url
    return response


@app.route("/newsletter", methods=["GET", "POST"])
def newsletter():
    message = None
    if request.method == "POST":
        lang = request.form.get("lang", "es")
        response = make_response(render_template("newsletter.html", message="Suscrito correctamente."))
        # CWE-113: Header Injection en Content-Language
        response.headers["Content-Language"] = lang
        return response
    return render_template("newsletter.html", message=message)


@app.route("/profile")
def profile():
    user = session.get("user", "invitado")
    response = make_response(render_template("profile.html", user=user))
    # CWE-614: Insecure Cookie — sin HttpOnly, Secure ni SameSite
    response.set_cookie("session_user", user)
    return response


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
