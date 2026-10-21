"""VERSION VOLONTAIREMENT VULNÉRABLE - à copier sur app.py dans la branche de démo.

Deux failles introduites :
  1. /greet : injection de commande OS (subprocess + shell=True + entrée utilisateur)
  2. /user  : injection SQL (requête construite par concaténation)
"""
import sqlite3
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

USERS = [("alice", "admin"), ("bob", "user")]


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (name TEXT, role TEXT)")
    conn.executemany("INSERT INTO users VALUES (?, ?)", USERS)
    return conn


@app.after_request
def security_headers(resp):
    """En-têtes de sécurité HTTP (réduit les alertes ZAP)."""
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'"
    )
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.get("/")
def index():
    return (
        "<!doctype html><html><head><title>TP2 DevSecOps</title></head><body>"
        "<h1>TP2 DevSecOps</h1><ul>"
        '<li><a href="/health">health</a></li>'
        '<li><a href="/greet?name=alice">greet</a></li>'
        '<li><a href="/user?name=alice">user</a></li>'
        "</ul></body></html>"
    )


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/greet")
def greet():
    name = request.args.get("name", "")
    # ❌ VULNÉRABLE : l'entrée utilisateur est passée à un shell.
    # Exemple d'attaque : /greet?name=x;cat /etc/passwd
    output = subprocess.check_output(f"echo Bonjour {name}", shell=True, text=True)
    return jsonify(message=output)


@app.get("/user")
def user():
    name = request.args.get("name", "")
    conn = get_db()
    # ❌ VULNÉRABLE : concaténation -> injection SQL
    # Exemple d'attaque : /user?name=x' OR '1'='1
    row = conn.execute(f"SELECT name, role FROM users WHERE name = '{name}'").fetchone()
    conn.close()
    if row is None:
        return jsonify(error="introuvable"), 404
    return jsonify(name=row[0], role=row[1])
