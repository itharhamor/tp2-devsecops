"""Application Flask de démonstration pour le TP2 DevSecOps (version SÉCURISÉE)."""
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)

USERS = [("alice", "admin"), ("bob", "user")]


def get_db():
    """Base SQLite en mémoire, recréée à chaque requête (démo uniquement)."""
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
    # Les liens permettent au spider de ZAP de découvrir toutes les routes.
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
    # Aucune commande système : on construit simplement la chaîne.
    return jsonify(message=f"Bonjour {name}")


@app.get("/user")
def user():
    name = request.args.get("name", "")
    conn = get_db()
    # Requête paramétrée -> pas d'injection SQL possible.
    row = conn.execute("SELECT name, role FROM users WHERE name = ?", (name,)).fetchone()
    conn.close()
    if row is None:
        return jsonify(error="introuvable"), 404
    return jsonify(name=row[0], role=row[1])
