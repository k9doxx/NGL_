from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, abort
)
import sqlite3
import hashlib
import uuid
import os
import secrets
from datetime import datetime
from functools import wraps

# ────────────────────────────────────────────
# Configuração do App
# ────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
DATABASE = "ngl_clone.db"


# ────────────────────────────────────────────
# Banco de Dados
# ────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            email         TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            display_name  TEXT    NOT NULL,
            bio           TEXT    DEFAULT '',
            avatar_emoji  TEXT    DEFAULT '😎',
            theme_color   TEXT    DEFAULT '#FF6B6B',
            bg_color      TEXT    DEFAULT '#0f0f23',
            card_color    TEXT    DEFAULT '#1a1a3e',
            text_color    TEXT    DEFAULT '#ffffff',
            link_id       TEXT    UNIQUE NOT NULL,
            created_at    TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS messages (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            content    TEXT    NOT NULL,
            hint       TEXT    DEFAULT '',
            is_read    INTEGER DEFAULT 0,
            is_starred INTEGER DEFAULT 0,
            created_at TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()


# ────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Faça login primeiro.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    if "user_id" not in session:
        return None
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    conn.close()
    return user


def time_ago(date_str):
    """Retorna tempo relativo em português."""
    now = datetime.utcnow()
    dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    diff = now - dt
    seconds = int(diff.total_seconds())
    if seconds < 60:
        return "agora mesmo"
    elif seconds < 3600:
        m = seconds // 60
        return f"há {m} min"
    elif seconds < 86400:
        h = seconds // 3600
        return f"há {h}h"
    else:
        d = seconds // 86400
        return f"há {d}d"


app.jinja_env.globals.update(time_ago=time_ago)


# ────────────────────────────────────────────
# ROTAS — Páginas Públicas
# ────────────────────────────────────────────
@app.route("/")
def index():
    user = get_current_user()
    return render_template("index.html", user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        display_name = request.form.get("display_name", "").strip()

        # Validações
        if not all([username, email, password, display_name]):
            flash("Preencha todos os campos.", "error")
            return redirect(url_for("register"))

        if len(username) < 3:
            flash("Username deve ter pelo menos 3 caracteres.", "error")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Senha deve ter pelo menos 6 caracteres.", "error")
            return redirect(url_for("register"))

        if password != confirm:
            flash("As senhas não coincidem.", "error")
            return redirect(url_for("register"))

        conn = get_db()
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email)
        ).fetchone()

        if existing:
            conn.close()
            flash("Username ou email já existe.", "error")
            return redirect(url_for("register"))

        link_id = str(uuid.uuid4())[:8]
        conn.execute(
            """INSERT INTO users
               (username, email, password_hash, display_name, link_id)
               VALUES (?, ?, ?, ?, ?)""",
            (username, email, hash_password(password), display_name, link_id)
        )
        conn.commit()

        user = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        session["user_id"] = user["id"]
        flash("Conta criada com sucesso! 🎉", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password_hash = ?",
            (username, hash_password(password))
        ).fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            flash("Login realizado! 🚀", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Username ou senha incorretos.", "error")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Você saiu da conta.", "info")
    return redirect(url_for("index"))


# ────────────────────────────────────────────
# ROTAS — Dashboard (Autenticado)
# ────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    conn = get_db()

    filter_type = request.args.get("filter", "all")

    if filter_type == "unread":
        messages = conn.execute(
            """SELECT * FROM messages
               WHERE user_id = ? AND is_read = 0
               ORDER BY created_at DESC""",
            (user["id"],)
        ).fetchall()
    elif filter_type == "starred":
        messages = conn.execute(
            """SELECT * FROM messages
               WHERE user_id = ? AND is_starred = 1
               ORDER BY created_at DESC""",
            (user["id"],)
        ).fetchall()
    else:
        messages = conn.execute(
            """SELECT * FROM messages
               WHERE user_id = ?
               ORDER BY created_at DESC""",
            (user["id"],)
        ).fetchall()

    total = conn.execute(
        "SELECT COUNT(*) as c FROM messages WHERE user_id = ?",
        (user["id"],)
    ).fetchone()["c"]

    unread = conn.execute(
        "SELECT COUNT(*) as c FROM messages WHERE user_id = ? AND is_read = 0",
        (user["id"],)
    ).fetchone()["c"]

    starred = conn.execute(
        "SELECT COUNT(*) as c FROM messages WHERE user_id = ? AND is_starred = 1",
        (user["id"],)
    ).fetchone()["c"]

    conn.close()

    base_url = request.host_url.rstrip("/")
    share_link = f"{base_url}/m/{user['link_id']}"

    return render_template(
        "dashboard.html",
        user=user, messages=messages,
        total=total, unread=unread, starred=starred,
        share_link=share_link, filter_type=filter_type
    )


@app.route("/message/<int:msg_id>/read", methods=["POST"])
@login_required
def mark_read(msg_id):
    conn = get_db()
    conn.execute(
        "UPDATE messages SET is_read = 1 WHERE id = ? AND user_id = ?",
        (msg_id, session["user_id"])
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/message/<int:msg_id>/star", methods=["POST"])
@login_required
def toggle_star(msg_id):
    conn = get_db()
    msg = conn.execute(
        "SELECT is_starred FROM messages WHERE id = ? AND user_id = ?",
        (msg_id, session["user_id"])
    ).fetchone()
    if msg:
        new_val = 0 if msg["is_starred"] else 1
        conn.execute(
            "UPDATE messages SET is_starred = ? WHERE id = ?",
            (new_val, msg_id)
        )
        conn.commit()
    conn.close()
    return jsonify({"ok": True, "starred": new_val if msg else 0})


@app.route("/message/<int:msg_id>/delete", methods=["POST"])
@login_required
def delete_message(msg_id):
    conn = get_db()
    conn.execute(
        "DELETE FROM messages WHERE id = ? AND user_id = ?",
        (msg_id, session["user_id"])
    )
    conn.commit()
    conn.close()
    flash("Mensagem apagada.", "info")
    return redirect(url_for("dashboard"))


@app.route("/messages/delete-all", methods=["POST"])
@login_required
def delete_all_messages():
    conn = get_db()
    conn.execute(
        "DELETE FROM messages WHERE user_id = ?", (session["user_id"],)
    )
    conn.commit()
    conn.close()
    flash("Todas as mensagens foram apagadas.", "info")
    return redirect(url_for("dashboard"))


# ────────────────────────────────────────────
# ROTAS — Configurações
# ────────────────────────────────────────────
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user = get_current_user()

    if request.method == "POST":
        display_name = request.form.get("display_name", user["display_name"])
        bio = request.form.get("bio", "")
        avatar_emoji = request.form.get("avatar_emoji", "😎")
        theme_color = request.form.get("theme_color", "#FF6B6B")
        bg_color = request.form.get("bg_color", "#0f0f23")
        card_color = request.form.get("card_color", "#1a1a3e")
        text_color = request.form.get("text_color", "#ffffff")

        conn = get_db()
        conn.execute(
            """UPDATE users SET
               display_name=?, bio=?, avatar_emoji=?,
               theme_color=?, bg_color=?, card_color=?, text_color=?
               WHERE id=?""",
            (display_name, bio, avatar_emoji, theme_color,
             bg_color, card_color, text_color, session["user_id"])
        )
        conn.commit()
        conn.close()

        flash("Configurações salvas! ✨", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html", user=user)


@app.route("/settings/password", methods=["POST"])
@login_required
def change_password():
    current = request.form.get("current_password", "")
    new_pass = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if new_pass != confirm:
        flash("As senhas não coincidem.", "error")
        return redirect(url_for("settings"))

    if len(new_pass) < 6:
        flash("Senha deve ter pelo menos 6 caracteres.", "error")
        return redirect(url_for("settings"))

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ? AND password_hash = ?",
        (session["user_id"], hash_password(current))
    ).fetchone()

    if not user:
        conn.close()
        flash("Senha atual incorreta.", "error")
        return redirect(url_for("settings"))

    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (hash_password(new_pass), session["user_id"])
    )
    conn.commit()
    conn.close()
    flash("Senha alterada com sucesso!", "success")
    return redirect(url_for("settings"))


# ────────────────────────────────────────────
# ROTAS — Envio de Mensagem Anônima (Pública)
# ────────────────────────────────────────────
@app.route("/m/<link_id>", methods=["GET", "POST"])
def send_message(link_id):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE link_id = ?", (link_id,)
    ).fetchone()

    if not user:
        conn.close()
        abort(404)

    if request.method == "POST":
        content = request.form.get("message", "").strip()
        hint = request.form.get("hint", "").strip()

        if not content:
            flash("Escreva uma mensagem.", "error")
            return redirect(url_for("send_message", link_id=link_id))

        if len(content) > 500:
            flash("Mensagem muito longa (máx 500 caracteres).", "error")
            return redirect(url_for("send_message", link_id=link_id))

        conn.execute(
            "INSERT INTO messages (user_id, content, hint) VALUES (?, ?, ?)",
            (user["id"], content, hint)
        )
        conn.commit()
        conn.close()
        return render_template("shared.html", user=user, sent=True)

    conn.close()
    return render_template("send_message.html", user=user)


# ────────────────────────────────────────────
# ROTAS — API
# ────────────────────────────────────────────
@app.route("/api/messages/count")
@login_required
def api_message_count():
    conn = get_db()
    unread = conn.execute(
        "SELECT COUNT(*) as c FROM messages WHERE user_id = ? AND is_read = 0",
        (session["user_id"],)
    ).fetchone()["c"]
    conn.close()
    return jsonify({"unread": unread})


# ────────────────────────────────────────────
# Error handlers
# ────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template("index.html", user=get_current_user(), error=True), 404


# ────────────────────────────────────────────
# Inicialização
# ────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print("  🔥 NGL Clone rodando!")
    print("  📌 Acesse: http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)
