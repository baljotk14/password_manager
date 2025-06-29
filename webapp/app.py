import os, sys, base64
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
import bcrypt

# allow imports of vault.py/storage.py from parent
sys.path.insert(0, os.path.abspath(os.path.join(__file__, "..")))

from storage import load_users, save_users, load_vault, save_vault
from vault   import derive_key, encrypt_entry, decrypt_entry

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("FLASK_SECRET", "CHANGE_THIS")

USERS_FILE = os.path.join("..","data","users.json")


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        users = load_users(USERS_FILE)
        u = request.form["username"].strip()
        pw = request.form["password"].encode()

        if u in users:
            flash("Username taken", "error")
        else:
            # bcrypt‐hash
            pw_hash = bcrypt.hashpw(pw, bcrypt.gensalt()).decode()
            # per‐user salt for KDF
            salt = base64.b64encode(os.urandom(16)).decode()

            users[u] = {
                "pw":   pw_hash,
                "salt": salt
            }
            save_users(USERS_FILE, users)
            flash("Registered - please log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        users = load_users(USERS_FILE)
        u = request.form["username"].strip()
        pw = request.form["password"].encode()

        userrec = users.get(u)
        # check structure and bcrypt check
        if (not userrec
            or not bcrypt.checkpw(pw, userrec["pw"].encode())):
            flash("Invalid credentials", "error")
        else:
            # derive vault‐key with their salt
            salt_bytes = base64.b64decode(userrec["salt"])
            key = derive_key(pw, salt_bytes)  # bytes
            session["username"] = u
            session["key"]      = key.decode()  # store as str
            return redirect(url_for("vault_add"))

    return render_template("login.html")


@app.route("/vault", methods=["GET","POST"])
def vault_add():
    if "username" not in session:
        return redirect(url_for("login"))

    user = session["username"]
    key  = session["key"].encode()

    if request.method == "POST":
        svc    = request.form["service"].strip()
        login_ = request.form["login"].strip()
        pwd    = request.form["password"]
        token  = encrypt_entry(key, pwd)

        entries = load_vault(user)
        entries.append({
            "service":  svc,
            "login":    login_,
            "password": token
        })
        save_vault(user, entries)
        flash(f"Added {svc}", "success")
        return redirect(url_for("vault_add"))

    return render_template("add_credentials.html", username=user)


@app.route("/vault/list")
def vault_list():
    if "username" not in session:
        return redirect(url_for("login"))
    entries = load_vault(session["username"])
    return render_template("entries.html", entries=entries)


#
# ─── TWO-STEP “REVEAL” FLOWS ────────────────────────────────────────────────────
#

# STEP 1: GET the form that asks “Enter your master password…”
@app.route("/vault/reveal/<int:idx>", methods=["GET"])
def reveal_form(idx):
    if "username" not in session:
        return redirect(url_for("login"))

    entries = load_vault(session["username"])
    if idx < 0 or idx >= len(entries):
        flash("Invalid entry", "error")
        return redirect(url_for("vault_list"))

    # render the unlock form
    return render_template(
        "reveal.html",
        idx=idx,
        service=entries[idx]["service"]
    )


# STEP 2: POST that master password, re-derive, decrypt
@app.route("/vault/reveal/<int:idx>", methods=["POST"])
def reveal_unlock(idx):
    if "username" not in session:
        return redirect(url_for("login"))

    # the password they just typed
    master_pw = request.form["master_pw"].encode()

    # re-derive via stored salt
    users   = load_users(USERS_FILE)
    userrec = users[session["username"]]
    salt    = base64.b64decode(userrec["salt"])
    guess   = derive_key(master_pw, salt)

    real_key = session["key"].encode()
    if guess != real_key:
        flash("Wrong master password", "error")
        return redirect(url_for("vault_list"))

    # OK: decrypt and flash it
    entries    = load_vault(session["username"])
    ciphertext = entries[idx]["password"]
    plain      = decrypt_entry(real_key, ciphertext)
    flash(f"<strong>{entries[idx]['service']}</strong>: {plain}", "info")
    return redirect(url_for("vault_list"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
