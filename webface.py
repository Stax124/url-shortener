import functools
from sqlite3 import IntegrityError

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from sqlitewrap import SQLite

app = Flask(__name__)
app.secret_key = b"totoj e zceLa n@@@hodny retezec nejlep os.urandom(24)"
app.secret_key = b"x6\x87j@\xd3\x88\x0e8\xe8pM\x13\r\xafa\x8b\xdbp\x8a\x1f\xd41\xb8"


slova = ("Super", "Perfekt", "Úža", "Flask")


def prihlasit(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        if "user" in session:
            return function(*args, **kwargs)
        else:
            return redirect(url_for("login", url=request.path))

    return wrapper


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html")


@app.route("/login/", methods=["POST"])
def login_post():
    jmeno = request.form.get("username", "")
    heslo = request.form.get("password", "")
    url = request.args.get("url", "")  # url je obsažena v adrese, proto request args
    with SQLite("data.sqlite") as cursor:
        db_response = cursor.execute(
            "SELECT login, password FROM user WHERE login = ?", [jmeno]
        )
        db_response = db_response.fetchone()
        if db_response:
            login, password = db_response
            if check_password_hash(password, heslo):
                session["user"] = jmeno
                flash("Logged in!", "success")
                if url:
                    return redirect(url)
                else:
                    return redirect(url_for("index"))
            else:
                flash("Incorrect login details!", "error")
        else:
            flash("Incorrect login details!", "error")
        return redirect(url_for("login", url=url))


@app.route("/register", methods=["GET"])
def registration():
    return render_template("register.html")


@app.route("/register", methods=["POST"])
def registration_post():
    username = request.form.get("username", "")
    password1 = request.form.get("password1", "")
    password2 = request.form.get("password2", "")
    if len(username) < 5:
        flash("Name needs to be at least 5 characters!", "error")
    if len(password1) < 8:
        flash("Password needs to be at least 8 characters!", "error")
    if password1 != password2:
        flash("Password validation failed", "error")
        return redirect(url_for("registration"))
    hash_ = generate_password_hash(password1)
    try:
        with SQLite("data.sqlite") as cursor:
            cursor.execute(
                "INSERT INTO user (login,password) VALUES (?,?)", [username, hash_]
            )
        flash(f"Uživatel `{username}` byl přidán!", "success")
    except IntegrityError:
        flash("Uživatel již existuje!", "error")

    return redirect(url_for("registration"))


@app.route("/logout", methods=["GET"])
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))
