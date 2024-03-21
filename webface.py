import functools
import random
import uuid
from pathlib import Path
from sqlite3 import IntegrityError
from typing import Union

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from sqlitewrap import SQLite

app = Flask(__name__)
app.secret_key = b"totoj e zceLa n@@@hodny retezec nejlep os.urandom(24)"
app.secret_key = b"x6\x87j@\xd3\x88\x0e8\xe8pM\x13\r\xafa\x8b\xdbp\x8a\x1f\xd41\xb8"


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
    short_url = request.args.get("short_url")

    return render_template("index.html", short_url=short_url)


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

    print(f"{username=}, {password1=}, {password2=}")

    if len(username) < 5:
        flash("Name needs to be at least 5 characters!", "error")
        return redirect(url_for("registration"))
    if len(password1) < 8:
        flash("Password needs to be at least 8 characters!", "error")
        return redirect(url_for("registration"))
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

    return redirect(url_for("login"))


def generate_short_url():
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choices(chars, k=8))


@app.route("/generate-url", methods=["POST"])
def generate_url():
    user_id: Union[int, None] = None

    full_url = request.form.get("url")
    short_url = generate_short_url()

    if "user" in session:
        username = session["user"]
        with SQLite("data.sqlite") as cursor:
            user_result = cursor.execute("SELECT * FROM user WHERE login=?", [username])
            user_result = user_result.fetchone()
            if user_result:
                user_id = user_result[0]

            else:
                flash("User not found!", "error")
                return redirect(url_for("index"))

    with SQLite("data.sqlite") as cursor:
        cursor.execute(
            "INSERT INTO url (full_url, short_url, generated_by) VALUES (?,?,?)",
            [full_url, short_url, user_id],
        )

    return redirect(url_for("index", short_url=request.url_root + short_url))


@app.route("/logout", methods=["GET"])
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))


@app.route("/<short_url>", methods=["GET"])
def redirect_to_full_url(short_url):
    with SQLite("data.sqlite") as cursor:
        result = cursor.execute(
            "SELECT full_url FROM url WHERE short_url=?", [short_url]
        )
        result = result.fetchone()

        # Increment url.clicks by 1
        cursor.execute(
            "UPDATE url SET clicks = clicks + 1 WHERE short_url=?", [short_url]
        )

        if result:
            full_url = result[0]
            return redirect(full_url)
        else:
            return redirect(url_for("page_not_found"))


@app.route("/404/", methods=["GET"])
def page_not_found():
    return render_template("404.html")


@app.route("/my-urls", methods=["GET"])
@prihlasit
def my_urls():
    username = session["user"]
    with SQLite("data.sqlite") as cursor:
        user_result = cursor.execute("SELECT * FROM user WHERE login=?", [username])
        user_result = user_result.fetchone()
        if user_result:
            user_id = user_result[0]
        else:
            flash("User not found!", "error")
            return redirect(url_for("index"))

    with SQLite("data.sqlite") as cursor:
        result = cursor.execute(
            "SELECT short_url, full_url, clicks FROM url WHERE generated_by=?",
            [user_id],
        )
        result = result.fetchall()
        return render_template("my-urls.html", urls=result)


@app.route("/upload", methods=["GET"])
def upload():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
def upload_post():
    if "file" not in request.files:
        flash("No file part")
        return redirect(request.url)

    file = request.files["file"]
    file_handle = uuid.uuid4().hex
    filename = file.filename

    if filename == "":
        flash("No selected file")
        return redirect(request.url)

    username = session.get("user")
    user_id = None
    with SQLite("data.sqlite") as cursor:
        user_result = cursor.execute("SELECT * FROM user WHERE login=?", [username])
        user_result = user_result.fetchone()
        if user_result:
            user_id = user_result[0]

    with SQLite("data.sqlite") as cursor:
        user_result = cursor.execute(
            """
        INSERT INTO files (filename, file_handle, owner) VALUES (?,?,?)                             
        """,
            [filename, file_handle, user_id],
        )

    file.save(Path("uploads") / file_handle)

    return redirect(url_for("upload"))
