# -*- coding: utf-8 -*-
import os
import csv
import io
import psycopg2
import secrets
import hashlib
import re
from psycopg2.extras import RealDictCursor
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, Response, session, send_file, jsonify, g
from flask_wtf.csrf import CSRFError, CSRFProtect
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta, date


load_dotenv()


def get_required_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"環境変数 {name} が設定されていません。")
    return value


app = Flask(__name__)
app.secret_key = get_required_env("SECRET_KEY")
app.json.ensure_ascii = False
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
    WTF_CSRF_CHECK_DEFAULT=False
)
csrf = CSRFProtect(app)


@app.before_request
def protect_web_forms_from_csrf():
    if not request.path.startswith("/api/"):
        csrf.protect()

CSV_FOLDER = "csv"
MEMBER_CSV_HEADERS = ["name", "group_name", "category", "note"]
MAX_MEMBER_CSV_SIZE = 2 * 1024 * 1024
os.makedirs(CSV_FOLDER, exist_ok=True)


def get_db_connection():
    conn = psycopg2.connect(
        host=get_required_env("DB_HOST"),
        database=get_required_env("DB_NAME"),
        user=get_required_env("DB_USER"),
        password=get_required_env("DB_PASSWORD"),
        port=get_required_env("DB_PORT"),
        cursor_factory=RealDictCursor
    )
    return conn


def add_audit_log(
    action, activity_id=None, target_type=None, target_id=None,
    description=None, user_id=None
):
    """Record an audit event without breaking the main operation on failure."""
    conn = None
    cur = None
    try:
        actor_user_id = user_id
        if actor_user_id is None:
            actor_user_id = session.get("user_id") or getattr(g, "user_id", None)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_logs (
                user_id, activity_id, action, target_type, target_id, description
            ) VALUES (%s, %s, %s, %s, %s, %s);
            """,
            (actor_user_id, activity_id, action, target_type, target_id, description)
        )
        conn.commit()
    except Exception:
        if conn is not None:
            conn.rollback()
        app.logger.exception("操作ログの登録に失敗しました。")
    finally:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.close()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        expires_at = session.get("expires_at")

        if expires_at is None:
            session.clear()
            return redirect(url_for("login"))

        expires_at_datetime = datetime.fromisoformat(expires_at)

        if datetime.now() > expires_at_datetime:
            session.clear()
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


def get_user_role_for_activity(activity_id, user_id):
    if user_id is None:
        return None

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT role FROM activity_users WHERE activity_id = %s AND user_id = %s;",
        (activity_id, user_id)
    )
    activity_user = cur.fetchone()
    cur.close()
    conn.close()
    return activity_user["role"] if activity_user else None


def require_activity_role(*allowed_roles, api=False):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            activity_id = kwargs.get("activity_id")
            if activity_id is None and args:
                activity_id = args[0]

            user_id = session.get("user_id") or getattr(g, "user_id", None)
            role = get_user_role_for_activity(activity_id, user_id)

            if role is None:
                if api:
                    return api_error("この活動は存在しないか、アクセス権限がありません。", 404)
                return "この活動は存在しないか、アクセス権限がありません。", 404

            if role not in allowed_roles:
                if api:
                    return api_error("この操作を行う権限がありません。", 403)
                return "この操作を行う権限がありません。", 403

            g.activity_role = role
            return view(*args, **kwargs)

        return wrapped_view
    return decorator


EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def get_current_user():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, email FROM users WHERE id = %s;",
        (session["user_id"],)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user


def render_account(error=None, status_code=200):
    user = get_current_user()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    return render_template(
        "account.html",
        user=user,
        error=error,
        message=request.args.get("message")
    ), status_code


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_valid_date_string(value):
    if not isinstance(value, str) or not value:
        return False

    try:
        date.fromisoformat(value)
    except ValueError:
        return False

    return True


def api_success(data=None, message=None, status_code=200):
    response = {
        "success": True
    }

    if message is not None:
        response["message"] = message

    if data is not None:
        response["data"] = data

    return jsonify(response), status_code


def api_error(error, status_code=400):
    return jsonify({
        "success": False,
        "error": error
    }), status_code


def api_login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return api_error("認証トークンが必要です。", 401)

        token = auth_header.replace("Bearer ", "", 1).strip()

        if not token:
            return api_error("認証トークンが必要です。", 401)

        token_hash = hash_token(token)

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                api_tokens.id,
                api_tokens.user_id,
                api_tokens.expires_at,
                users.username
            FROM api_tokens
            JOIN users ON api_tokens.user_id = users.id
            WHERE api_tokens.token_hash = %s
              AND users.is_active = TRUE;
            """,
            (token_hash,)
        )

        token_data = cur.fetchone()

        if token_data is None:
            cur.close()
            conn.close()
            return api_error("無効なトークンです。", 401)

        if datetime.now() > token_data["expires_at"]:
            cur.execute(
                """
                DELETE FROM api_tokens
                WHERE id = %s;
                """,
                (token_data["id"],)
            )

            conn.commit()
            cur.close()
            conn.close()

            return api_error("トークンの有効期限が切れています。", 401)

        g.user_id = token_data["user_id"]
        g.username = token_data["username"]

        cur.close()
        conn.close()

        return view(*args, **kwargs)

    return wrapped_view


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember")

        if not username or not password:
            return render_template(
                "login.html",
                error="ユーザー名とパスワードを入力してください。"
            ), 400

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT * FROM users WHERE username = %s AND is_active = TRUE;",
            (username,)
        )
        user = cur.fetchone()

        cur.close()
        conn.close()

        if user is not None and check_password_hash(user["password_hash"], password):
            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            if remember == "on":
                session["expires_at"] = (datetime.now() + timedelta(days=30)).isoformat()
            else:
                session["expires_at"] = (datetime.now() + timedelta(minutes=30)).isoformat()

            add_audit_log("web_login", target_type="user", target_id=user["id"], description="Webログインに成功しました。")

            return redirect(url_for("index"))
        else:
            error = "ユーザー名またはパスワードが違います。"

    return render_template("login.html", error=error, message=request.args.get("message"))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    username = ""
    email = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username:
            error = "ユーザー名を入力してください。"
        elif len(username) > 100:
            error = "ユーザー名は100文字以内で入力してください。"
        elif not email:
            error = "メールアドレスを入力してください。"
        elif len(email) > 255:
            error = "メールアドレスは255文字以内で入力してください。"
        elif EMAIL_PATTERN.fullmatch(email) is None:
            error = "有効なメールアドレスを入力してください。"
        elif not password:
            error = "パスワードを入力してください。"
        elif len(password) < 8:
            error = "パスワードは8文字以上で入力してください。"
        elif password != confirm_password:
            error = "パスワードと確認用パスワードが一致しません。"

        if error is None:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = %s;", (username,))
            if cur.fetchone() is not None:
                error = "そのユーザー名は既に使用されています。"
            else:
                cur.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(%s);", (email,))
                if cur.fetchone() is not None:
                    error = "そのメールアドレスは既に使用されています。"

            if error is None:
                try:
                    cur.execute(
                        """
                        INSERT INTO users (username, email, password_hash)
                        VALUES (%s, %s, %s)
                        RETURNING id;
                        """,
                        (username, email, generate_password_hash(password))
                    )
                    user_id = cur.fetchone()["id"]
                    conn.commit()
                except psycopg2.IntegrityError:
                    conn.rollback()
                    error = "ユーザー名またはメールアドレスは既に使用されています。"

            cur.close()
            conn.close()

            if error is None:
                add_audit_log(
                    "user_register", target_type="user", target_id=user_id,
                    description="Webから新規ユーザー登録を行いました。", user_id=user_id
                )
                return redirect(url_for(
                    "login",
                    message="登録が完了しました。ログインしてください。"
                ))

    return render_template(
        "register.html", error=error, username=username, email=email
    ), 400 if error else 200


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    message = None

    if request.method == "POST":
        email = request.form.get("email", "").strip()

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT id
            FROM users
            WHERE LOWER(email) = LOWER(%s)
              AND is_active = TRUE;
            """,
            (email,)
        )
        user = cur.fetchone()

        if user is not None:
            token = secrets.token_urlsafe(32)
            token_hash = hash_token(token)
            expires_at = datetime.now() + timedelta(minutes=30)

            cur.execute(
                """
                INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
                VALUES (%s, %s, %s);
                """,
                (user["id"], token_hash, expires_at)
            )
            conn.commit()

            reset_url = f"http://127.0.0.1:5000/reset_password/{token}"
            print(f"パスワード再設定URL: {reset_url}")

        cur.close()
        conn.close()

        # メールアドレスの登録有無を推測されないよう、常に同じ文言を表示する。
        message = "入力されたメールアドレス宛に、再設定用の案内を送信しました。"

    return render_template("forgot_password.html", message=message)


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hash_token(token)
    error = None

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "GET":
        cur.execute(
            """
            SELECT id
            FROM password_reset_tokens
            WHERE token_hash = %s
              AND used_at IS NULL
              AND expires_at > %s;
            """,
            (token_hash, datetime.now())
        )
        reset_token = cur.fetchone()

        cur.close()
        conn.close()

        if reset_token is None:
            return render_template(
                "reset_password.html",
                error="この再設定URLは無効、有効期限切れ、または使用済みです。",
                show_form=False
            ), 400

        return render_template("reset_password.html", show_form=True)

    # 同じトークンによる同時更新を防ぐため、検証対象の行をロックする。
    cur.execute(
        """
        SELECT id, user_id
        FROM password_reset_tokens
        WHERE token_hash = %s
          AND used_at IS NULL
          AND expires_at > %s
        FOR UPDATE;
        """,
        (token_hash, datetime.now())
    )
    reset_token = cur.fetchone()

    if reset_token is None:
        cur.close()
        conn.close()
        return render_template(
            "reset_password.html",
            error="この再設定URLは無効、有効期限切れ、または使用済みです。",
            show_form=False
        ), 400

    password = request.form.get("password", "")
    password_confirm = request.form.get("password_confirm", "")

    if not password:
        error = "新しいパスワードを入力してください。"
    elif password != password_confirm:
        error = "パスワードと確認用パスワードが一致しません。"

    if error is not None:
        conn.rollback()
        cur.close()
        conn.close()
        return render_template(
            "reset_password.html",
            error=error,
            show_form=True
        ), 400

    password_hash = generate_password_hash(password)

    cur.execute(
        """
        UPDATE users
        SET password_hash = %s
        WHERE id = %s;
        """,
        (password_hash, reset_token["user_id"])
    )
    cur.execute(
        """
        UPDATE password_reset_tokens
        SET used_at = %s
        WHERE id = %s;
        """,
        (datetime.now(), reset_token["id"])
    )

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log(
        "password_reset", target_type="user", target_id=reset_token["user_id"],
        description="パスワード再設定を完了しました。", user_id=reset_token["user_id"]
    )

    return render_template(
        "reset_password.html",
        message="パスワードを再設定しました。新しいパスワードでログインしてください。",
        show_form=False
    )


@app.route("/logout")
def logout():
    add_audit_log("web_logout", target_type="user", target_id=session.get("user_id"), description="Webからログアウトしました。")
    session.clear()
    return redirect(url_for("login"))


@app.route("/account")
@login_required
def account():
    return render_account()


@app.route("/account/update_username", methods=["POST"])
@login_required
def update_username():
    username = request.form.get("username", "").strip()

    if not username:
        return render_account("ユーザー名を入力してください。", 400)
    if len(username) > 100:
        return render_account("ユーザー名は100文字以内で入力してください。", 400)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM users WHERE username = %s AND id <> %s;",
        (username, session["user_id"])
    )

    if cur.fetchone() is not None:
        cur.close()
        conn.close()
        return render_account("そのユーザー名は既に使用されています。", 400)

    try:
        cur.execute(
            "UPDATE users SET username = %s WHERE id = %s;",
            (username, session["user_id"])
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        cur.close()
        conn.close()
        return render_account("そのユーザー名は既に使用されています。", 400)

    cur.close()
    conn.close()
    session["username"] = username
    add_audit_log("username_update", target_type="user", target_id=session["user_id"], description="ユーザー名を変更しました。")
    return redirect(url_for("account", message="ユーザー名を変更しました。"))


@app.route("/account/update_email", methods=["POST"])
@login_required
def update_email():
    email = request.form.get("email", "").strip()

    if not email:
        return render_account("メールアドレスを入力してください。", 400)
    if len(email) > 255:
        return render_account("メールアドレスは255文字以内で入力してください。", 400)
    if EMAIL_PATTERN.fullmatch(email) is None:
        return render_account("有効なメールアドレスを入力してください。", 400)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM users WHERE LOWER(email) = LOWER(%s) AND id <> %s;",
        (email, session["user_id"])
    )

    if cur.fetchone() is not None:
        cur.close()
        conn.close()
        return render_account("そのメールアドレスは既に使用されています。", 400)

    try:
        cur.execute(
            "UPDATE users SET email = %s WHERE id = %s;",
            (email, session["user_id"])
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        cur.close()
        conn.close()
        return render_account("そのメールアドレスは既に使用されています。", 400)

    cur.close()
    conn.close()
    add_audit_log("email_update", target_type="user", target_id=session["user_id"], description="メールアドレスを変更しました。")
    return redirect(url_for("account", message="メールアドレスを変更しました。"))


@app.route("/account/update_password", methods=["POST"])
@login_required
def update_password():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not current_password or not new_password or not confirm_password:
        return render_account("パスワード欄をすべて入力してください。", 400)
    if new_password != confirm_password:
        return render_account("新しいパスワードと確認用パスワードが一致しません。", 400)
    if len(new_password) < 8:
        return render_account("新しいパスワードは8文字以上で入力してください。", 400)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT password_hash FROM users WHERE id = %s FOR UPDATE;",
        (session["user_id"],)
    )
    user = cur.fetchone()

    if user is None or not check_password_hash(user["password_hash"], current_password):
        conn.rollback()
        cur.close()
        conn.close()
        return render_account("現在のパスワードが正しくありません。", 400)

    cur.execute(
        "UPDATE users SET password_hash = %s WHERE id = %s;",
        (generate_password_hash(new_password), session["user_id"])
    )
    cur.execute("DELETE FROM api_tokens WHERE user_id = %s;", (session["user_id"],))
    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("password_update", target_type="user", target_id=session["user_id"], description="パスワードを変更し、APIトークンを失効しました。")

    return redirect(url_for(
        "account",
        message="パスワードを変更しました。発行済みのAPIトークンはすべて失効しました。"
    ))


@app.route("/account/delete", methods=["POST"])
@login_required
def delete_account():
    current_password = request.form.get("current_password", "")
    confirm_text = request.form.get("confirm_text", "")

    if confirm_text != "削除します":
        return render_account("確認用文字列として「削除します」と入力してください。", 400)
    if not current_password:
        return render_account("現在のパスワードを入力してください。", 400)

    user_id = session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT username, password_hash FROM users WHERE id = %s FOR UPDATE;",
        (user_id,)
    )
    user = cur.fetchone()

    if user is None or not check_password_hash(user["password_hash"], current_password):
        conn.rollback()
        cur.close()
        conn.close()
        return render_account("現在のパスワードが正しくありません。", 400)

    cur.execute(
        """
        INSERT INTO audit_logs (
            user_id, activity_id, action, target_type, target_id, description
        )
        VALUES (%s, NULL, 'account_delete', 'user', %s, %s);
        """,
        (user_id, user_id, f"ユーザー「{user['username']}」がアカウントを削除しました。")
    )
    cur.execute(
        """
        UPDATE users
        SET is_active = FALSE,
            deleted_at = CURRENT_TIMESTAMP
        WHERE id = %s;
        """,
        (user_id,)
    )
    cur.execute("DELETE FROM api_tokens WHERE user_id = %s;", (user_id,))
    cur.execute("DELETE FROM password_reset_tokens WHERE user_id = %s;", (user_id,))
    conn.commit()
    cur.close()
    conn.close()

    session.clear()
    return redirect(url_for("login", message="アカウントを削除しました。"))


@app.route("/")
@login_required
def index():
    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT activities.*, activity_users.role
        FROM activities
        JOIN activity_users ON activity_users.activity_id = activities.id
        WHERE activity_users.user_id = %s
        ORDER BY activities.created_at DESC;
        """,
        (user_id,)
    )
    activities = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("activities.html", activities=activities)


@app.route("/activities/add", methods=["GET", "POST"])
@login_required
def add_activity():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        user_id = session["user_id"]

        if not name:
            return "活動名は必須です。", 400

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO activities (user_id, name, description)
            VALUES (%s, %s, %s)
            RETURNING id;
            """,
            (user_id, name, description)
        )

        activity_id = cur.fetchone()["id"]
        cur.execute(
            "INSERT INTO activity_users (activity_id, user_id, role) VALUES (%s, %s, 'owner');",
            (activity_id, user_id)
        )
        conn.commit()
        cur.close()
        conn.close()

        add_audit_log("activity_create", activity_id, "activity", activity_id, f"活動「{name}」を作成しました。")

        return redirect(url_for("index"))

    return render_template("add_activity.html")


@app.route("/api/activities", methods=["GET"])
@api_login_required
def api_activities():
    user_id = g.user_id

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            activities.id,
            activities.name,
            activities.description,
            activities.created_at,
            activity_users.role
        FROM activities
        JOIN activity_users ON activity_users.activity_id = activities.id
        WHERE activity_users.user_id = %s
        ORDER BY activities.created_at DESC;
        """,
        (user_id,)
    )

    activities = cur.fetchall()

    cur.close()
    conn.close()

    return api_success(
        data={
            "activities": activities
        },
        message="活動一覧を取得しました。"
    )


@app.route("/api/activities/<int:activity_id>", methods=["GET"])
@api_login_required
@require_activity_role("owner", "staff", "viewer", api=True)
def api_activity_detail(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    return api_success(
        data={
            "activity": activity
        },
        message="活動詳細を取得しました。"
    )


@app.route("/api/activities/<int:activity_id>/members", methods=["GET"])
@api_login_required
@require_activity_role("owner", "staff", "viewer", api=True)
def api_activity_members(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            id,
            name,
            group_name,
            category,
            note,
            created_at
        FROM members
        WHERE activity_id = %s
        ORDER BY category, group_name, name;
        """,
        (activity_id,)
    )

    members = cur.fetchall()

    cur.close()
    conn.close()

    return api_success(
        data={
            "activity": {
                "id": activity["id"],
                "name": activity["name"]
            },
            "members": members
        },
        message="メンバー一覧を取得しました。"
    )


@app.route("/api/activities/<int:activity_id>/members", methods=["POST"])
@api_login_required
@require_activity_role("owner", "staff", api=True)
def api_add_member(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    data = request.get_json(silent=True)

    if data is None:
        return api_error("JSONデータを送信してください。", 400)

    name = data.get("name")
    group_name = data.get("group_name") if "group_name" in data else data.get("part")
    category = data.get("category") if "category" in data else data.get("generation")
    note = data.get("note", "")

    if not isinstance(name, str) or not name.strip():
        return api_error("nameは必須です。", 400)

    name = name.strip()

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO members (activity_id, name, group_name, category, note)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id, name, group_name, category, note, created_at;
        """,
        (activity_id, name, group_name, category, note)
    )

    member = cur.fetchone()

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("member_create", activity_id, "member", member["id"], f"APIからメンバー「{member['name']}」を追加しました。")

    return api_success(
        data={
            "member": member
        },
        message="メンバーを追加しました。",
        status_code=201
    )


@app.route("/api/activities/<int:activity_id>/members/<int:member_id>", methods=["PUT"])
@api_login_required
@require_activity_role("owner", "staff", api=True)
def api_update_member(activity_id, member_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    data = request.get_json(silent=True)

    if data is None:
        return api_error("JSONデータを送信してください。", 400)

    name = data.get("name")
    group_name = data.get("group_name") if "group_name" in data else data.get("part")
    category = data.get("category") if "category" in data else data.get("generation")
    note = data.get("note", "")

    if not isinstance(name, str) or not name.strip():
        return api_error("nameは必須です。", 400)

    name = name.strip()

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE members
        SET name = %s,
            group_name = %s,
            category = %s,
            note = %s
        WHERE id = %s
          AND activity_id = %s
        RETURNING id, name, group_name, category, note, created_at;
        """,
        (name, group_name, category, note, member_id, activity_id)
    )

    member = cur.fetchone()

    if member is None:
        conn.rollback()
        cur.close()
        conn.close()
        return api_error("このメンバーは存在しないか、アクセス権限がありません。", 404)

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("member_update", activity_id, "member", member_id, f"APIからメンバー「{member['name']}」を編集しました。")

    return api_success(
        data={
            "member": member
        },
        message="メンバー情報を更新しました。"
    )


@app.route("/api/activities/<int:activity_id>/sessions", methods=["GET"])
@api_login_required
@require_activity_role("owner", "staff", "viewer", api=True)
def api_activity_sessions(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            id,
            session_date,
            title,
            place,
            note,
            created_at
        FROM sessions
        WHERE activity_id = %s
        ORDER BY session_date DESC;
        """,
        (activity_id,)
    )

    sessions_data = cur.fetchall()

    cur.close()
    conn.close()

    return api_success(
        data={
            "activity": {
                "id": activity["id"],
                "name": activity["name"]
            },
            "sessions": sessions_data
        },
        message="活動日一覧を取得しました。"
    )


@app.route("/api/activities/<int:activity_id>/sessions", methods=["POST"])
@api_login_required
@require_activity_role("owner", "staff", api=True)
def api_add_session(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    data = request.get_json(silent=True)

    if data is None:
        return api_error("JSONデータを送信してください。", 400)

    session_date = data.get("session_date")
    title = data.get("title", "通常活動")
    place = data.get("place", "")
    note = data.get("note", "")

    if not is_valid_date_string(session_date):
        return api_error("session_dateはYYYY-MM-DD形式で指定してください。", 400)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO sessions (activity_id, session_date, title, place, note)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id, session_date, title, place, note, created_at;
        """,
        (activity_id, session_date, title, place, note)
    )

    session_data = cur.fetchone()

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("session_create", activity_id, "session", session_data["id"], "APIから活動日を追加しました。")

    return api_success(
        data={
            "session": session_data
        },
        message="活動日を追加しました。",
        status_code=201
    )


@app.route("/api/activities/<int:activity_id>/sessions/<int:session_id>", methods=["PUT"])
@api_login_required
@require_activity_role("owner", "staff", api=True)
def api_update_session(activity_id, session_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    data = request.get_json(silent=True)

    if data is None:
        return api_error("JSONデータを送信してください。", 400)

    session_date = data.get("session_date")
    title = data.get("title", "通常活動")
    place = data.get("place", "")
    note = data.get("note", "")

    if not is_valid_date_string(session_date):
        return api_error("session_dateはYYYY-MM-DD形式で指定してください。", 400)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE sessions
        SET session_date = %s,
            title = %s,
            place = %s,
            note = %s
        WHERE id = %s
          AND activity_id = %s
        RETURNING id, session_date, title, place, note, created_at;
        """,
        (session_date, title, place, note, session_id, activity_id)
    )

    session_data = cur.fetchone()

    if session_data is None:
        conn.rollback()
        cur.close()
        conn.close()
        return api_error("この活動日は存在しないか、アクセス権限がありません。", 404)

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("session_update", activity_id, "session", session_id, "APIから活動日を編集しました。")

    return api_success(
        data={
            "session": session_data
        },
        message="活動日を更新しました。"
    )


@app.route("/api/activities/<int:activity_id>/sessions/<int:session_id>", methods=["DELETE"])
@api_login_required
@require_activity_role("owner", api=True)
def api_delete_session(activity_id, session_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        DELETE FROM sessions
        WHERE id = %s
          AND activity_id = %s
        RETURNING id, session_date, title, place, note;
        """,
        (session_id, activity_id)
    )

    session_data = cur.fetchone()

    if session_data is None:
        conn.rollback()
        cur.close()
        conn.close()
        return api_error("この活動日は存在しないか、アクセス権限がありません。", 404)

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("session_delete", activity_id, "session", session_id, "APIから活動日を削除しました。")

    return api_success(
        data={
            "deleted_session": session_data
        },
        message="活動日を削除しました。"
    )


@app.route("/api/activities/<int:activity_id>/members/<int:member_id>", methods=["DELETE"])
@api_login_required
@require_activity_role("owner", api=True)
def api_delete_member(activity_id, member_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        DELETE FROM members
        WHERE id = %s
          AND activity_id = %s
        RETURNING id, name, group_name, category, note;
        """,
        (member_id, activity_id)
    )

    member = cur.fetchone()

    if member is None:
        conn.rollback()
        cur.close()
        conn.close()
        return api_error("このメンバーは存在しないか、アクセス権限がありません。", 404)

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("member_delete", activity_id, "member", member_id, "APIからメンバーを削除しました。")

    return api_success(
        data={
            "deleted_member": member
        },
        message="メンバーを削除しました。"
    )


@app.route("/api/activities/<int:activity_id>/sessions/<int:session_id>/attendance", methods=["GET"])
@api_login_required
@require_activity_role("owner", "staff", "viewer", api=True)
def api_session_attendance(activity_id, session_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, session_date, title, place, note
        FROM sessions
        WHERE id = %s
          AND activity_id = %s;
        """,
        (session_id, activity_id)
    )
    session_data = cur.fetchone()

    if session_data is None:
        cur.close()
        conn.close()
        return api_error("この活動日は存在しないか、アクセス権限がありません。", 404)

    cur.execute(
        """
        INSERT INTO attendance (session_id, member_id, status)
        SELECT %s, members.id, 'unchecked'
        FROM members
        WHERE members.activity_id = %s
          AND members.id NOT IN (
              SELECT member_id
              FROM attendance
              WHERE session_id = %s
          );
        """,
        (session_id, activity_id, session_id)
    )

    conn.commit()

    cur.execute(
        """
        SELECT
            attendance.id,
            attendance.status,
            attendance.checked_in_at,
            attendance.note,
            members.id AS member_id,
            members.name,
            members.group_name,
            members.category
        FROM attendance
        JOIN members ON attendance.member_id = members.id
        WHERE attendance.session_id = %s
          AND members.activity_id = %s
        ORDER BY members.category, members.group_name, members.name;
        """,
        (session_id, activity_id)
    )
    attendances = cur.fetchall()

    cur.execute(
        """
        SELECT
            COUNT(*) AS total_count,
            COUNT(*) FILTER (WHERE attendance.status = 'checked') AS checked_count,
            COUNT(*) FILTER (WHERE attendance.status = 'unchecked') AS unchecked_count
        FROM attendance
        JOIN members ON attendance.member_id = members.id
        WHERE attendance.session_id = %s
          AND members.activity_id = %s;
        """,
        (session_id, activity_id)
    )
    counts = cur.fetchone()

    cur.close()
    conn.close()

    return api_success(
        data={
            "activity": {
                "id": activity["id"],
                "name": activity["name"]
            },
            "session": session_data,
            "counts": counts,
            "attendances": attendances
        },
        message="受付一覧を取得しました。"
    )


@app.route("/api/activities/<int:activity_id>/attendance/<int:attendance_id>/check_in", methods=["POST"])
@api_login_required
@require_activity_role("owner", "staff", api=True)
def api_check_in(activity_id, attendance_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE attendance
        SET status = 'checked',
            checked_in_at = NOW()
        FROM sessions, members
        WHERE attendance.id = %s
          AND attendance.session_id = sessions.id
          AND attendance.member_id = members.id
          AND sessions.activity_id = %s
          AND members.activity_id = %s
        RETURNING
            attendance.id,
            attendance.session_id,
            attendance.member_id,
            attendance.status,
            attendance.checked_in_at,
            attendance.note;
        """,
        (attendance_id, activity_id, activity_id)
    )

    attendance_data = cur.fetchone()

    if attendance_data is None:
        conn.rollback()
        cur.close()
        conn.close()
        return api_error("この受付データは存在しないか、アクセス権限がありません。", 404)

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("attendance_check_in", activity_id, "attendance", attendance_id, "APIから受付済みに変更しました。")

    return api_success(
        data={
            "attendance": attendance_data
        },
        message="受付済みにしました。"
    )


@app.route("/api/activities/<int:activity_id>/attendance/<int:attendance_id>/cancel_check_in", methods=["POST"])
@api_login_required
@require_activity_role("owner", "staff", api=True)
def api_cancel_check_in(activity_id, attendance_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE attendance
        SET status = 'unchecked',
            checked_in_at = NULL
        FROM sessions, members
        WHERE attendance.id = %s
          AND attendance.session_id = sessions.id
          AND attendance.member_id = members.id
          AND sessions.activity_id = %s
          AND members.activity_id = %s
        RETURNING
            attendance.id,
            attendance.session_id,
            attendance.member_id,
            attendance.status,
            attendance.checked_in_at,
            attendance.note;
        """,
        (attendance_id, activity_id, activity_id)
    )

    attendance_data = cur.fetchone()

    if attendance_data is None:
        conn.rollback()
        cur.close()
        conn.close()
        return api_error("この受付データは存在しないか、アクセス権限がありません。", 404)

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("attendance_cancel", activity_id, "attendance", attendance_id, "APIから未受付に戻しました。")

    return api_success(
        data={
            "attendance": attendance_data
        },
        message="未受付に戻しました。"
    )


@app.route("/api/activities/<int:activity_id>/attendance/<int:attendance_id>/note", methods=["PUT"])
@api_login_required
@require_activity_role("owner", "staff", api=True)
def api_update_attendance_note(activity_id, attendance_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    data = request.get_json(silent=True)

    if data is None:
        return api_error("JSONデータを送信してください。", 400)

    note = data.get("note", "")

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE attendance
        SET note = %s
        FROM sessions, members
        WHERE attendance.id = %s
          AND attendance.session_id = sessions.id
          AND attendance.member_id = members.id
          AND sessions.activity_id = %s
          AND members.activity_id = %s
        RETURNING
            attendance.id,
            attendance.session_id,
            attendance.member_id,
            attendance.status,
            attendance.checked_in_at,
            attendance.note;
        """,
        (note, attendance_id, activity_id, activity_id)
    )

    attendance_data = cur.fetchone()

    if attendance_data is None:
        conn.rollback()
        cur.close()
        conn.close()
        return api_error("この受付データは存在しないか、アクセス権限がありません。", 404)

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("attendance_note_update", activity_id, "attendance", attendance_id, "APIから受付備考を更新しました。")

    return api_success(
        data={
            "attendance": attendance_data
        },
        message="備考を更新しました。"
    )


@app.route("/api/activities/<int:activity_id>/attendance/summary", methods=["GET"])
@api_login_required
@require_activity_role("owner", "staff", "viewer", api=True)
def api_attendance_summary(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            members.id AS member_id,
            members.name,
            members.group_name,
            members.category,
            COUNT(attendance.id) AS total_count,
            COUNT(attendance.id) FILTER (WHERE attendance.status = 'checked') AS checked_count
        FROM members
        LEFT JOIN attendance ON members.id = attendance.member_id
        LEFT JOIN sessions ON attendance.session_id = sessions.id
        WHERE members.activity_id = %s
          AND (
              sessions.activity_id = %s
              OR sessions.id IS NULL
          )
        GROUP BY members.id, members.name, members.group_name, members.category
        ORDER BY members.category, members.group_name, members.name;
        """,
        (activity_id, activity_id)
    )

    summaries = cur.fetchall()

    cur.close()
    conn.close()

    result = []

    for summary in summaries:
        total_count = summary["total_count"]
        checked_count = summary["checked_count"]

        if total_count == 0:
            attendance_rate = 0
        else:
            attendance_rate = round(checked_count * 100 / total_count, 1)

        result.append({
            "member_id": summary["member_id"],
            "name": summary["name"],
            "group_name": summary["group_name"],
            "category": summary["category"],
            "total_count": total_count,
            "checked_count": checked_count,
            "attendance_rate": attendance_rate
        })

    return api_success(
        data={
            "activity": {
                "id": activity["id"],
                "name": activity["name"]
            },
            "summaries": result
        },
        message="個人別出席率を取得しました。"
    )


@app.route("/api/activities/<int:activity_id>/attendance/group_summary", methods=["GET"])
@api_login_required
@require_activity_role("owner", "staff", "viewer", api=True)
def api_attendance_group_summary(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            members.group_name,
            COUNT(attendance.id) AS total_count,
            COUNT(attendance.id) FILTER (WHERE attendance.status = 'checked') AS checked_count
        FROM members
        LEFT JOIN attendance ON members.id = attendance.member_id
        LEFT JOIN sessions ON attendance.session_id = sessions.id
        WHERE members.activity_id = %s
          AND (
              sessions.activity_id = %s
              OR sessions.id IS NULL
          )
        GROUP BY members.group_name
        ORDER BY members.group_name;
        """,
        (activity_id, activity_id)
    )

    group_name_summaries = cur.fetchall()

    cur.execute(
        """
        SELECT
            members.category,
            COUNT(attendance.id) AS total_count,
            COUNT(attendance.id) FILTER (WHERE attendance.status = 'checked') AS checked_count
        FROM members
        LEFT JOIN attendance ON members.id = attendance.member_id
        LEFT JOIN sessions ON attendance.session_id = sessions.id
        WHERE members.activity_id = %s
          AND (
              sessions.activity_id = %s
              OR sessions.id IS NULL
          )
        GROUP BY members.category
        ORDER BY members.category;
        """,
        (activity_id, activity_id)
    )

    category_summaries = cur.fetchall()

    cur.close()
    conn.close()

    group_name_result = []

    for summary in group_name_summaries:
        total_count = summary["total_count"]
        checked_count = summary["checked_count"]

        if total_count == 0:
            attendance_rate = 0
        else:
            attendance_rate = round(checked_count * 100 / total_count, 1)

        group_name_result.append({
            "group_name": summary["group_name"],
            "total_count": total_count,
            "checked_count": checked_count,
            "attendance_rate": attendance_rate
        })

    category_result = []

    for summary in category_summaries:
        total_count = summary["total_count"]
        checked_count = summary["checked_count"]

        if total_count == 0:
            attendance_rate = 0
        else:
            attendance_rate = round(checked_count * 100 / total_count, 1)

        category_result.append({
            "category": summary["category"],
            "total_count": total_count,
            "checked_count": checked_count,
            "attendance_rate": attendance_rate
        })

    return api_success(
        data={
            "activity": {
                "id": activity["id"],
                "name": activity["name"]
            },
            "group_name_summaries": group_name_result,
            "category_summaries": category_result
        },
        message="所属グループ・所属区分別出席率を取得しました。"
    )


@app.route("/api/activities", methods=["POST"])
@api_login_required
def api_add_activity():
    data = request.get_json(silent=True)

    if data is None:
        return api_error("JSONデータを送信してください。", 400)

    name = data.get("name")
    description = data.get("description", "")

    if not isinstance(name, str) or not name.strip():
        return api_error("nameは必須です。", 400)

    name = name.strip()

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO activities (user_id, name, description)
        VALUES (%s, %s, %s)
        RETURNING id, name, description, created_at;
        """,
        (g.user_id, name, description)
    )

    activity = cur.fetchone()

    cur.execute(
        "INSERT INTO activity_users (activity_id, user_id, role) VALUES (%s, %s, 'owner');",
        (activity["id"], g.user_id)
    )

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("activity_create", activity["id"], "activity", activity["id"], f"APIから活動「{activity['name']}」を作成しました。")

    return api_success(
        data={
            "activity": activity
        },
        message="活動を作成しました。",
        status_code=201
    )


@app.route("/api/activities/<int:activity_id>", methods=["PUT"])
@api_login_required
@require_activity_role("owner", api=True)
def api_update_activity(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    data = request.get_json(silent=True)

    if data is None:
        return api_error("JSONデータを送信してください。", 400)

    name = data.get("name")
    description = data.get("description", "")

    if not isinstance(name, str) or not name.strip():
        return api_error("nameは必須です。", 400)

    name = name.strip()

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE activities
        SET name = %s,
            description = %s
        WHERE id = %s
          AND user_id = %s
        RETURNING id, name, description, created_at;
        """,
        (name, description, activity_id, g.user_id)
    )

    updated_activity = cur.fetchone()

    if updated_activity is None:
        conn.rollback()
        cur.close()
        conn.close()
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("activity_update", activity_id, "activity", activity_id, f"APIから活動「{updated_activity['name']}」を編集しました。")

    return api_success(
        data={
            "activity": updated_activity
        },
        message="活動情報を更新しました。"
    )


@app.route("/api/activities/<int:activity_id>", methods=["DELETE"])
@api_login_required
@require_activity_role("owner", api=True)
def api_delete_activity(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        DELETE FROM activities
        WHERE id = %s
          AND user_id = %s
        RETURNING id, name, description;
        """,
        (activity_id, g.user_id)
    )

    deleted_activity = cur.fetchone()

    if deleted_activity is None:
        conn.rollback()
        cur.close()
        conn.close()
        return api_error("この活動は存在しないか、アクセス権限がありません。", 404)

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("activity_delete", target_type="activity", target_id=activity_id, description=f"APIから活動「{deleted_activity['name']}」を削除しました。")

    return api_success(
        data={
            "deleted_activity": deleted_activity
        },
        message="活動を削除しました。"
    )


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True)

    if data is None:
        return api_error("JSONデータを送信してください。", 400)

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return api_error("usernameとpasswordは必須です。", 400)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT *
        FROM users
        WHERE username = %s
          AND is_active = TRUE;
        """,
        (username,)
    )

    user = cur.fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        cur.close()
        conn.close()

        return api_error("ユーザー名またはパスワードが違います。", 401)

    token = secrets.token_urlsafe(32)
    token_hash = hash_token(token)
    expires_at = datetime.now() + timedelta(days=30)

    cur.execute(
        """
        INSERT INTO api_tokens (user_id, token_hash, expires_at)
        VALUES (%s, %s, %s);
        """,
        (user["id"], token_hash, expires_at)
    )

    conn.commit()
    cur.close()
    conn.close()

    return api_success(
        data={
            "token": token,
            "expires_at": expires_at.isoformat(),
            "user": {
                "id": user["id"],
                "username": user["username"]
            }
        },
        message="ログインしました。"
    )


@app.route("/api/logout", methods=["POST"])
@api_login_required
def api_logout():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "", 1).strip()
    token_hash = hash_token(token)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        DELETE FROM api_tokens
        WHERE token_hash = %s;
        """,
        (token_hash,)
    )

    conn.commit()
    cur.close()
    conn.close()

    return api_success(
        message="ログアウトしました。"
    )


@app.route("/api/me", methods=["GET"])
@api_login_required
def api_me():
    return api_success(
        data={
            "user": {
                "id": g.user_id,
                "username": g.username
            }
        },
        message="ユーザー情報を取得しました。"
    )


@app.route("/activities/edit/<int:activity_id>", methods=["GET", "POST"])
@login_required
@require_activity_role("owner")
def edit_activity(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()

        if not name:
            return "活動名は必須です。", 400

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
            UPDATE activities
            SET name = %s,
                description = %s
            WHERE id = %s
              AND user_id = %s;
            """,
            (name, description, activity_id, session["user_id"])
        )

        conn.commit()
        cur.close()
        conn.close()

        add_audit_log("activity_update", activity_id, "activity", activity_id, f"活動「{name}」を編集しました。")

        return redirect(url_for("activity_dashboard", activity_id=activity_id))

    return render_template("edit_activity.html", activity=activity)


@app.route("/activities/delete/<int:activity_id>", methods=["POST"])
@login_required
@require_activity_role("owner")
def delete_activity(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        DELETE FROM activities
        WHERE id = %s
          AND user_id = %s;
        """,
        (activity_id, session["user_id"])
    )

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("activity_delete", target_type="activity", target_id=activity_id, description=f"活動「{activity['name']}」を削除しました。")

    return redirect(url_for("index"))


@app.route("/activities/<int:activity_id>")
@login_required
@require_activity_role("owner", "staff", "viewer")
def activity_dashboard(activity_id):
    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor()

    # activity_usersに登録されたユーザーだけが活動を閲覧できる。
    cur.execute(
        """
        SELECT activities.*, activity_users.role
        FROM activities
        JOIN activity_users ON activity_users.activity_id = activities.id
        WHERE activities.id = %s
          AND activity_users.user_id = %s;
        """,
        (activity_id, user_id)
    )
    activity = cur.fetchone()

    if activity is None:
        cur.close()
        conn.close()
        return "この活動は存在しないか、アクセス権限がありません。", 404

    # メンバー数
    cur.execute(
        """
        SELECT COUNT(*) AS member_count
        FROM members
        WHERE activity_id = %s;
        """,
        (activity_id,)
    )
    member_count = cur.fetchone()["member_count"]

    # 活動日数
    cur.execute(
        """
        SELECT COUNT(*) AS session_count
        FROM sessions
        WHERE activity_id = %s;
        """,
        (activity_id,)
    )
    session_count = cur.fetchone()["session_count"]

    today = date.today()

    # 今日の全活動日と、それぞれの受付済み人数を取得する。
    # 母数は受付レコード数ではなく、上で取得した活動のメンバー数を使う。
    cur.execute(
        """
        SELECT
            sessions.id,
            sessions.session_date,
            sessions.title,
            sessions.place,
            sessions.note,
            COUNT(attendance.id) FILTER (
                WHERE attendance.status = 'checked'
                  AND attendance_members.id IS NOT NULL
            ) AS checked_count
        FROM sessions
        LEFT JOIN attendance
          ON attendance.session_id = sessions.id
        LEFT JOIN members AS attendance_members
          ON attendance.member_id = attendance_members.id
         AND attendance_members.activity_id = %s
        WHERE sessions.activity_id = %s
          AND sessions.session_date = %s
        GROUP BY
            sessions.id,
            sessions.session_date,
            sessions.title,
            sessions.place,
            sessions.note
        ORDER BY sessions.id;
        """,
        (activity_id, activity_id, today)
    )
    today_sessions = cur.fetchall()

    today_sessions_summary = []

    for today_session in today_sessions:
        checked_count = today_session["checked_count"]

        if member_count == 0:
            attendance_rate = 0.0
        else:
            attendance_rate = round(checked_count * 100 / member_count, 1)

        today_sessions_summary.append({
            "id": today_session["id"],
            "session_date": today_session["session_date"],
            "title": today_session["title"],
            "place": today_session["place"],
            "note": today_session["note"],
            "checked_count": checked_count,
            "member_count": member_count,
            "attendance_rate": attendance_rate
        })

    # 今日を含まない未来の活動日から、最も近い1件を取得する。
    cur.execute(
        """
        SELECT id, session_date, title, place, note
        FROM sessions
        WHERE activity_id = %s
          AND session_date > %s
        ORDER BY session_date, id
        LIMIT 1;
        """,
        (activity_id, today)
    )
    next_session = cur.fetchone()

    # 今日より前の活動を新しい順に最大5件取得する。
    cur.execute(
        """
        SELECT
            sessions.id,
            sessions.session_date,
            sessions.title,
            sessions.place,
            COUNT(attendance.id) FILTER (
                WHERE attendance.status = 'checked'
                  AND attendance_members.id IS NOT NULL
            ) AS checked_count
        FROM sessions
        LEFT JOIN attendance
          ON attendance.session_id = sessions.id
        LEFT JOIN members AS attendance_members
          ON attendance.member_id = attendance_members.id
         AND attendance_members.activity_id = %s
        WHERE sessions.activity_id = %s
          AND sessions.session_date < %s
        GROUP BY
            sessions.id,
            sessions.session_date,
            sessions.title,
            sessions.place
        ORDER BY sessions.session_date DESC, sessions.id DESC
        LIMIT 5;
        """,
        (activity_id, activity_id, today)
    )
    recent_sessions = cur.fetchall()

    recent_sessions_summary = []

    for recent_session in recent_sessions:
        checked_count = recent_session["checked_count"]
        attendance_rate = (
            0.0
            if member_count == 0
            else round(checked_count * 100 / member_count, 1)
        )

        recent_sessions_summary.append({
            "id": recent_session["id"],
            "session_date": recent_session["session_date"],
            "title": recent_session["title"],
            "place": recent_session["place"],
            "checked_count": checked_count,
            "member_count": member_count,
            "attendance_rate": attendance_rate
        })

    # 受付データがある活動だけを母数にし、出席率50%未満を最大5名取得する。
    cur.execute(
        """
        SELECT
            members.id AS member_id,
            members.name,
            members.group_name,
            members.category,
            COUNT(attendance.id) AS total_count,
            COUNT(attendance.id) FILTER (
                WHERE attendance.status = 'checked'
            ) AS checked_count
        FROM members
        JOIN attendance
          ON members.id = attendance.member_id
        JOIN sessions
          ON attendance.session_id = sessions.id
         AND sessions.activity_id = %s
        WHERE members.activity_id = %s
        GROUP BY
            members.id,
            members.name,
            members.group_name,
            members.category
        HAVING COUNT(attendance.id) > 0
           AND COUNT(attendance.id) FILTER (
               WHERE attendance.status = 'checked'
           ) * 100.0 / COUNT(attendance.id) < 50
        ORDER BY
            COUNT(attendance.id) FILTER (
                WHERE attendance.status = 'checked'
            ) * 1.0 / COUNT(attendance.id),
            members.name
        LIMIT 5;
        """,
        (activity_id, activity_id)
    )
    low_attendance_rows = cur.fetchall()

    low_attendance_members = []

    for member in low_attendance_rows:
        low_attendance_members.append({
            "member_id": member["member_id"],
            "name": member["name"],
            "group_name": member["group_name"],
            "category": member["category"],
            "checked_count": member["checked_count"],
            "total_count": member["total_count"],
            "attendance_rate": round(
                member["checked_count"] * 100 / member["total_count"],
                1
            )
        })

    # 所属グループ別の受付データを集計する。
    cur.execute(
        """
        SELECT
            COALESCE(NULLIF(BTRIM(members.group_name), ''), '未設定')
                AS group_name,
            COUNT(sessions.id) AS total_count,
            COUNT(sessions.id) FILTER (
                WHERE attendance.status = 'checked'
            ) AS checked_count
        FROM members
        LEFT JOIN attendance
          ON members.id = attendance.member_id
        LEFT JOIN sessions
          ON attendance.session_id = sessions.id
         AND sessions.activity_id = %s
        WHERE members.activity_id = %s
        GROUP BY COALESCE(NULLIF(BTRIM(members.group_name), ''), '未設定')
        ORDER BY group_name;
        """,
        (activity_id, activity_id)
    )
    group_name_rows = cur.fetchall()

    group_name_summaries = []

    for summary in group_name_rows:
        total_count = summary["total_count"]
        group_name_summaries.append({
            "group_name": summary["group_name"],
            "checked_count": summary["checked_count"],
            "total_count": total_count,
            "attendance_rate": (
                0.0
                if total_count == 0
                else round(summary["checked_count"] * 100 / total_count, 1)
            )
        })

    # 所属区分別の受付データを集計する。
    cur.execute(
        """
        SELECT
            COALESCE(NULLIF(BTRIM(members.category), ''), '未設定')
                AS category,
            COUNT(sessions.id) AS total_count,
            COUNT(sessions.id) FILTER (
                WHERE attendance.status = 'checked'
            ) AS checked_count
        FROM members
        LEFT JOIN attendance
          ON members.id = attendance.member_id
        LEFT JOIN sessions
          ON attendance.session_id = sessions.id
         AND sessions.activity_id = %s
        WHERE members.activity_id = %s
        GROUP BY COALESCE(NULLIF(BTRIM(members.category), ''), '未設定')
        ORDER BY category;
        """,
        (activity_id, activity_id)
    )
    category_rows = cur.fetchall()

    category_summaries = []

    for summary in category_rows:
        total_count = summary["total_count"]
        category_summaries.append({
            "category": summary["category"],
            "checked_count": summary["checked_count"],
            "total_count": total_count,
            "attendance_rate": (
                0.0
                if total_count == 0
                else round(summary["checked_count"] * 100 / total_count, 1)
            )
        })

    cur.close()
    conn.close()

    return render_template(
        "activity_dashboard.html",
        activity=activity,
        member_count=member_count,
        session_count=session_count,
        today=today,
        today_sessions_summary=today_sessions_summary,
        next_session=next_session,
        recent_sessions_summary=recent_sessions_summary,
        low_attendance_members=low_attendance_members,
        group_name_summaries=group_name_summaries,
        category_summaries=category_summaries
    )


def get_activity_or_404(activity_id):
    user_id = session.get("user_id") or getattr(g, "user_id", None)

    if user_id is None:
        return None

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT activities.*, activity_users.role
        FROM activities
        JOIN activity_users ON activity_users.activity_id = activities.id
        WHERE activities.id = %s
          AND activity_users.user_id = %s;
        """,
        (activity_id, user_id)
    )

    activity = cur.fetchone()

    cur.close()
    conn.close()

    return activity


@app.route("/activities/<int:activity_id>/audit_logs")
@login_required
@require_activity_role("owner", "staff", "viewer")
def activity_audit_logs(activity_id):
    activity = get_activity_or_404(activity_id)
    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            audit_logs.created_at,
            users.username,
            audit_logs.action,
            audit_logs.target_type,
            audit_logs.description
        FROM audit_logs
        LEFT JOIN users ON audit_logs.user_id = users.id
        WHERE audit_logs.activity_id = %s
        ORDER BY audit_logs.created_at DESC, audit_logs.id DESC
        LIMIT 100;
        """,
        (activity_id,)
    )
    audit_logs = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("audit_logs.html", activity=activity, audit_logs=audit_logs)


@app.route("/activities/<int:activity_id>/permissions")
@login_required
@require_activity_role("owner")
def activity_permissions(activity_id):
    activity = get_activity_or_404(activity_id)
    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT activity_users.id, activity_users.user_id, activity_users.role,
               activity_users.created_at, users.username, users.email
        FROM activity_users
        JOIN users ON users.id = activity_users.user_id
        WHERE activity_users.activity_id = %s
        ORDER BY CASE activity_users.role WHEN 'owner' THEN 1 WHEN 'staff' THEN 2 ELSE 3 END,
                 users.username;
        """,
        (activity_id,)
    )
    activity_users = cur.fetchall()
    cur.close()
    conn.close()
    return render_template(
        "activity_permissions.html",
        activity=activity,
        activity_users=activity_users,
        message=request.args.get("message"),
        error=request.args.get("error")
    )


@app.route("/activities/<int:activity_id>/permissions/add", methods=["POST"])
@login_required
@require_activity_role("owner")
def add_activity_permission(activity_id):
    identifier = request.form.get("identifier", "").strip()
    role = request.form.get("role", "")
    if not identifier or role not in {"staff", "viewer"}:
        return redirect(url_for("activity_permissions", activity_id=activity_id, error="ユーザー名またはメールアドレスと権限を正しく指定してください。"))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username FROM users WHERE is_active = TRUE AND (username = %s OR LOWER(email) = LOWER(%s));",
        (identifier, identifier)
    )
    user = cur.fetchone()
    if user is None:
        cur.close()
        conn.close()
        return redirect(url_for("activity_permissions", activity_id=activity_id, error="該当するユーザーが見つかりません。"))

    try:
        cur.execute(
            """
            INSERT INTO activity_users (activity_id, user_id, role)
            VALUES (%s, %s, %s) RETURNING id;
            """,
            (activity_id, user["id"], role)
        )
        activity_user_id = cur.fetchone()["id"]
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        cur.close()
        conn.close()
        return redirect(url_for("activity_permissions", activity_id=activity_id, error="そのユーザーは既に活動へ追加されています。"))
    cur.close()
    conn.close()
    add_audit_log("permission_create", activity_id, "activity_user", activity_user_id, f"ユーザー「{user['username']}」を{role}として追加しました。")
    return redirect(url_for("activity_permissions", activity_id=activity_id, message="ユーザーを追加しました。"))


@app.route("/activities/<int:activity_id>/permissions/update/<int:activity_user_id>", methods=["POST"])
@login_required
@require_activity_role("owner")
def update_activity_permission(activity_id, activity_user_id):
    role = request.form.get("role", "")
    if role not in {"staff", "viewer"}:
        return redirect(url_for("activity_permissions", activity_id=activity_id, error="指定された権限が不正です。"))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE activity_users SET role = %s
        WHERE id = %s AND activity_id = %s AND role <> 'owner'
        RETURNING user_id;
        """,
        (role, activity_user_id, activity_id)
    )
    updated = cur.fetchone()
    if updated is None:
        conn.rollback()
        cur.close()
        conn.close()
        return redirect(url_for("activity_permissions", activity_id=activity_id, error="owner権限は変更できません。"))
    conn.commit()
    cur.close()
    conn.close()
    add_audit_log("permission_update", activity_id, "activity_user", activity_user_id, f"活動権限を{role}へ変更しました。")
    return redirect(url_for("activity_permissions", activity_id=activity_id, message="権限を変更しました。"))


@app.route("/activities/<int:activity_id>/permissions/delete/<int:activity_user_id>", methods=["POST"])
@login_required
@require_activity_role("owner")
def delete_activity_permission(activity_id, activity_user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        DELETE FROM activity_users
        WHERE id = %s AND activity_id = %s AND role <> 'owner'
        RETURNING user_id;
        """,
        (activity_user_id, activity_id)
    )
    deleted = cur.fetchone()
    if deleted is None:
        conn.rollback()
        cur.close()
        conn.close()
        return redirect(url_for("activity_permissions", activity_id=activity_id, error="owner権限は削除できません。"))
    conn.commit()
    cur.close()
    conn.close()
    add_audit_log("permission_delete", activity_id, "activity_user", activity_user_id, "活動からユーザー権限を削除しました。")
    return redirect(url_for("activity_permissions", activity_id=activity_id, message="ユーザー権限を削除しました。"))


@app.route("/activities/<int:activity_id>/members")
@login_required
@require_activity_role("owner", "staff", "viewer")
def members(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT *
        FROM members
        WHERE activity_id = %s
        ORDER BY category, group_name, name;
        """,
        (activity_id,)
    )
    members = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "members.html",
        activity=activity,
        members=members
    )


@app.route(
    "/activities/<int:activity_id>/members/import_csv",
    methods=["GET", "POST"]
)
@login_required
@require_activity_role("owner", "staff")
def import_members_csv(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    error = None
    import_result = None

    if request.method == "POST":
        uploaded_file = request.files.get("csv_file")

        if uploaded_file is None or not uploaded_file.filename:
            error = "インポートするCSVファイルを選択してください。"
        else:
            file_data = uploaded_file.read(MAX_MEMBER_CSV_SIZE + 1)

            if len(file_data) > MAX_MEMBER_CSV_SIZE:
                error = "CSVファイルは2MB以下にしてください。"
            elif not file_data:
                error = "CSVファイルが空です。"
            else:
                try:
                    csv_text = file_data.decode("utf-8-sig")
                except UnicodeDecodeError:
                    error = (
                        "CSVファイルをUTF-8として読み込めませんでした。"
                        "UTF-8またはUTF-8 BOM付きで保存してください。"
                    )

        rows_to_insert = []
        skipped_rows = []

        if error is None:
            try:
                reader = csv.DictReader(
                    io.StringIO(csv_text, newline=""),
                    strict=True
                )
                fieldnames = reader.fieldnames

                if fieldnames is None:
                    error = "CSVのヘッダー行がありません。"
                else:
                    missing_headers = [
                        header
                        for header in MEMBER_CSV_HEADERS
                        if header not in fieldnames
                    ]

                    if missing_headers:
                        error = (
                            "必要なヘッダーがありません: "
                            + ", ".join(missing_headers)
                        )

                if error is None:
                    for row_number, row in enumerate(reader, start=2):
                        if None in row:
                            skipped_rows.append({
                                "row_number": row_number,
                                "reason": "ヘッダーより列数が多いため"
                            })
                            continue

                        name = (row.get("name") or "").strip()
                        group_name = (row.get("group_name") or "").strip()
                        category = (row.get("category") or "").strip()
                        note = (row.get("note") or "").strip()

                        if not name:
                            skipped_rows.append({
                                "row_number": row_number,
                                "reason": "名前が空のため"
                            })
                            continue

                        if len(name) > 100:
                            skipped_rows.append({
                                "row_number": row_number,
                                "reason": "名前が100文字を超えているため"
                            })
                            continue

                        if len(group_name) > 100:
                            skipped_rows.append({
                                "row_number": row_number,
                                "reason": "所属グループが100文字を超えているため"
                            })
                            continue

                        if len(category) > 100:
                            skipped_rows.append({
                                "row_number": row_number,
                                "reason": "所属区分が100文字を超えているため"
                            })
                            continue

                        rows_to_insert.append((
                            activity_id,
                            name,
                            group_name,
                            category,
                            note
                        ))
            except csv.Error:
                error = (
                    "CSVの形式が正しくありません。"
                    "引用符や改行、列数を確認してください。"
                )

        if error is None:
            conn = get_db_connection()
            cur = conn.cursor()

            try:
                if rows_to_insert:
                    cur.executemany(
                        """
                        INSERT INTO members (
                            activity_id,
                            name,
                            group_name,
                            category,
                            note
                        )
                        VALUES (%s, %s, %s, %s, %s);
                        """,
                        rows_to_insert
                    )

                conn.commit()
                import_result = {
                    "registered_count": len(rows_to_insert),
                    "skipped_count": len(skipped_rows),
                    "skipped_rows": skipped_rows
                }
                add_audit_log(
                    "member_csv_import", activity_id, "member",
                    description=f"CSVから{len(rows_to_insert)}件を登録し、{len(skipped_rows)}件をスキップしました。"
                )
            except psycopg2.Error:
                conn.rollback()
                error = (
                    "データベースへの登録に失敗しました。"
                    "入力内容を確認して、もう一度お試しください。"
                )
            finally:
                cur.close()
                conn.close()

    return render_template(
        "import_members_csv.html",
        activity=activity,
        error=error,
        import_result=import_result,
        max_csv_size_mb=MAX_MEMBER_CSV_SIZE // (1024 * 1024)
    )


@app.route("/activities/<int:activity_id>/members/import_template")
@login_required
@require_activity_role("owner", "staff")
def download_member_import_template(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(MEMBER_CSV_HEADERS)
    writer.writerow(["山田太郎", "企画班", "2026年度", "デモ用"])
    writer.writerow(["佐藤花子", "受付班", "2026年度", "デモ用"])
    csv_data = output.getvalue().encode("utf-8-sig")

    return Response(
        csv_data,
        content_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                "attachment; filename=member_import_template.csv"
            )
        }
    )


@app.route("/activities/<int:activity_id>/members/add", methods=["GET", "POST"])
@login_required
@require_activity_role("owner", "staff")
def add_member(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        group_name = request.form.get("group_name", "").strip()
        category = request.form.get("category", "").strip()
        note = request.form.get("note", "")

        if not name:
            return "メンバー名は必須です。", 400

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO members (activity_id, name, group_name, category, note)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (activity_id, name, group_name, category, note)
        )

        member_id = cur.fetchone()["id"]
        conn.commit()
        cur.close()
        conn.close()

        add_audit_log("member_create", activity_id, "member", member_id, f"メンバー「{name}」を追加しました。")

        return redirect(url_for("members", activity_id=activity_id))

    return render_template(
        "add_member.html",
        activity=activity
    )


@app.route("/activities/<int:activity_id>/members/edit/<int:member_id>", methods=["GET", "POST"])
@login_required
@require_activity_role("owner", "staff")
def edit_member(activity_id, member_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        group_name = request.form.get("group_name", "").strip()
        category = request.form.get("category", "").strip()
        note = request.form.get("note", "")

        if not name:
            cur.close()
            conn.close()
            return "メンバー名は必須です。", 400

        cur.execute(
            """
            UPDATE members
            SET name = %s,
                group_name = %s,
                category = %s,
                note = %s
            WHERE id = %s
              AND activity_id = %s;
            """,
            (name, group_name, category, note, member_id, activity_id)
        )

        conn.commit()
        cur.close()
        conn.close()

        add_audit_log("member_update", activity_id, "member", member_id, f"メンバー「{name}」を編集しました。")

        return redirect(url_for("members", activity_id=activity_id))

    cur.execute(
        """
        SELECT *
        FROM members
        WHERE id = %s
          AND activity_id = %s;
        """,
        (member_id, activity_id)
    )
    member = cur.fetchone()

    cur.close()
    conn.close()

    if member is None:
        return "このメンバーは存在しないか、アクセス権限がありません。", 404

    return render_template(
        "edit_member.html",
        activity=activity,
        member=member
    )


@app.route("/activities/<int:activity_id>/members/delete/<int:member_id>", methods=["POST"])
@login_required
@require_activity_role("owner")
def delete_member(activity_id, member_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        DELETE FROM members
        WHERE id = %s
          AND activity_id = %s;
        """,
        (member_id, activity_id)
    )

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("member_delete", activity_id, "member", member_id, "メンバーを削除しました。")

    return redirect(url_for("members", activity_id=activity_id))


@app.route("/activities/<int:activity_id>/sessions")
@login_required
@require_activity_role("owner", "staff", "viewer")
def sessions(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT *
        FROM sessions
        WHERE activity_id = %s
        ORDER BY session_date DESC;
        """,
        (activity_id,)
    )
    sessions = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "sessions.html",
        activity=activity,
        sessions=sessions
    )


@app.route("/activities/<int:activity_id>/sessions/add", methods=["GET", "POST"])
@login_required
@require_activity_role("owner", "staff")
def add_session(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    if request.method == "POST":
        session_date = request.form.get("session_date", "")
        title = request.form.get("title", "通常活動")
        place = request.form.get("place", "")
        note = request.form.get("note", "")

        if not is_valid_date_string(session_date):
            return "活動日はYYYY-MM-DD形式で指定してください。", 400

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO sessions (activity_id, session_date, title, place, note)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (activity_id, session_date, title, place, note)
        )

        new_session_id = cur.fetchone()["id"]
        conn.commit()
        cur.close()
        conn.close()

        add_audit_log("session_create", activity_id, "session", new_session_id, f"活動日「{session_date} {title}」を追加しました。")

        return redirect(url_for("sessions", activity_id=activity_id))

    return render_template(
        "add_session.html",
        activity=activity
    )


@app.route("/activities/<int:activity_id>/sessions/add_bulk", methods=["GET", "POST"])
@login_required
@require_activity_role("owner", "staff")
def add_sessions_bulk(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    if request.method == "POST":
        start_date = request.form.get("start_date", "")
        count_text = request.form.get("count", "")
        title = request.form.get("title", "通常活動")
        place = request.form.get("place", "")
        note = request.form.get("note", "")

        if not is_valid_date_string(start_date):
            return "開始日はYYYY-MM-DD形式で指定してください。", 400

        try:
            count = int(count_text)
        except (TypeError, ValueError):
            return "追加回数は1から100までの整数で指定してください。", 400

        if not 1 <= count <= 100:
            return "追加回数は1から100までの整数で指定してください。", 400

        start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()

        conn = get_db_connection()
        cur = conn.cursor()

        for i in range(count):
            session_date = start_date_obj + timedelta(days=7 * i)

            cur.execute(
                """
                INSERT INTO sessions (activity_id, session_date, title, place, note)
                VALUES (%s, %s, %s, %s, %s);
                """,
                (activity_id, session_date, title, place, note)
            )

        conn.commit()
        cur.close()
        conn.close()

        add_audit_log("session_bulk_create", activity_id, "session", description=f"{start_date}から週次で{count}件の活動日を追加しました。")

        return redirect(url_for("sessions", activity_id=activity_id))

    return render_template(
        "add_sessions_bulk.html",
        activity=activity
    )


@app.route("/activities/<int:activity_id>/sessions/edit/<int:session_id>", methods=["GET", "POST"])
@login_required
@require_activity_role("owner", "staff")
def edit_session(activity_id, session_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        session_date = request.form.get("session_date", "")
        title = request.form.get("title", "通常活動")
        place = request.form.get("place", "")
        note = request.form.get("note", "")

        if not is_valid_date_string(session_date):
            cur.close()
            conn.close()
            return "活動日はYYYY-MM-DD形式で指定してください。", 400

        cur.execute(
            """
            UPDATE sessions
            SET session_date = %s,
                title = %s,
                place = %s,
                note = %s
            WHERE id = %s
              AND activity_id = %s;
            """,
            (session_date, title, place, note, session_id, activity_id)
        )

        conn.commit()
        cur.close()
        conn.close()

        add_audit_log("session_update", activity_id, "session", session_id, f"活動日「{session_date} {title}」を編集しました。")

        return redirect(url_for("sessions", activity_id=activity_id))

    cur.execute(
        """
        SELECT *
        FROM sessions
        WHERE id = %s
          AND activity_id = %s;
        """,
        (session_id, activity_id)
    )
    session_data = cur.fetchone()

    cur.close()
    conn.close()

    if session_data is None:
        return "この活動日は存在しないか、アクセス権限がありません。", 404

    return render_template(
        "edit_session.html",
        activity=activity,
        session=session_data
    )


@app.route("/activities/<int:activity_id>/sessions/delete/<int:session_id>", methods=["POST"])
@login_required
@require_activity_role("owner")
def delete_session(activity_id, session_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        DELETE FROM sessions
        WHERE id = %s
          AND activity_id = %s;
        """,
        (session_id, activity_id)
    )

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("session_delete", activity_id, "session", session_id, "活動日を削除しました。")

    return redirect(url_for("sessions", activity_id=activity_id))


@app.route("/activities/<int:activity_id>/sessions/<int:session_id>/reception")
@login_required
@require_activity_role("owner", "staff")
def reception(activity_id, session_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    keyword = request.args.get("keyword", "")
    status_filter = request.args.get("status_filter", "all")
    group_name_filter = request.args.get(
        "group_name_filter",
        request.args.get("part_filter", "all")
    )
    category_filter = request.args.get(
        "category_filter",
        request.args.get("generation_filter", "all")
    )

    # この活動日が、この活動に属しているか確認する。
    cur.execute(
        """
        SELECT *
        FROM sessions
        WHERE id = %s
          AND activity_id = %s;
        """,
        (session_id, activity_id)
    )
    session_data = cur.fetchone()

    if session_data is None:
        cur.close()
        conn.close()
        return "この活動日は存在しないか、アクセス権限がありません。", 404

    # この活動に所属しているメンバーだけ、受付データを作成する。
    cur.execute(
        """
        INSERT INTO attendance (session_id, member_id, status)
        SELECT %s, members.id, 'unchecked'
        FROM members
        WHERE members.activity_id = %s
          AND members.id NOT IN (
              SELECT member_id
              FROM attendance
              WHERE session_id = %s
          );
        """,
        (session_id, activity_id, session_id)
    )

    conn.commit()

    sql = """
        SELECT
            attendance.id,
            attendance.status,
            attendance.checked_in_at,
            members.id AS member_id,
            members.name,
            members.group_name,
            members.category,
            attendance.note
        FROM attendance
        JOIN members ON attendance.member_id = members.id
        WHERE attendance.session_id = %s
          AND members.activity_id = %s
    """

    params = [session_id, activity_id]

    if keyword:
        sql += " AND members.name ILIKE %s"
        params.append(f"%{keyword}%")

    if status_filter == "checked":
        sql += " AND attendance.status = %s"
        params.append("checked")
    elif status_filter == "unchecked":
        sql += " AND attendance.status = %s"
        params.append("unchecked")

    if group_name_filter != "all":
        sql += " AND members.group_name = %s"
        params.append(group_name_filter)

    if category_filter != "all":
        sql += " AND members.category = %s"
        params.append(category_filter)

    sql += " ORDER BY members.category, members.group_name, members.name;"

    cur.execute(sql, params)
    attendances = cur.fetchall()

    cur.execute(
        """
        SELECT
            COUNT(*) AS total_count,
            COUNT(*) FILTER (WHERE attendance.status = 'checked') AS checked_count,
            COUNT(*) FILTER (WHERE attendance.status = 'unchecked') AS unchecked_count
        FROM attendance
        JOIN members ON attendance.member_id = members.id
        WHERE attendance.session_id = %s
          AND members.activity_id = %s;
        """,
        (session_id, activity_id)
    )
    counts = cur.fetchone()

    cur.execute(
        """
        SELECT DISTINCT group_name
        FROM members
        WHERE activity_id = %s
          AND group_name IS NOT NULL
          AND BTRIM(group_name) <> ''
        ORDER BY group_name;
        """,
        (activity_id,)
    )
    group_names = [row["group_name"] for row in cur.fetchall()]

    cur.execute(
        """
        SELECT DISTINCT category
        FROM members
        WHERE activity_id = %s
          AND category IS NOT NULL
          AND BTRIM(category) <> ''
        ORDER BY category;
        """,
        (activity_id,)
    )
    categories = [row["category"] for row in cur.fetchall()]

    cur.close()
    conn.close()

    return render_template(
        "reception.html",
        activity=activity,
        session=session_data,
        attendances=attendances,
        counts=counts,
        keyword=keyword,
        status_filter=status_filter,
        group_name_filter=group_name_filter,
        category_filter=category_filter,
        group_names=group_names,
        categories=categories
    )


@app.route("/activities/<int:activity_id>/attendance/<int:attendance_id>/check_in", methods=["POST"])
@login_required
@require_activity_role("owner", "staff")
def check_in(activity_id, attendance_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    # この受付データが、この活動のものか確認する。
    cur.execute(
        """
        SELECT attendance.session_id
        FROM attendance
        JOIN sessions ON attendance.session_id = sessions.id
        JOIN members ON attendance.member_id = members.id
        WHERE attendance.id = %s
          AND sessions.activity_id = %s
          AND members.activity_id = %s;
        """,
        (attendance_id, activity_id, activity_id)
    )
    attendance_data = cur.fetchone()

    if attendance_data is None:
        cur.close()
        conn.close()
        return "この受付データは存在しないか、アクセス権限がありません。", 404

    session_id = attendance_data["session_id"]

    cur.execute(
        """
        UPDATE attendance
        SET status = 'checked',
            checked_in_at = NOW()
        WHERE id = %s;
        """,
        (attendance_id,)
    )

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("attendance_check_in", activity_id, "attendance", attendance_id, "受付済みに変更しました。")

    return redirect(url_for(
        "reception",
        activity_id=activity_id,
        session_id=session_id
    ))


@app.route("/activities/<int:activity_id>/attendance/<int:attendance_id>/cancel_check_in", methods=["POST"])
@login_required
@require_activity_role("owner", "staff")
def cancel_check_in(activity_id, attendance_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT attendance.session_id
        FROM attendance
        JOIN sessions ON attendance.session_id = sessions.id
        JOIN members ON attendance.member_id = members.id
        WHERE attendance.id = %s
          AND sessions.activity_id = %s
          AND members.activity_id = %s;
        """,
        (attendance_id, activity_id, activity_id)
    )
    attendance_data = cur.fetchone()

    if attendance_data is None:
        cur.close()
        conn.close()
        return "この受付データは存在しないか、アクセス権限がありません。", 404

    session_id = attendance_data["session_id"]

    cur.execute(
        """
        UPDATE attendance
        SET status = 'unchecked',
            checked_in_at = NULL
        WHERE id = %s;
        """,
        (attendance_id,)
    )

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("attendance_cancel", activity_id, "attendance", attendance_id, "未受付に戻しました。")

    return redirect(url_for(
        "reception",
        activity_id=activity_id,
        session_id=session_id
    ))


@app.route("/activities/<int:activity_id>/attendance/<int:attendance_id>/update_note", methods=["POST"])
@login_required
@require_activity_role("owner", "staff")
def update_attendance_note(activity_id, attendance_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    note = request.form.get("note", "")

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT attendance.session_id
        FROM attendance
        JOIN sessions ON attendance.session_id = sessions.id
        JOIN members ON attendance.member_id = members.id
        WHERE attendance.id = %s
          AND sessions.activity_id = %s
          AND members.activity_id = %s;
        """,
        (attendance_id, activity_id, activity_id)
    )
    attendance_data = cur.fetchone()

    if attendance_data is None:
        cur.close()
        conn.close()
        return "この受付データは存在しないか、アクセス権限がありません。", 404

    session_id = attendance_data["session_id"]

    cur.execute(
        """
        UPDATE attendance
        SET note = %s
        WHERE id = %s;
        """,
        (note, attendance_id)
    )

    conn.commit()
    cur.close()
    conn.close()

    add_audit_log("attendance_note_update", activity_id, "attendance", attendance_id, "受付備考を更新しました。")

    return redirect(url_for(
        "reception",
        activity_id=activity_id,
        session_id=session_id
    ))


@app.route("/activities/<int:activity_id>/sessions/<int:session_id>/export_csv")
@login_required
@require_activity_role("owner", "staff")
def export_csv(activity_id, session_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    # この活動日が、この活動に属しているか確認する。
    cur.execute(
        """
        SELECT *
        FROM sessions
        WHERE id = %s
          AND activity_id = %s;
        """,
        (session_id, activity_id)
    )
    session_data = cur.fetchone()

    if session_data is None:
        cur.close()
        conn.close()
        return "この活動日は存在しないか、アクセス権限がありません。", 404

    cur.execute(
        """
        SELECT
            members.name,
            members.group_name,
            members.category,
            attendance.status,
            attendance.checked_in_at,
            attendance.note
        FROM attendance
        JOIN members ON attendance.member_id = members.id
        JOIN sessions ON attendance.session_id = sessions.id
        WHERE attendance.session_id = %s
          AND members.activity_id = %s
          AND sessions.activity_id = %s
        ORDER BY members.category, members.group_name, members.name;
        """,
        (session_id, activity_id, activity_id)
    )
    attendances = cur.fetchall()

    cur.close()
    conn.close()

    filename = f"attendance_{session_data['session_date']}.csv"
    filepath = os.path.join(CSV_FOLDER, filename)

    with open(filepath, "w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(["名前", "所属グループ", "所属区分", "状態", "受付時刻", "備考"])

        for attendance in attendances:
            if attendance["status"] == "checked":
                status_text = "受付済み"
            else:
                status_text = "未受付"

            writer.writerow([
                attendance["name"],
                attendance["group_name"],
                attendance["category"],
                status_text,
                attendance["checked_in_at"] or "",
                attendance["note"] or ""
            ])

    add_audit_log("attendance_csv_export", activity_id, "session", session_id, "受付状況CSVを出力しました。")

    return send_file(
    filepath,
    mimetype="text/csv",
    as_attachment=True,
    download_name=filename
    )
    


@app.route("/activities/<int:activity_id>/attendance/summary")
@login_required
@require_activity_role("owner", "staff", "viewer")
def attendance_summary(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            members.id AS member_id,
            members.name,
            members.group_name,
            members.category,
            COUNT(attendance.id) AS total_count,
            COUNT(attendance.id) FILTER (WHERE attendance.status = 'checked') AS checked_count
        FROM members
        LEFT JOIN attendance ON members.id = attendance.member_id
        LEFT JOIN sessions ON attendance.session_id = sessions.id
        WHERE members.activity_id = %s
          AND (
              sessions.activity_id = %s
              OR sessions.id IS NULL
          )
        GROUP BY members.id, members.name, members.group_name, members.category
        ORDER BY members.category, members.group_name, members.name;
        """,
        (activity_id, activity_id)
    )

    summaries = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "attendance_summary.html",
        activity=activity,
        summaries=summaries
    )


@app.route("/activities/<int:activity_id>/attendance/group_summary")
@login_required
@require_activity_role("owner", "staff", "viewer")
def attendance_group_summary(activity_id):
    activity = get_activity_or_404(activity_id)

    if activity is None:
        return "この活動は存在しないか、アクセス権限がありません。", 404

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            members.group_name,
            COUNT(attendance.id) AS total_count,
            COUNT(attendance.id) FILTER (WHERE attendance.status = 'checked') AS checked_count
        FROM members
        LEFT JOIN attendance ON members.id = attendance.member_id
        LEFT JOIN sessions ON attendance.session_id = sessions.id
        WHERE members.activity_id = %s
          AND (
              sessions.activity_id = %s
              OR sessions.id IS NULL
          )
        GROUP BY members.group_name
        ORDER BY members.group_name;
        """,
        (activity_id, activity_id)
    )
    group_name_summaries = cur.fetchall()

    cur.execute(
        """
        SELECT
            members.category,
            COUNT(attendance.id) AS total_count,
            COUNT(attendance.id) FILTER (WHERE attendance.status = 'checked') AS checked_count
        FROM members
        LEFT JOIN attendance ON members.id = attendance.member_id
        LEFT JOIN sessions ON attendance.session_id = sessions.id
        WHERE members.activity_id = %s
          AND (
              sessions.activity_id = %s
              OR sessions.id IS NULL
          )
        GROUP BY members.category
        ORDER BY members.category;
        """,
        (activity_id, activity_id)
    )
    category_summaries = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "attendance_group_summary.html",
        activity=activity,
        group_name_summaries=group_name_summaries,
        category_summaries=category_summaries
    )


@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith("/api/"):
        return api_error("指定されたAPIは存在しません。", 404)

    return "ページが見つかりません。", 404


@app.errorhandler(CSRFError)
def csrf_error(error):
    return "不正なリクエストです。もう一度操作してください。", 400


@app.errorhandler(405)
def method_not_allowed_error(error):
    if request.path.startswith("/api/"):
        return api_error("このAPIでは指定されたHTTPメソッドは使用できません。", 405)

    return "この操作は許可されていません。", 405


@app.errorhandler(500)
def internal_server_error(error):
    if request.path.startswith("/api/"):
        return api_error("サーバー内部でエラーが発生しました。", 500)

    return "サーバー内部でエラーが発生しました。", 500


if __name__ == "__main__":
    debug_enabled = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug_enabled)
