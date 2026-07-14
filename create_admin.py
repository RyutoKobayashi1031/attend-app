import getpass
import os
import sys

import psycopg2
from dotenv import load_dotenv
from psycopg2 import errors
from werkzeug.security import generate_password_hash


REQUIRED_DB_ENV_VARS = (
    "DB_HOST",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "DB_PORT",
)


def get_db_connection():
    missing = [name for name in REQUIRED_DB_ENV_VARS if not os.getenv(name)]
    if missing:
        raise ValueError(
            "次の環境変数が設定されていません: " + ", ".join(missing)
        )

    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        port=os.getenv("DB_PORT"),
    )


def validate_input(username, email, password, confirm_password):
    if not username:
        return "username は必須です。"
    if not email:
        return "email は必須です。"
    if len(password) < 8:
        return "password は8文字以上で入力してください。"
    if password != confirm_password:
        return "password と confirm_password が一致しません。"
    return None


def create_user(username, email, password):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE username = %s;", (username,))
            if cur.fetchone() is not None:
                return "その username は既に使用されています。"

            cur.execute(
                "SELECT 1 FROM users WHERE LOWER(email) = LOWER(%s);",
                (email,),
            )
            if cur.fetchone() is not None:
                return "その email は既に使用されています。"

            cur.execute(
                """
                INSERT INTO users (username, email, password_hash, is_active)
                VALUES (%s, %s, %s, TRUE);
                """,
                (username, email, generate_password_hash(password)),
            )
        conn.commit()
        return None
    except errors.UniqueViolation:
        conn.rollback()
        return "username または email は既に使用されています。"
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def main():
    load_dotenv()

    username = input("username: ").strip()
    email = input("email: ").strip()
    password = getpass.getpass("password: ")
    confirm_password = getpass.getpass("confirm_password: ")

    validation_error = validate_input(
        username, email, password, confirm_password
    )
    if validation_error:
        print(validation_error, file=sys.stderr)
        return 1

    try:
        registration_error = create_user(username, email, password)
    except (ValueError, psycopg2.Error) as exc:
        print(f"ユーザーを作成できませんでした: {exc}", file=sys.stderr)
        return 1

    if registration_error:
        print(registration_error, file=sys.stderr)
        return 1

    print(f"ユーザー '{username}' を作成しました。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
