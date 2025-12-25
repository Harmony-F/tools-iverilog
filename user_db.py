import hashlib
import json
import os
import secrets
from typing import Dict, Tuple

USER_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "users.json")
ITERATIONS = 120_000


def _load_users() -> Dict[str, Dict[str, str]]:
    if not os.path.exists(USER_DB_PATH):
        return {}
    with open(USER_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_users(users: Dict[str, Dict[str, str]]) -> None:
    os.makedirs(os.path.dirname(USER_DB_PATH), exist_ok=True)
    with open(USER_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def create_user(username: str, password: str) -> Tuple[str, str]:
    users = _load_users()
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), ITERATIONS
    ).hex()
    users[username] = {
        "salt": salt,
        "iterations": ITERATIONS,
        "hash": password_hash,
    }
    _save_users(users)
    return username, password_hash


def verify_user(username: str, password: str) -> bool:
    users = _load_users()
    if username not in users:
        return False
    entry = users[username]
    candidate_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        entry["salt"].encode("utf-8"),
        int(entry.get("iterations", ITERATIONS)),
    ).hex()
    return secrets.compare_digest(candidate_hash, entry["hash"])


def verify_user_with_hashes(username: str, password: str) -> Tuple[bool, Dict[str, str]]:
    """Verify credentials and return hashed representations when successful."""

    users = _load_users()
    username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()

    if username not in users:
        return False, {"error": "用户名或密码错误", "username_hash": username_hash}

    entry = users[username]
    candidate_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        entry["salt"].encode("utf-8"),
        int(entry.get("iterations", ITERATIONS)),
    ).hex()

    if not secrets.compare_digest(candidate_hash, entry["hash"]):
        return False, {"error": "用户名或密码错误", "username_hash": username_hash}

    return True, {
        "username_hash": username_hash,
        "password_hash": entry["hash"],
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Create a new user with hashed password")
    parser.add_argument("username")
    parser.add_argument("password")
    args = parser.parse_args()
    user, password_hash = create_user(args.username, args.password)
    print(f"Created user '{user}' with PBKDF2-HMAC-SHA256 hash stored in {USER_DB_PATH}.")
