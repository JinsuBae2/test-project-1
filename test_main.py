import importlib.util
import sqlite3
import sys
from pathlib import Path

from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).parent


def load_app(tmp_path, monkeypatch, admin_token=None, admin_password=None):
    db_file = tmp_path / "service.db"
    monkeypatch.setenv("DB_FILE", str(db_file))

    if admin_token is None:
        monkeypatch.delenv("ADMIN_MASTER_TOKEN", raising=False)
    else:
        monkeypatch.setenv("ADMIN_MASTER_TOKEN", admin_token)

    if admin_password is None:
        monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("ADMIN_PASSWORD", admin_password)

    module_name = f"main_{tmp_path.name}_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(module_name, PROJECT_ROOT / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    module.DB_FILE = str(db_file)
    module.init_db()
    return module, TestClient(module.app, raise_server_exceptions=False)


def test_sql_injection_payload_is_stored_as_plain_username(tmp_path, monkeypatch):
    module, client = load_app(tmp_path, monkeypatch)
    username = "attacker'); DROP TABLE todos; --"

    response = client.post(
        "/api/auth/register",
        json={"username": username, "password": "safe-password"},
    )

    assert response.status_code == 200
    conn = sqlite3.connect(module.DB_FILE)
    stored_username = conn.execute("SELECT username FROM users").fetchone()[0]
    todos_table = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'todos'"
    ).fetchone()
    conn.close()
    assert stored_username == username
    assert todos_table == ("todos",)


def test_search_treats_sql_metacharacters_as_plain_text(tmp_path, monkeypatch):
    module, client = load_app(tmp_path, monkeypatch)
    conn = sqlite3.connect(module.DB_FILE)
    conn.execute(
        "INSERT INTO items (title, content, owner_username) VALUES (?, ?, ?)",
        ("Visible item", "ordinary content", "admin"),
    )
    conn.commit()
    conn.close()

    response = client.get("/api/items", params={"keyword": "' OR 1=1 --"})

    assert response.status_code == 200
    assert response.json() == {"total": 0, "items": []}


def test_admin_credentials_come_from_environment(tmp_path, monkeypatch):
    _, client = load_app(
        tmp_path,
        monkeypatch,
        admin_token="runtime-token",
        admin_password="runtime-password",
    )

    response = client.post("/admin/login", json={"password": "runtime-password"})

    assert response.status_code == 200
    assert response.json() == {"success": True, "token": "runtime-token"}


def test_admin_login_fails_closed_without_environment(tmp_path, monkeypatch):
    _, client = load_app(tmp_path, monkeypatch)

    response = client.post("/admin/login", json={"password": "admin1234"})

    assert response.status_code == 503


def test_user_passwords_use_unique_salted_pbkdf2_hashes(tmp_path, monkeypatch):
    module, client = load_app(tmp_path, monkeypatch)

    for username in ("first-user", "second-user"):
        response = client.post(
            "/api/auth/register",
            json={"username": username, "password": "same-password"},
        )
        assert response.status_code == 200

    conn = sqlite3.connect(module.DB_FILE)
    hashes = [row[0] for row in conn.execute("SELECT password_hash FROM users ORDER BY id")]
    conn.close()

    assert all(value.startswith("pbkdf2_sha256$") for value in hashes)
    assert hashes[0] != hashes[1]

    login = client.post(
        "/api/auth/login",
        json={"username": "first-user", "password": "same-password"},
    )
    assert login.status_code == 200


def test_regular_user_login_does_not_expose_admin_token(tmp_path, monkeypatch):
    _, client = load_app(
        tmp_path,
        monkeypatch,
        admin_token="runtime-token",
        admin_password="runtime-password",
    )
    client.post(
        "/api/auth/register",
        json={"username": "regular-user", "password": "user-password"},
    )

    response = client.post(
        "/api/auth/login",
        json={"username": "regular-user", "password": "user-password"},
    )

    assert response.status_code == 200
    assert "token" not in response.json()


def test_todo_flow_preserves_search_filter_and_admin_delete(tmp_path, monkeypatch):
    _, client = load_app(
        tmp_path,
        monkeypatch,
        admin_token="runtime-token",
        admin_password="runtime-password",
    )
    clean = client.post(
        "/todos",
        json={
            "title": "회의 준비",
            "description": "milk 안건 검토",
            "is_completed": False,
            "tags": "work",
        },
    ).json()["todo"]
    client.post(
        "/todos",
        json={"title": "광고", "description": "제외 대상", "tags": "ad"},
    )

    assert client.get("/todos").json()["total"] == 2
    assert client.get("/todos/search", params={"q": "milk"}).json()["total"] == 1
    assert client.get("/todos/filtered").json()["total"] == 1

    deleted = client.delete(
        f"/admin/todos/{clean['id']}",
        headers={"X-Auth-Token": "runtime-token"},
    )
    assert deleted.status_code == 200
    assert client.get("/todos").json()["total"] == 1


def test_protected_endpoints_fail_closed_without_environment(tmp_path, monkeypatch):
    _, client = load_app(tmp_path, monkeypatch)

    create_item = client.post(
        "/api/items",
        json={"title": "항목", "content": "내용"},
    )
    delete_todo = client.delete("/admin/todos/1")

    assert create_item.status_code == 503
    assert delete_todo.status_code == 503


def test_deduplicate_records_keeps_first_occurrence_order(tmp_path, monkeypatch):
    module, _ = load_app(tmp_path, monkeypatch)
    records = [
        {"id": 2, "title": "first"},
        {"id": 1, "title": "second"},
        {"id": 2, "title": "duplicate"},
    ]

    result = module.deduplicate_records(records)

    assert result == [
        {"id": 2, "title": "first"},
        {"id": 1, "title": "second"},
    ]
