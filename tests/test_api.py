import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DB_FILE", str(tmp_path / "test.db"))
    monkeypatch.setenv("ADMIN_MASTER_TOKEN", "test-admin-token")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-password")

    module_name = f"todo_app_{tmp_path.name}"
    spec = importlib.util.spec_from_file_location(module_name, PROJECT_ROOT / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    with TestClient(module.app, raise_server_exceptions=False) as client:
        yield module, client

    sys.modules.pop(module_name, None)


def test_todo_crud_flow(app_client):
    _, client = app_client
    created = client.post(
        "/todos",
        json={
            "title": "하네스 검증",
            "description": "CRUD 테스트",
            "is_completed": False,
            "tags": "work,api",
        },
    )
    assert created.status_code == 200
    todo_id = created.json()["todo"]["id"]

    listed = client.get("/todos")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1

    deleted = client.delete(
        f"/admin/todos/{todo_id}",
        headers={"X-Auth-Token": "test-admin-token"},
    )
    assert deleted.status_code == 200
    assert client.get("/todos").json() == {"total": 0, "todos": []}


def test_sql_injection_payload_is_stored_as_plain_data(app_client):
    _, client = app_client
    attack = "할 일'); DROP TABLE todos; --"

    response = client.post("/todos", json={"title": attack, "tags": "security"})

    assert response.status_code == 200
    todos = client.get("/todos").json()["todos"]
    assert todos[0]["title"] == attack
    assert client.get("/todos").status_code == 200


def test_registration_rejects_sql_execution_and_preserves_input(app_client):
    module, client = app_client
    attack = "user'); DROP TABLE todos; --"

    response = client.post(
        "/api/auth/register",
        json={"username": attack, "password": "safe-password"},
    )

    assert response.status_code == 200
    conn = sqlite3.connect(module.DB_FILE)
    stored = conn.execute("SELECT username FROM users").fetchone()[0]
    table = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'todos'"
    ).fetchone()
    conn.close()
    assert stored == attack
    assert table == ("todos",)


def test_invalid_admin_token_is_rejected(app_client):
    _, client = app_client
    created = client.post("/todos", json={"title": "보호 대상"}).json()["todo"]

    response = client.delete(
        f"/admin/todos/{created['id']}",
        headers={"X-Auth-Token": "wrong-token"},
    )

    assert response.status_code in (401, 403)
    assert client.get("/todos").json()["total"] == 1


def test_empty_title_is_rejected(app_client):
    _, client = app_client

    response = client.post("/todos", json={"title": ""})

    assert response.status_code == 422


def test_database_connection_enables_wal_and_busy_timeout(app_client):
    module, _ = app_client
    conn = module.get_db_connection()

    journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
    conn.close()

    assert journal_mode.lower() == "wal"
    assert busy_timeout == 5000


def test_health_check_returns_application_metadata(app_client):
    _, client = app_client

    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_user_registration_login_and_duplicate_rejection(app_client):
    module, client = app_client
    credentials = {"username": "member", "password": "member-password"}

    assert client.post("/api/auth/register", json=credentials).status_code == 200
    assert client.post("/api/auth/register", json=credentials).status_code == 400

    login = client.post("/api/auth/login", json=credentials)
    assert login.status_code == 200
    assert "token" not in login.json()
    assert client.post(
        "/api/auth/login",
        json={"username": "member", "password": "wrong-password"},
    ).status_code == 401
    assert module.verify_credential("member-password", "invalid-hash") is False


def test_admin_item_creation_and_search(app_client):
    _, client = app_client

    created = client.post(
        "/api/items",
        json={"title": "검색 가능한 항목", "content": "보안 문서"},
        headers={"X-Auth-Token": "test-admin-token"},
    )

    assert created.status_code == 200
    assert client.get("/api/items").json()["total"] == 1
    searched = client.get("/api/items", params={"keyword": "보안"})
    assert searched.status_code == 200
    assert searched.json()["items"][0]["title"] == "검색 가능한 항목"


def test_todo_search_and_blocked_tag_filter(app_client):
    _, client = app_client
    client.post(
        "/todos",
        json={"title": "회의", "description": "우유 논의", "tags": "work"},
    )
    client.post(
        "/todos",
        json={"title": "광고", "description": "제외 대상", "tags": "work, ad"},
    )

    search = client.get("/todos/search", params={"q": "우유"})
    filtered = client.get("/todos/filtered")

    assert search.json()["total"] == 1
    assert filtered.json()["total"] == 1
    assert filtered.json()["todos"][0]["title"] == "회의"


def test_admin_login_and_missing_todo_handling(app_client):
    _, client = app_client

    assert client.post(
        "/admin/login",
        json={"password": "wrong-password"},
    ).status_code == 401
    login = client.post(
        "/admin/login",
        json={"password": "test-admin-password"},
    )
    assert login.status_code == 200
    assert login.json()["token"] == "test-admin-token"

    missing = client.delete(
        "/admin/todos/999",
        headers={"X-Auth-Token": "test-admin-token"},
    )
    assert missing.status_code == 404


def test_admin_endpoints_fail_closed_without_configuration(app_client):
    module, client = app_client
    module.ADMIN_MASTER_TOKEN = None
    module.ADMIN_PASSWORD = None

    assert client.post(
        "/admin/login",
        json={"password": "anything"},
    ).status_code == 503
    assert client.delete("/admin/todos/1").status_code == 503


def test_deduplication_keeps_first_occurrence(app_client):
    module, _ = app_client
    records = [
        {"id": 2, "title": "첫 번째"},
        {"id": 1, "title": "두 번째"},
        {"id": 2, "title": "중복"},
    ]

    assert module.deduplicate_records(records) == records[:2]
