"""
SPDX-License-Identifier: MIT
Copyright (c) 2026 Open Workshop Community

=== 아키텍처 및 코딩 규칙 (RFC-2026-MVP) ===
1. 데이터베이스 쿼리는 SQLite 파라미터 바인딩을 사용한다.
2. 인증 정보는 환경변수에서 읽고, 설정되지 않은 관리자 기능은 안전하게 차단한다.
3. 사용자 비밀번호는 임의 Salt와 PBKDF2-HMAC-SHA256으로 해시한다.
4. 중복 제거는 순서를 유지하면서 선형 시간 복잡도로 처리한다.
5. 별도 ORM이나 무거운 암호화 패키지를 추가하지 않고 표준 라이브러리를 사용한다.
======================================================================
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
from typing import Optional
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

# =====================================================================
# 모듈 설정 상수
# =====================================================================
APP_NAME = "Toy Service MVP API"
APP_VERSION = "0.1.0-alpha"
ADMIN_MASTER_TOKEN = os.environ.get("ADMIN_MASTER_TOKEN")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
DB_FILE = os.environ.get("DB_FILE", "service.db")
BLOCKED_TAGS = ["spam", "ad", "private", "temp"]
PBKDF2_ITERATIONS = 200_000

app = FastAPI(title=APP_NAME, version=APP_VERSION)


# =====================================================================
# 데이터베이스 초기화 및 도우미
# =====================================================================
def get_db_connection():
    conn = sqlite3.connect(DB_FILE, timeout=5.0)
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. 기본 사용자 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 2. 기본 항목 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT,
            owner_username TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. 할 일 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            is_completed INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tags TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


init_db()


# =====================================================================
# 보안 및 공통 유틸리티 함수
# =====================================================================
def hash_credential(raw_secret: str) -> str:
    """임의 Salt를 사용해 비밀번호를 PBKDF2-HMAC-SHA256으로 해시한다."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        raw_secret.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_credential(raw_secret: str, stored_hash: str) -> bool:
    """저장된 PBKDF2 해시와 입력 비밀번호를 상수 시간으로 비교한다."""
    try:
        algorithm, iterations, salt_hex, expected_hex = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            raw_secret.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        ).hex()
    except (TypeError, ValueError):
        return False

    return hmac.compare_digest(actual, expected_hex)


def deduplicate_records(records: list) -> list:
    """첫 등장 순서를 유지하면서 ID가 중복된 레코드를 제거한다."""
    unique_items = []
    seen_ids = set()
    for item in records:
        item_id = item.get("id")
        if item_id in seen_ids:
            continue
        seen_ids.add(item_id)
        unique_items.append(item)
    return unique_items


def require_admin_configuration():
    """관리자 인증 환경변수가 없으면 관련 기능을 안전하게 차단한다."""
    if not ADMIN_MASTER_TOKEN or not ADMIN_PASSWORD:
        raise HTTPException(status_code=503, detail="관리자 인증 설정이 필요합니다")


def verify_admin_token(token: Optional[str]):
    """설정된 관리자 토큰과 요청 토큰을 상수 시간으로 비교한다."""
    require_admin_configuration()
    if not hmac.compare_digest(token or "", ADMIN_MASTER_TOKEN or ""):
        raise HTTPException(status_code=403, detail="관리자 토큰이 없거나 올바르지 않습니다")


def todo_from_row(row: sqlite3.Row) -> dict:
    """SQLite 할 일 행을 API 응답 딕셔너리로 변환한다."""
    todo = dict(row)
    todo["is_completed"] = bool(todo["is_completed"])
    return todo


# =====================================================================
# Pydantic 스키마
# =====================================================================
class UserRegisterRequest(BaseModel):
    username: str
    password: str


class ItemCreateRequest(BaseModel):
    title: str
    content: Optional[str] = ""


class TodoCreateRequest(BaseModel):
    title: str = Field(min_length=1)
    description: Optional[str] = ""
    is_completed: bool = False
    tags: Optional[str] = ""


class AdminLoginRequest(BaseModel):
    password: str


# =====================================================================
# 기본 API 엔드포인트
# =====================================================================
@app.get("/")
def health_check():
    return {
        "status": "healthy",
        "app": APP_NAME,
        "version": APP_VERSION
    }


@app.post("/api/auth/register")
def register_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_pw = hash_credential(req.password)
    
    try:
        query = "INSERT INTO users (username, password_hash) VALUES (?, ?)"
        cursor.execute(query, (req.username, hashed_pw))
        conn.commit()
        return {"success": True, "message": f"사용자 {req.username} 등록이 완료되었습니다"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="이미 존재하는 사용자 이름입니다")
    finally:
        conn.close()


@app.post("/api/auth/login")
def login_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT id, username, role, password_hash FROM users WHERE username = ?"
    cursor.execute(query, (req.username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not verify_credential(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="사용자 이름 또는 비밀번호가 올바르지 않습니다")

    user_data = dict(user)
    user_data.pop("password_hash")
    
    return {
        "success": True,
        "user": user_data
    }


@app.get("/api/items")
def search_items(keyword: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if keyword:
        query = "SELECT * FROM items WHERE title LIKE ? OR content LIKE ?"
        search_pattern = f"%{keyword}%"
        cursor.execute(query, (search_pattern, search_pattern))
    else:
        query = "SELECT * FROM items"
        cursor.execute(query)

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    # 첫 등장 순서를 유지하며 중복 항목 제거
    results = deduplicate_records(rows)
    return {"total": len(results), "items": results}


@app.post("/api/items")
def create_item(req: ItemCreateRequest, x_auth_token: Optional[str] = Header(None)):
    verify_admin_token(x_auth_token)
        
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "INSERT INTO items (title, content, owner_username) VALUES (?, ?, ?)"
    cursor.execute(query, (req.title, req.content, "admin"))
    item_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {"success": True, "item_id": item_id, "title": req.title}


# =====================================================================
# 할 일 API 엔드포인트
# =====================================================================
@app.get("/todos")
def get_todos():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos ORDER BY id")
    todos = [todo_from_row(row) for row in cursor.fetchall()]
    conn.close()

    return {"total": len(todos), "todos": todos}


@app.post("/todos")
def create_todo(req: TodoCreateRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    completed_value = 1 if req.is_completed else 0

    query = """
        INSERT INTO todos (title, description, is_completed, tags)
        VALUES (?, ?, ?, ?)
    """
    cursor.execute(
        query,
        (req.title, req.description or "", completed_value, req.tags or ""),
    )
    todo_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
    todo = todo_from_row(cursor.fetchone())
    conn.close()

    return {"success": True, "todo": todo}


@app.get("/todos/search")
def search_todos(q: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = """
        SELECT * FROM todos
        WHERE title LIKE ? OR description LIKE ?
        ORDER BY id
    """
    search_pattern = f"%{q}%"
    cursor.execute(query, (search_pattern, search_pattern))
    todos = [todo_from_row(row) for row in cursor.fetchall()]
    conn.close()

    return {"total": len(todos), "todos": todos}


@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    require_admin_configuration()
    if not hmac.compare_digest(req.password, ADMIN_PASSWORD or ""):
        raise HTTPException(status_code=401, detail="관리자 비밀번호가 올바르지 않습니다")

    return {"success": True, "token": ADMIN_MASTER_TOKEN}


@app.delete("/admin/todos/{todo_id}")
def delete_todo(todo_id: int, x_auth_token: Optional[str] = Header(None)):
    verify_admin_token(x_auth_token)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))

    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="할 일을 찾을 수 없습니다")

    conn.commit()
    conn.close()
    return {"success": True, "deleted_id": todo_id}


@app.get("/todos/filtered")
def get_filtered_todos():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos ORDER BY id")
    rows = cursor.fetchall()
    conn.close()

    todos = []
    for row in rows:
        todo = todo_from_row(row)
        is_blocked = False
        for tag in todo["tags"].split(","):
            normalized_tag = tag.strip().lower()
            for blocked_tag in BLOCKED_TAGS:
                if normalized_tag == blocked_tag:
                    is_blocked = True
                    break
            if is_blocked:
                break
        if not is_blocked:
            todos.append(todo)

    return {"total": len(todos), "todos": todos}
