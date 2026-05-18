# -*- coding: utf-8 -*-
"""
K-water 방문 사전신청 시스템
- Streamlit + SQLite 기본 실행
- DATABASE_URL 설정 시 PostgreSQL/MariaDB 등 서버 DB로 확장 가능
- 사내 노트북 검증 후 회사 클라우드/내부 서버 배포를 고려한 단일 앱

실행:
    python -m streamlit run app.py --server.address 0.0.0.0 --server.port 8501
"""

from __future__ import annotations

import os
import secrets
import hashlib
from datetime import datetime, date
from typing import Any, Dict, Optional, List

import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

load_dotenv()

# GitHub/Streamlit Cloud 배포 시 data, logs 폴더가 없어도 자동 생성
PathLike = __import__("pathlib").Path
PathLike("data").mkdir(exist_ok=True)
PathLike("logs").mkdir(exist_ok=True)

APP_TITLE = os.getenv("APP_TITLE", "K-water 방문 사전신청 시스템")
APP_SUBTITLE = os.getenv("APP_SUBTITLE", "부서 신청 · 관리자 승인 · 초소 모니터링 통합 운영")
MONITOR_CODE = os.getenv("MONITOR_CODE", "monitor1234")
DEPT_USER_LIMIT = int(os.getenv("DEPT_USER_LIMIT", "2"))
AUTO_REFRESH_SECONDS = int(os.getenv("AUTO_REFRESH_SECONDS", "5"))

DEFAULT_ADMINS = [
    ("admin01", "kwater1234", "관리자1", "비상계획처"),
    ("admin02", "kwater1234", "관리자2", "정보보안처"),
    ("admin03", "kwater1234", "관리자3", "시설관리부"),
]

DEPARTMENTS = [
    "비상계획처", "정보보안처", "시설관리부", "총무부", "안전보건부",
    "운영부서", "정문초소", "1층 안내데스크", "3층 안내데스크", "세종관", "후문", "기타"
]

MONITOR_LOCATIONS = ["정문초소", "1층 안내데스크", "3층 안내데스크", "세종관", "후문"]

STATUS_LABELS = {
    "pending": "승인대기",
    "approved": "승인",
    "rejected": "반려",
}

ENTRY_LABELS = {
    "waiting": "입문대기",
    "entered": "입문완료",
    "exited": "퇴문완료",
}

# -----------------------------
# 기본 설정
# -----------------------------
st.set_page_config(
    page_title=APP_TITLE,
    page_icon="🏢",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
:root {
  --kw-bg:#eef3f0;
  --kw-card:#ffffff;
  --kw-primary:#365b6d;
  --kw-primary2:#2a4756;
  --kw-line:#d8e0dd;
  --kw-sub:#5c6f79;
}
.main .block-container {padding-top: 1.4rem; max-width: 1480px;}
div[data-testid="stMetric"] {
  background: linear-gradient(180deg,#ffffff,#f4f8f6);
  border:1px solid var(--kw-line);
  border-radius:18px;
  padding:14px 16px;
}
.kw-hero {
  background: linear-gradient(135deg, #eef5f2 0%, #dde8e3 100%);
  border:1px solid #d6e1dd;
  border-radius:22px;
  padding:24px 28px;
  margin-bottom:18px;
}
.kw-title {font-size:30px; font-weight:800; color:#1e313d; margin:0;}
.kw-sub {font-size:14px; color:var(--kw-sub); line-height:1.7; margin-top:8px;}
.kw-card {
  background:#fff;
  border:1px solid var(--kw-line);
  border-radius:18px;
  padding:18px 20px;
  margin:10px 0;
}
.kw-alert {
  background:#fff7e6;
  border:1px solid #e4c879;
  color:#6d510f;
  border-radius:16px;
  padding:14px 16px;
  margin:10px 0 16px;
}
.kw-ok {
  background:#edf8f0;
  border:1px solid #c9e4d1;
  color:#2a6f46;
  border-radius:16px;
  padding:14px 16px;
  margin:10px 0 16px;
}
.kw-danger {
  background:#fff0f0;
  border:1px solid #efcccc;
  color:#9e5651;
  border-radius:16px;
  padding:14px 16px;
  margin:10px 0 16px;
}
.small-muted {font-size:12px; color:#6d7e86;}
hr {border-color:#eef2f0;}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# -----------------------------
# DB / 보안 유틸
# -----------------------------
def normalize_database_url(url: str) -> str:
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


@st.cache_resource
def get_engine() -> Engine:
    db_url = os.getenv("DATABASE_URL", "sqlite:///data/visit_system.db")
    db_url = normalize_database_url(db_url)

    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}

    return create_engine(db_url, pool_pre_ping=True, future=True, connect_args=connect_args)


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_str() -> str:
    return date.today().isoformat()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    iterations = 200_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt, hexhash = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iterations))
        return secrets.compare_digest(dk.hex(), hexhash)
    except Exception:
        return False


def execute(sql: str, params: Optional[Dict[str, Any]] = None) -> None:
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(text(sql), params or {})


def fetch_all(sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    engine = get_engine()
    with engine.begin() as conn:
        rows = conn.execute(text(sql), params or {}).mappings().all()
    return [dict(r) for r in rows]


def fetch_one(sql: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    rows = fetch_all(sql, params)
    return rows[0] if rows else None


def init_db() -> None:
    """SQLite/PostgreSQL 공통 사용을 고려해 범용 SQL 위주로 구성."""
    execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username VARCHAR(80) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name VARCHAR(100) NOT NULL,
        department VARCHAR(100) NOT NULL,
        role VARCHAR(30) NOT NULL DEFAULT 'user',
        status VARCHAR(30) NOT NULL DEFAULT 'pending',
        requested_reason TEXT,
        created_at VARCHAR(30) NOT NULL,
        approved_at VARCHAR(30),
        approved_by VARCHAR(80),
        last_login_at VARCHAR(30)
    )
    """)

    execute("""
    CREATE TABLE IF NOT EXISTS visits (
        id INTEGER PRIMARY KEY,
        request_user VARCHAR(80) NOT NULL,
        request_name VARCHAR(100) NOT NULL,
        request_department VARCHAR(100) NOT NULL,
        visit_date VARCHAR(20) NOT NULL,
        visit_time VARCHAR(20) NOT NULL,
        visitor_name VARCHAR(100) NOT NULL,
        visitor_org VARCHAR(150),
        visitor_phone VARCHAR(80),
        vehicle_no VARCHAR(80),
        target_department VARCHAR(100) NOT NULL,
        purpose TEXT NOT NULL,
        request_note TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'pending',
        entry_status VARCHAR(30) NOT NULL DEFAULT 'waiting',
        admin_memo TEXT,
        approved_at VARCHAR(30),
        approved_by VARCHAR(80),
        rejected_at VARCHAR(30),
        rejected_by VARCHAR(80),
        entered_at VARCHAR(30),
        entered_by VARCHAR(80),
        entry_location VARCHAR(100),
        exited_at VARCHAR(30),
        exited_by VARCHAR(80),
        exit_location VARCHAR(100),
        created_at VARCHAR(30) NOT NULL,
        updated_at VARCHAR(30) NOT NULL
    )
    """)

    execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY,
        event_type VARCHAR(60) NOT NULL,
        title VARCHAR(200) NOT NULL,
        body TEXT,
        target_role VARCHAR(30) DEFAULT 'admin',
        created_at VARCHAR(30) NOT NULL
    )
    """)

    # 기본 관리자 계정 생성
    for username, password, name, dept in DEFAULT_ADMINS:
        existing = fetch_one("SELECT id FROM users WHERE username=:username", {"username": username})
        if not existing:
            execute("""
            INSERT INTO users
            (username, password_hash, name, department, role, status, requested_reason, created_at, approved_at, approved_by)
            VALUES
            (:username, :password_hash, :name, :department, 'admin', 'approved', '초기 관리자 계정', :created_at, :created_at, 'system')
            """, {
                "username": username,
                "password_hash": hash_password(password),
                "name": name,
                "department": dept,
                "created_at": now_str(),
            })


def add_event(event_type: str, title: str, body: str = "", target_role: str = "admin") -> None:
    execute("""
    INSERT INTO events (event_type, title, body, target_role, created_at)
    VALUES (:event_type, :title, :body, :target_role, :created_at)
    """, {
        "event_type": event_type,
        "title": title,
        "body": body,
        "target_role": target_role,
        "created_at": now_str(),
    })


def login(username: str, password: str) -> Optional[Dict[str, Any]]:
    user = fetch_one("SELECT * FROM users WHERE username=:username", {"username": username.strip()})
    if not user:
        return None
    if user["status"] != "approved":
        return {"error": f"계정 상태가 '{STATUS_LABELS.get(user['status'], user['status'])}'입니다. 관리자 승인 후 이용 가능합니다."}
    if not verify_password(password, user["password_hash"]):
        return None
    execute("UPDATE users SET last_login_at=:t WHERE username=:u", {"t": now_str(), "u": username.strip()})
    user.pop("password_hash", None)
    return user


def require_login() -> Optional[Dict[str, Any]]:
    return st.session_state.get("user")


def is_admin(user: Dict[str, Any]) -> bool:
    return user.get("role") == "admin"


def approved_user_count_by_department(dept: str) -> int:
    row = fetch_one("""
    SELECT COUNT(*) AS cnt FROM users
    WHERE department=:dept AND role='user' AND status='approved'
    """, {"dept": dept})
    return int(row["cnt"]) if row else 0


# -----------------------------
# 화면 공통
# -----------------------------
def header():
    st.markdown(
        f"""
        <div class="kw-hero">
          <div class="kw-title">🏢 {APP_TITLE}</div>
          <div class="kw-sub">{APP_SUBTITLE}<br>
          <b>운영 구조:</b> Streamlit 웹앱 + 공통 DB 저장 · 사내 노트북/고정PC/클라우드 서버 배포 가능</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def sidebar_login_status():
    user = require_login()
    with st.sidebar:
        st.markdown("### 접속 정보")
        if user:
            st.success(f"{user['name']}님 로그인")
            st.caption(f"{user['department']} · {user['role']}")
            if st.button("로그아웃", use_container_width=True):
                st.session_state.clear()
                st.rerun()
        else:
            st.info("로그인 전입니다.")


def enable_auto_refresh():
    # Streamlit 기본 기능만 사용하기 위해 JS로 페이지 새로고침
    if st.sidebar.checkbox("자동 새로고침", value=False, help=f"{AUTO_REFRESH_SECONDS}초 간격으로 화면을 갱신합니다."):
        import streamlit.components.v1 as components
        components.html(
            f"<script>setTimeout(function(){{ window.parent.location.reload(); }}, {AUTO_REFRESH_SECONDS * 1000});</script>",
            height=0,
        )


def admin_notification():
    user = require_login()
    if not user or not is_admin(user):
        return
    pending_users = fetch_one("SELECT COUNT(*) AS cnt FROM users WHERE role='user' AND status='pending'")
    pending_visits = fetch_one("SELECT COUNT(*) AS cnt FROM visits WHERE status='pending'")
    pu = int(pending_users["cnt"]) if pending_users else 0
    pv = int(pending_visits["cnt"]) if pending_visits else 0

    if pu or pv:
        st.markdown(
            f"""
            <div class="kw-alert">
            🔔 <b>관리자 확인 필요</b><br>
            승인 대기 계정 <b>{pu}</b>건 · 승인 대기 방문신청 <b>{pv}</b>건이 있습니다.
            </div>
            """,
            unsafe_allow_html=True,
        )


# -----------------------------
# 페이지: 로그인 / 계정신청
# -----------------------------
def page_login():
    header()
    col1, col2 = st.columns([0.95, 1.05])

    with col1:
        st.subheader("로그인")
        with st.form("login_form"):
            username = st.text_input("아이디")
            password = st.text_input("비밀번호", type="password")
            submitted = st.form_submit_button("로그인", use_container_width=True)
        if submitted:
            result = login(username, password)
            if result and "error" in result:
                st.warning(result["error"])
            elif result:
                st.session_state["user"] = result
                st.success("로그인되었습니다.")
                st.rerun()
            else:
                st.error("아이디 또는 비밀번호가 올바르지 않습니다.")

        st.markdown("""
        <div class="kw-card">
        <b>초기 관리자 계정</b><br>
        admin01 / kwater1234 / 비상계획처<br>
        admin02 / kwater1234 / 정보보안처<br>
        admin03 / kwater1234 / 시설관리부
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.subheader("부서 사용자 계정 신청")
        with st.form("account_request_form", clear_on_submit=True):
            name = st.text_input("성명 *")
            department = st.selectbox("부서 *", DEPARTMENTS, index=0)
            username = st.text_input("희망 아이디 *")
            password = st.text_input("비밀번호 *", type="password")
            password2 = st.text_input("비밀번호 확인 *", type="password")
            reason = st.text_area("신청 사유", placeholder="예: 방문 사전신청 담당자")
            agree = st.checkbox("계정 승인 후 방문신청 업무 목적으로만 사용하겠습니다.")
            submitted = st.form_submit_button("계정 신청", use_container_width=True)

        if submitted:
            if not all([name.strip(), username.strip(), password]):
                st.error("성명, 아이디, 비밀번호는 필수입니다.")
            elif password != password2:
                st.error("비밀번호 확인이 일치하지 않습니다.")
            elif not agree:
                st.error("사용 목적 확인에 동의해야 합니다.")
            elif fetch_one("SELECT id FROM users WHERE username=:u", {"u": username.strip()}):
                st.error("이미 사용 중인 아이디입니다.")
            else:
                execute("""
                INSERT INTO users
                (username, password_hash, name, department, role, status, requested_reason, created_at)
                VALUES
                (:username, :password_hash, :name, :department, 'user', 'pending', :reason, :created_at)
                """, {
                    "username": username.strip(),
                    "password_hash": hash_password(password),
                    "name": name.strip(),
                    "department": department,
                    "reason": reason.strip(),
                    "created_at": now_str(),
                })
                add_event("user_request", "신규 계정신청", f"{department} / {name} / {username}")
                st.success("계정신청이 접수되었습니다. 관리자 승인 후 로그인할 수 있습니다.")


# -----------------------------
# 페이지: 대시보드
# -----------------------------
def page_dashboard():
    header()
    admin_notification()

    today = today_str()
    metrics = {
        "승인대기 계정": fetch_one("SELECT COUNT(*) AS cnt FROM users WHERE role='user' AND status='pending'")["cnt"],
        "승인대기 방문": fetch_one("SELECT COUNT(*) AS cnt FROM visits WHERE status='pending'")["cnt"],
        "오늘 승인 방문": fetch_one("SELECT COUNT(*) AS cnt FROM visits WHERE visit_date=:d AND status='approved'", {"d": today})["cnt"],
        "오늘 입문 완료": fetch_one("SELECT COUNT(*) AS cnt FROM visits WHERE visit_date=:d AND entry_status='entered'", {"d": today})["cnt"],
    }
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("승인대기 계정", metrics["승인대기 계정"])
    c2.metric("승인대기 방문신청", metrics["승인대기 방문"])
    c3.metric("오늘 승인 방문", metrics["오늘 승인 방문"])
    c4.metric("오늘 입문 완료", metrics["오늘 입문 완료"])

    st.subheader("최근 방문신청")
    rows = fetch_all("""
    SELECT id, created_at, request_department, request_name, visit_date, visit_time,
           visitor_name, visitor_org, target_department, status, entry_status
    FROM visits
    ORDER BY id DESC
    LIMIT 30
    """)
    if rows:
        df = pd.DataFrame(rows)
        df["status"] = df["status"].map(lambda x: STATUS_LABELS.get(x, x))
        df["entry_status"] = df["entry_status"].map(lambda x: ENTRY_LABELS.get(x, x))
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("등록된 방문신청이 없습니다.")


# -----------------------------
# 페이지: 관리자 계정승인
# -----------------------------
def page_user_approval():
    st.subheader("부서 사용자 계정 승인")
    admin_notification()

    rows = fetch_all("""
    SELECT id, username, name, department, status, requested_reason, created_at, approved_at, approved_by
    FROM users
    WHERE role='user'
    ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, id DESC
    """)
    if not rows:
        st.info("신청된 사용자 계정이 없습니다.")
        return

    for r in rows:
        with st.expander(f"[{STATUS_LABELS.get(r['status'], r['status'])}] {r['department']} · {r['name']} ({r['username']})", expanded=(r["status"]=="pending")):
            st.write(f"신청일시: {r['created_at']}")
            st.write(f"신청사유: {r.get('requested_reason') or '-'}")
            st.write(f"승인정보: {r.get('approved_at') or '-'} / {r.get('approved_by') or '-'}")

            if r["status"] == "pending":
                approved_count = approved_user_count_by_department(r["department"])
                st.caption(f"현재 {r['department']} 승인 사용자 수: {approved_count}명 / 제한 {DEPT_USER_LIMIT}명")
                c1, c2 = st.columns(2)
                with c1:
                    if st.button("승인", key=f"approve_user_{r['id']}", use_container_width=True):
                        if approved_count >= DEPT_USER_LIMIT:
                            st.error(f"{r['department']}은 승인 사용자 {DEPT_USER_LIMIT}명 제한에 도달했습니다.")
                        else:
                            execute("""
                            UPDATE users SET status='approved', approved_at=:t, approved_by=:by
                            WHERE id=:id
                            """, {"t": now_str(), "by": st.session_state["user"]["username"], "id": r["id"]})
                            add_event("user_approved", "계정 승인", f"{r['department']} / {r['name']} / {r['username']}")
                            st.success("승인되었습니다.")
                            st.rerun()
                with c2:
                    if st.button("반려", key=f"reject_user_{r['id']}", use_container_width=True):
                        execute("""
                        UPDATE users SET status='rejected', approved_at=:t, approved_by=:by
                        WHERE id=:id
                        """, {"t": now_str(), "by": st.session_state["user"]["username"], "id": r["id"]})
                        add_event("user_rejected", "계정 반려", f"{r['department']} / {r['name']} / {r['username']}")
                        st.warning("반려 처리되었습니다.")
                        st.rerun()


# -----------------------------
# 페이지: 방문신청
# -----------------------------
def page_visit_request():
    user = st.session_state["user"]
    st.subheader("방문 사전신청 등록")
    st.caption("승인된 부서 사용자만 방문신청을 등록할 수 있습니다.")

    with st.form("visit_request_form", clear_on_submit=True):
        c1, c2 = st.columns(2)
        with c1:
            visit_date = st.date_input("방문일자 *", value=date.today())
            visit_time = st.time_input("방문시간 *")
            visitor_name = st.text_input("방문자명 *")
            visitor_org = st.text_input("방문자 소속")
            visitor_phone = st.text_input("연락처")
        with c2:
            target_department = st.selectbox("방문부서 *", DEPARTMENTS, index=DEPARTMENTS.index(user["department"]) if user["department"] in DEPARTMENTS else 0)
            vehicle_no = st.text_input("차량번호")
            purpose = st.text_area("방문목적 *", height=120)
            request_note = st.text_area("요청사항", height=120)
        submitted = st.form_submit_button("방문신청 등록", use_container_width=True)

    if submitted:
        if not visitor_name.strip() or not purpose.strip():
            st.error("방문자명과 방문목적은 필수입니다.")
        else:
            execute("""
            INSERT INTO visits
            (request_user, request_name, request_department, visit_date, visit_time,
             visitor_name, visitor_org, visitor_phone, vehicle_no, target_department,
             purpose, request_note, status, entry_status, created_at, updated_at)
            VALUES
            (:request_user, :request_name, :request_department, :visit_date, :visit_time,
             :visitor_name, :visitor_org, :visitor_phone, :vehicle_no, :target_department,
             :purpose, :request_note, 'pending', 'waiting', :created_at, :updated_at)
            """, {
                "request_user": user["username"],
                "request_name": user["name"],
                "request_department": user["department"],
                "visit_date": visit_date.isoformat(),
                "visit_time": visit_time.strftime("%H:%M"),
                "visitor_name": visitor_name.strip(),
                "visitor_org": visitor_org.strip(),
                "visitor_phone": visitor_phone.strip(),
                "vehicle_no": vehicle_no.strip(),
                "target_department": target_department,
                "purpose": purpose.strip(),
                "request_note": request_note.strip(),
                "created_at": now_str(),
                "updated_at": now_str(),
            })
            add_event("visit_request", "신규 방문신청", f"{user['department']} / {visitor_name} / {visit_date.isoformat()}")
            st.success("방문신청이 등록되었습니다. 관리자 승인 후 모니터링 화면에 표시됩니다.")


def page_my_visits():
    user = st.session_state["user"]
    st.subheader("내 방문신청 현황")
    rows = fetch_all("""
    SELECT id, created_at, visit_date, visit_time, visitor_name, visitor_org,
           target_department, purpose, status, entry_status, admin_memo,
           approved_at, entered_at, exited_at
    FROM visits
    WHERE request_user=:u
    ORDER BY id DESC
    """, {"u": user["username"]})
    if rows:
        df = pd.DataFrame(rows)
        df["status"] = df["status"].map(lambda x: STATUS_LABELS.get(x, x))
        df["entry_status"] = df["entry_status"].map(lambda x: ENTRY_LABELS.get(x, x))
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("내가 등록한 방문신청이 없습니다.")


# -----------------------------
# 페이지: 관리자 방문승인
# -----------------------------
def page_visit_approval():
    st.subheader("방문신청 승인/반려")
    admin_notification()

    status_filter = st.selectbox("상태 필터", ["pending", "approved", "rejected", "all"], format_func=lambda x: "전체" if x=="all" else STATUS_LABELS.get(x, x))
    if status_filter == "all":
        rows = fetch_all("SELECT * FROM visits ORDER BY id DESC LIMIT 200")
    else:
        rows = fetch_all("SELECT * FROM visits WHERE status=:s ORDER BY id DESC LIMIT 200", {"s": status_filter})

    if not rows:
        st.info("조회된 방문신청이 없습니다.")
        return

    for r in rows:
        title = f"[{STATUS_LABELS.get(r['status'], r['status'])}] {r['visit_date']} {r['visit_time']} · {r['visitor_name']} · {r['target_department']}"
        with st.expander(title, expanded=(r["status"]=="pending")):
            c1, c2, c3 = st.columns(3)
            c1.write(f"신청부서: {r['request_department']}")
            c1.write(f"신청자: {r['request_name']} ({r['request_user']})")
            c2.write(f"방문자 소속: {r.get('visitor_org') or '-'}")
            c2.write(f"연락처: {r.get('visitor_phone') or '-'}")
            c3.write(f"차량번호: {r.get('vehicle_no') or '-'}")
            c3.write(f"출입상태: {ENTRY_LABELS.get(r['entry_status'], r['entry_status'])}")
            st.markdown("**방문목적**")
            st.info(r["purpose"])
            if r.get("request_note"):
                st.markdown("**요청사항**")
                st.warning(r["request_note"])

            memo_key = f"memo_{r['id']}"
            admin_memo = st.text_area("관리자 메모", value=r.get("admin_memo") or "", key=memo_key)

            if r["status"] == "pending":
                c1, c2 = st.columns(2)
                with c1:
                    if st.button("방문 승인", key=f"approve_visit_{r['id']}", use_container_width=True):
                        execute("""
                        UPDATE visits SET status='approved', admin_memo=:memo,
                            approved_at=:t, approved_by=:by, updated_at=:t
                        WHERE id=:id
                        """, {"memo": admin_memo, "t": now_str(), "by": st.session_state["user"]["username"], "id": r["id"]})
                        add_event("visit_approved", "방문신청 승인", f"{r['visitor_name']} / {r['visit_date']} {r['visit_time']}")
                        st.success("승인되었습니다.")
                        st.rerun()
                with c2:
                    if st.button("방문 반려", key=f"reject_visit_{r['id']}", use_container_width=True):
                        execute("""
                        UPDATE visits SET status='rejected', admin_memo=:memo,
                            rejected_at=:t, rejected_by=:by, updated_at=:t
                        WHERE id=:id
                        """, {"memo": admin_memo, "t": now_str(), "by": st.session_state["user"]["username"], "id": r["id"]})
                        add_event("visit_rejected", "방문신청 반려", f"{r['visitor_name']} / {r['visit_date']} {r['visit_time']}")
                        st.warning("반려 처리되었습니다.")
                        st.rerun()


# -----------------------------
# 페이지: 모니터링
# -----------------------------
def page_monitor():
    header()
    st.subheader("초소·안내데스크 모니터링")

    if not st.session_state.get("monitor_ok"):
        c1, c2 = st.columns([1, 1])
        with c1:
            code = st.text_input("모니터링 접속 코드", type="password")
            location = st.selectbox("근무 위치", MONITOR_LOCATIONS)
            if st.button("모니터링 접속", use_container_width=True):
                if code == MONITOR_CODE:
                    st.session_state["monitor_ok"] = True
                    st.session_state["monitor_location"] = location
                    st.rerun()
                else:
                    st.error("모니터링 코드가 올바르지 않습니다.")
        with c2:
            st.markdown("""
            <div class="kw-card">
            <b>모니터링 화면 용도</b><br>
            승인된 방문자를 조회하고 입문/퇴문 처리를 합니다.<br>
            기본 접속 코드는 <b>monitor1234</b>입니다. 운영 전 반드시 변경하세요.
            </div>
            """, unsafe_allow_html=True)
        return

    location = st.session_state.get("monitor_location", MONITOR_LOCATIONS[0])
    st.success(f"{location} 모니터링 접속 중")
    if st.button("모니터링 접속 해제"):
        st.session_state.pop("monitor_ok", None)
        st.session_state.pop("monitor_location", None)
        st.rerun()

    enable_auto_refresh()

    filter_date = st.date_input("조회일자", value=date.today())
    keyword = st.text_input("검색어", placeholder="방문자명, 소속, 부서, 차량번호 등")

    sql = """
    SELECT * FROM visits
    WHERE status='approved' AND visit_date=:d
    """
    params = {"d": filter_date.isoformat()}
    if keyword.strip():
        sql += """
        AND (
          visitor_name LIKE :kw OR visitor_org LIKE :kw OR target_department LIKE :kw
          OR vehicle_no LIKE :kw OR request_department LIKE :kw
        )
        """
        params["kw"] = f"%{keyword.strip()}%"
    sql += " ORDER BY visit_time ASC, id DESC"
    rows = fetch_all(sql, params)

    if not rows:
        st.info("조회된 승인 방문자가 없습니다.")
        return

    for r in rows:
        badge = ENTRY_LABELS.get(r["entry_status"], r["entry_status"])
        with st.container(border=True):
            c1, c2, c3, c4 = st.columns([1.2, 1.2, 1.2, 1])
            c1.markdown(f"### {r['visitor_name']}")
            c1.caption(f"{r.get('visitor_org') or '-'} / {r.get('visitor_phone') or '-'}")
            c2.write(f"방문시간: **{r['visit_time']}**")
            c2.write(f"방문부서: **{r['target_department']}**")
            c3.write(f"차량번호: **{r.get('vehicle_no') or '-'}**")
            c3.write(f"상태: **{badge}**")
            c4.write(f"신청부서: {r['request_department']}")
            c4.write(f"신청자: {r['request_name']}")
            st.info(r["purpose"])
            if r.get("request_note"):
                st.warning(f"요청사항: {r['request_note']}")
            if r.get("admin_memo"):
                st.caption(f"관리자 메모: {r['admin_memo']}")

            b1, b2 = st.columns(2)
            with b1:
                if r["entry_status"] == "waiting":
                    if st.button("입문 처리", key=f"enter_{r['id']}", use_container_width=True):
                        execute("""
                        UPDATE visits SET entry_status='entered', entered_at=:t, entered_by=:by,
                            entry_location=:loc, updated_at=:t
                        WHERE id=:id
                        """, {"t": now_str(), "by": location, "loc": location, "id": r["id"]})
                        add_event("entry", "입문 처리", f"{r['visitor_name']} / {location}")
                        st.success("입문 처리되었습니다.")
                        st.rerun()
                elif r["entry_status"] == "entered":
                    st.success(f"입문완료: {r.get('entered_at') or '-'} / {r.get('entry_location') or '-'}")
                else:
                    st.info(f"입문: {r.get('entered_at') or '-'} / 퇴문: {r.get('exited_at') or '-'}")
            with b2:
                if r["entry_status"] == "entered":
                    if st.button("퇴문 처리", key=f"exit_{r['id']}", use_container_width=True):
                        execute("""
                        UPDATE visits SET entry_status='exited', exited_at=:t, exited_by=:by,
                            exit_location=:loc, updated_at=:t
                        WHERE id=:id
                        """, {"t": now_str(), "by": location, "loc": location, "id": r["id"]})
                        add_event("exit", "퇴문 처리", f"{r['visitor_name']} / {location}")
                        st.success("퇴문 처리되었습니다.")
                        st.rerun()
                elif r["entry_status"] == "exited":
                    st.success(f"퇴문완료: {r.get('exited_at') or '-'} / {r.get('exit_location') or '-'}")


# -----------------------------
# 페이지: 데이터 관리
# -----------------------------
def page_data_admin():
    st.subheader("데이터 백업/조회")
    admin_notification()

    tab1, tab2, tab3 = st.tabs(["방문신청 데이터", "사용자 데이터", "이벤트 로그"])

    with tab1:
        rows = fetch_all("SELECT * FROM visits ORDER BY id DESC")
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
        if not df.empty:
            st.download_button(
                "방문신청 CSV 다운로드",
                data=df.to_csv(index=False).encode("utf-8-sig"),
                file_name=f"visits_backup_{date.today().isoformat()}.csv",
                mime="text/csv",
                use_container_width=True,
            )

    with tab2:
        rows = fetch_all("""
        SELECT id, username, name, department, role, status, requested_reason,
               created_at, approved_at, approved_by, last_login_at
        FROM users ORDER BY id DESC
        """)
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
        if not df.empty:
            st.download_button(
                "사용자 CSV 다운로드",
                data=df.to_csv(index=False).encode("utf-8-sig"),
                file_name=f"users_backup_{date.today().isoformat()}.csv",
                mime="text/csv",
                use_container_width=True,
            )

    with tab3:
        rows = fetch_all("SELECT * FROM events ORDER BY id DESC LIMIT 500")
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
        if not df.empty:
            st.download_button(
                "이벤트 로그 CSV 다운로드",
                data=df.to_csv(index=False).encode("utf-8-sig"),
                file_name=f"events_backup_{date.today().isoformat()}.csv",
                mime="text/csv",
                use_container_width=True,
            )


# -----------------------------
# 메인 라우터
# -----------------------------
def main():
    init_db()
    sidebar_login_status()

    with st.sidebar:
        st.markdown("---")
        st.markdown("### 메뉴")
        user = require_login()

        if user:
            if is_admin(user):
                menu = st.radio(
                    "관리자 메뉴",
                    ["대시보드", "계정승인", "방문승인", "모니터링", "데이터관리"],
                    label_visibility="collapsed",
                )
            else:
                menu = st.radio(
                    "사용자 메뉴",
                    ["방문신청", "내 신청현황", "모니터링"],
                    label_visibility="collapsed",
                )
        else:
            menu = st.radio(
                "접속 메뉴",
                ["로그인/계정신청", "모니터링"],
                label_visibility="collapsed",
            )

        st.markdown("---")
        st.caption("서버 운영 시 .env에서 MONITOR_CODE, DATABASE_URL, 관리자 비밀번호 정책을 변경하세요.")

    # 비로그인 모니터링은 별도 가능
    if menu == "모니터링":
        page_monitor()
        return

    user = require_login()
    if not user:
        page_login()
        return

    if is_admin(user):
        if menu == "대시보드":
            page_dashboard()
        elif menu == "계정승인":
            page_user_approval()
        elif menu == "방문승인":
            page_visit_approval()
        elif menu == "데이터관리":
            page_data_admin()
    else:
        header()
        if menu == "방문신청":
            page_visit_request()
        elif menu == "내 신청현황":
            page_my_visits()


if __name__ == "__main__":
    main()
