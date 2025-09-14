from __future__ import annotations
import os, io, csv
from datetime import datetime, timedelta, date
from zoneinfo import ZoneInfo

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, g, request, session, redirect, url_for, render_template_string, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import holidays  # python-holidays

# -------------------- Config --------------------
APP_TZ = ZoneInfo("Europe/Berlin")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
DATABASE_URL = os.getenv("DATABASE_URL")  # postgres://...
STATE_DEFAULT = os.getenv("STATE_DEFAULT", "BY")  # 기본 바이에른

app = Flask(__name__)
app.secret_key = SECRET_KEY

# -------------------- DB helpers --------------------
def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL)
    return g.db

def dict_cur(db):
    return db.cursor(cursor_factory=RealDictCursor)

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    db = get_db()
    cur = db.cursor()
    # users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id VARCHAR(64) PRIMARY KEY,
      password VARCHAR(255) NOT NULL,
      role VARCHAR(10) DEFAULT 'user'
    );
    """)
    # attendance
    cur.execute("""
    CREATE TABLE IF NOT EXISTS attendance (
      record_id SERIAL PRIMARY KEY,
      user_id VARCHAR(64),
      date DATE,
      clock_in_time TIME,
      clock_out_time TIME,
      tardiness_reason TEXT,
      early_leave_reason TEXT,
      overtime_details TEXT,
      CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)
    # vacations
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vacations (
      id SERIAL PRIMARY KEY,
      user_id VARCHAR(64) NOT NULL,
      start_date DATE NOT NULL,
      end_date DATE NOT NULL,
      type VARCHAR(10) NOT NULL, -- annual,sick,half_am,half_pm,unpaid
      reason TEXT,
      status VARCHAR(10) DEFAULT 'pending', -- pending,approved,rejected
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_user_v FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)
    # holidays
    cur.execute("""
    CREATE TABLE IF NOT EXISTS holidays (
      day DATE PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      state_code CHAR(2),
      is_company_off BOOLEAN DEFAULT FALSE
    );
    """)
    db.commit()
    # seed accounts
    c2 = dict_cur(db)
    c2.execute("SELECT 1 FROM users WHERE id=%s", ("admin",))
    if not c2.fetchone():
        c2.execute("INSERT INTO users(id,password,role) VALUES(%s,%s,'admin')",
                   ("admin", generate_password_hash("admin1234")))
    c2.execute("SELECT 1 FROM users WHERE id=%s", ("testuser",))
    if not c2.fetchone():
        c2.execute("INSERT INTO users(id,password,role) VALUES(%s,%s,'user')",
                   ("testuser", generate_password_hash("1234")))
    db.commit()

with app.app_context():
    init_db()

# -------------------- Template base --------------------
BASE = """
<!doctype html><html lang="ko"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<title>{{ title or '출퇴근' }}</title>
<style>body{padding:2rem}.container{max-width:1000px}</style>
</head><body><div class="container">
<nav class="mb-3 d-flex justify-content-between">
  <div>
    {% if session.get('user_id') %}
      <a class="me-2" href="{{ url_for('dashboard') }}">대시보드</a>
      <a class="me-2" href="{{ url_for('history') }}">내 기록</a>
      <a class="me-2" href="{{ url_for('weekly_report') }}">주간리포트</a>
      {% if session.get('role')=='admin' %}
        <a class="me-2" href="{{ url_for('admin') }}">관리자</a>
        <a class="me-2" href="{{ url_for('admin_list_holidays') }}">공휴일관리</a>
      {% endif %}
    {% endif %}
  </div>
  <div>
    {% if session.get('user_id') %}
      <span class="me-2">{{ session.get('user_id') }}님</span>
      <a class="btn btn-sm btn-outline-danger" href="{{ url_for('logout') }}">로그아웃</a>
    {% endif %}
  </div>
</nav>
{% with m=get_flashed_messages(with_categories=true) %}
  {% if m %}{% for cat,msg in m %}
    <div class="alert alert-{{ 'warning' if cat=='error' else cat }}">{{ msg }}</div>
  {% endfor %}{% endif %}
{% endwith %}
{{ body|safe }}
</div></body></html>
"""

# -------------------- Helpers --------------------
def require_login():
    if "user_id" not in session:
        return redirect(url_for("root"))

def admin_required():
    if (r := require_login()): return r
    if session.get("role") != "admin":
        flash("관리자만 접근 가능합니다.", "error")
        return redirect(url_for("dashboard"))

def now_berlin():
    return datetime.now(tz=APP_TZ)

def daterange(d1: date, d2: date):
    cur = d1
    while cur <= d2:
        yield cur
        cur += timedelta(days=1)

# -------------------- Auth --------------------
@app.route("/")
def root():
    if "user_id" in session: return redirect(url_for("dashboard"))
    body = """
      <div class="card"><div class="card-body">
        <h3 class="mb-3">로그인</h3>
        <form method="post" action="{{ url_for('login') }}" class="row g-3">
          <div class="col-md-6"><label class="form-label">아이디</label><input name="user_id" class="form-control" required></div>
          <div class="col-md-6"><label class="form-label">비밀번호</label><input type="password" name="password" class="form-control" required></div>
          <div class="col-12"><button class="btn btn-primary">로그인</button></div>
        </form>
      </div></div>
    """
    return render_template_string(BASE, title="로그인", body=body)

@app.route("/login", methods=["POST"])
def login():
    user_id = request.form.get("user_id","").strip()
    pw = request.form.get("password","")
    db = get_db()
    c = dict_cur(db)
    c.execute("SELECT id,password,role FROM users WHERE id=%s", (user_id,))
    row = c.fetchone()
    if row and check_password_hash(row["password"], pw):
        session["user_id"] = row["id"]; session["role"] = row["role"]
        flash("로그인 성공", "success")
        return redirect(url_for("dashboard"))
    flash("아이디 또는 비밀번호가 올바르지 않습니다.", "error")
    return redirect(url_for("root"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("root"))

# -------------------- Attendance --------------------
@app.route("/dashboard")
def dashboard():
    if (r := require_login()): return r
    user = session["user_id"]
    now = now_berlin()
    today = now.date()
    db = get_db(); c = dict_cur(db)
    c.execute("""
      SELECT record_id, clock_in_time, clock_out_time
      FROM attendance WHERE user_id=%s AND date=%s
      ORDER BY record_id DESC LIMIT 1
    """, (user, today))
    rec = c.fetchone()
    working = rec and rec["clock_in_time"] and not rec["clock_out_time"]
    body = render_template_string("""
      <div class="d-flex justify-content-between">
        <h3>대시보드</h3><span class="badge text-bg-secondary">{{ today }}</span>
      </div>
      {% if not working %}
        <div class="alert alert-info mt-2">출근 전입니다.</div>
        <form method="post" action="{{ url_for('clock_in') }}"><button class="btn btn-success btn-lg">출근</button></form>
      {% else %}
        <div class="alert alert-success mt-2">업무 중... (출근: {{ rec.clock_in_time }})</div>
        <form method="post" action="{{ url_for('clock_out') }}"><button class="btn btn-danger btn-lg">퇴근</button></form>
      {% endif %}
    """, today=today, working=working, rec=rec)
    return render_template_string(BASE, title="대시보드", body=body)

@app.route("/clock-in", methods=["POST"])
def clock_in():
    if (r := require_login()): return r
    user = session["user_id"]
    now = now_berlin()
    today, time_str = now.date(), now.strftime("%H:%M:%S")
    if now.hour >= 8:
        session["pending_ci"] = {"date": str(today), "time": time_str}
        return redirect(url_for("tardiness"))
    db = get_db(); c = db.cursor()
    c.execute("""
      INSERT INTO attendance(user_id,date,clock_in_time)
      VALUES (%s,%s,%s)
    """, (user, today, time_str))
    db.commit()
    flash(f"출근 시간: {today} {time_str}", "success")
    return redirect(url_for("dashboard"))

@app.route("/tardiness", methods=["GET","POST"])
def tardiness():
    if (r := require_login()): return r
    pending = session.get("pending_ci")
    if not pending: return redirect(url_for("dashboard"))
    if request.method == "POST":
        reason = request.form.get("reason","").strip()
        if not reason:
            flash("지각 사유를 입력해주세요.","error"); return redirect(url_for("tardiness"))
        user = session["user_id"]; db = get_db(); c = db.cursor()
        c.execute("""
          INSERT INTO attendance(user_id,date,clock_in_time,tardiness_reason)
          VALUES (%s,%s,%s,%s)
        """, (user, pending["date"], pending["time"], reason))
        db.commit(); session.pop("pending_ci", None)
        flash("지각 사유와 함께 출근 기록 완료", "success")
        return redirect(url_for("dashboard"))
    body = """
      <h3>지각 사유 입력</h3>
      <form method="post" class="mt-3">
        <textarea class="form-control" name="reason" rows="3" required></textarea><br>
        <button class="btn btn-primary">저장</button>
      </form>
    """
    return render_template_string(BASE, title="지각 사유", body=body)

@app.route("/clock-out", methods=["POST"])
def clock_out():
    if (r := require_login()): return r
    user = session["user_id"]
    now = now_berlin()
    today, time_str = now.date(), now.strftime("%H:%M:%S")
    db = get_db(); c = dict_cur(db)
    c.execute("""
      SELECT record_id, clock_in_time
      FROM attendance
      WHERE user_id=%s AND date=%s AND clock_out_time IS NULL
      ORDER BY record_id DESC LIMIT 1
    """, (user, today))
    rec = c.fetchone()
    if not rec:
        flash("출근 기록이 없습니다.", "error")
        return redirect(url_for("dashboard"))
    clock_in_dt = datetime.strptime(f"{today} {rec['clock_in_time']}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=APP_TZ)
    scheduled_end = clock_in_dt.replace(hour=17, minute=0, second=0)
    overtime_start = scheduled_end + timedelta(hours=1)
    if now < scheduled_end:
        session["pending_co"] = {"rid": rec["record_id"], "time": time_str, "need":"early"}
        return redirect(url_for("early_leave"))
    if now >= overtime_start:
        session["pending_co"] = {"rid": rec["record_id"], "time": time_str, "need":"overtime"}
        return redirect(url_for("overtime"))
    c2 = db.cursor()
    c2.execute("UPDATE attendance SET clock_out_time=%s WHERE record_id=%s", (time_str, rec["record_id"]))
    db.commit()
    flash("퇴근 기록 완료", "success")
    return redirect(url_for("dashboard"))

@app.route("/early-leave", methods=["GET","POST"])
def early_leave():
    if (r := require_login()): return r
    p = session.get("pending_co")
    if not p or p["need"]!="early": return redirect(url_for("dashboard"))
    if request.method=="POST":
        reason = request.form.get("reason","").strip()
        if not reason:
            flash("조퇴 사유를 입력해주세요.","error"); return redirect(url_for("early_leave"))
        db = get_db(); c = db.cursor()
        c.execute("""
          UPDATE attendance SET clock_out_time=%s, early_leave_reason=%s
          WHERE record_id=%s
        """, (p["time"], reason, p["rid"]))
        db.commit(); session.pop("pending_co",None)
        flash("조퇴 사유와 함께 퇴근 기록 완료","success")
        return redirect(url_for("dashboard"))
    body = """
      <h3>조퇴 사유 입력</h3>
      <form method="post" class="mt-3">
        <textarea class="form-control" name="reason" rows="3" required></textarea><br>
        <button class="btn btn-primary">저장</button>
      </form>
    """
    return render_template_string(BASE, title="조퇴 사유", body=body)

@app.route("/overtime", methods=["GET","POST"])
def overtime():
    if (r := require_login()): return r
    p = session.get("pending_co")
    if not p or p["need"]!="overtime": return redirect(url_for("dashboard"))
    if request.method=="POST":
        details = request.form.get("details","").strip()
        if not details:
            flash("야근 업무 내용을 입력해주세요.","error"); return redirect(url_for("overtime"))
        db = get_db(); c = db.cursor()
        c.execute("""
          UPDATE attendance SET clock_out_time=%s, overtime_details=%s
          WHERE record_id=%s
        """, (p["time"], details, p["rid"]))
        db.commit(); session.pop("pending_co",None)
        flash("야근 내용과 함께 퇴근 기록 완료","success")
        return redirect(url_for("dashboard"))
    body = """
      <h3>야근 내용 입력</h3>
      <form method="post" class="mt-3">
        <textarea class="form-control" name="details" rows="4" required></textarea><br>
        <button class="btn btn-primary">저장</button>
      </form>
    """
    return render_template_string(BASE, title="야근 내용", body=body)

@app.route("/history")
def history():
    if (r := require_login()): return r
    db = get_db(); c = dict_cur(db)
    c.execute("""
      SELECT date, clock_in_time, clock_out_time,
             tardiness_reason, early_leave_reason, overtime_details
      FROM attendance WHERE user_id=%s ORDER BY date DESC
    """, (session["user_id"],))
    rows = c.fetchall()
    body = render_template_string("""
      <h3 class="mb-3">내 기록</h3>
      <div class="table-responsive"><table class="table table-sm table-striped">
        <thead><tr><th>날짜</th><th>출근</th><th>퇴근</th><th>지각</th><th>조퇴</th><th>야근</th></tr></thead>
        <tbody>
        {% for r in rows %}
          <tr>
            <td>{{ r.date }}</td><td>{{ r.clock_in_time or '' }}</td><td>{{ r.clock_out_time or '' }}</td>
            <td>{{ r.tardiness_reason or '' }}</td><td>{{ r.early_leave_reason or '' }}</td><td>{{ r.overtime_details or '' }}</td>
          </tr>
        {% endfor %}
        </tbody></table></div>
    """, rows=rows)
    return render_template_string(BASE, title="내 기록", body=body)

# -------------------- Admin (users/attendance/CSV) --------------------
@app.route("/admin")
def admin():
    if (r := admin_required()): return r
    q_id = request.args.get("q_id","").strip()
    q_date = request.args.get("q_date","").strip()
    db = get_db(); c = dict_cur(db)
    sql = """
      SELECT user_id,date,clock_in_time,clock_out_time,
             tardiness_reason,early_leave_reason,overtime_details
      FROM attendance
    """
    cond, params = [], []
    if q_id: cond.append("user_id ILIKE %s"); params.append(f"%{q_id}%")
    if q_date: cond.append("date=%s"); params.append(q_date)
    if cond: sql += " WHERE " + " AND ".join(cond)
    sql += " ORDER BY date DESC, user_id"
    c.execute(sql, params); att = c.fetchall()
    c.execute("SELECT id,role FROM users ORDER BY role,id"); users = c.fetchall()

    body = render_template_string("""
      <div class="d-flex justify-content-between mb-2">
        <h3>관리자</h3>
        <div class="d-flex gap-2">
          <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('export_csv', q_id=q_id, q_date=q_date) }}">CSV 내보내기</a>
          <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('admin_list_holidays') }}">공휴일 관리</a>
        </div>
      </div>
      <form class="row g-2 mb-3" method="get">
        <div class="col-md-4"><input class="form-control" name="q_id" placeholder="아이디" value="{{ q_id }}"></div>
        <div class="col-md-4"><input class="form-control" name="q_date" placeholder="YYYY-MM-DD" value="{{ q_date }}"></div>
        <div class="col-md-4"><button class="btn btn-primary w-100">검색</button></div>
      </form>
      <div class="table-responsive mb-4"><table class="table table-sm table-striped">
        <thead><tr><th>사용자</th><th>날짜</th><th>출근</th><th>퇴근</th><th>지각</th><th>조퇴</th><th>야근</th></tr></thead>
        <tbody>
          {% for r in att %}
          <tr>
            <td>{{ r.user_id }}</td><td>{{ r.date }}</td><td>{{ r.clock_in_time or '' }}</td>
            <td>{{ r.clock_out_time or '' }}</td><td>{{ r.tardiness_reason or '' }}</td>
            <td>{{ r.early_leave_reason or '' }}</td><td>{{ r.overtime_details or '' }}</td>
          </tr>{% endfor %}
        </tbody></table></div>
      <h5>사용자 관리</h5>
      <div class="row g-3">
        <form class="col-md-6" method="post" action="{{ url_for('register_user') }}">
          <input class="form-control mb-2" name="new_id" placeholder="신규 아이디" required>
          <input type="password" class="form-control mb-2" name="new_pw" placeholder="신규 비밀번호" required>
          <button class="btn btn-success">신규 사용자 등록</button>
        </form>
        <form class="col-md-6" method="post" action="{{ url_for('change_password') }}">
          <select class="form-select mb-2" name="user_id">
            {% for u in users %}<option value="{{u.id}}">{{u.id}} ({{u.role}})</option>{% endfor %}
          </select>
          <input type="password" class="form-control mb-2" name="new_pw" placeholder="새 비밀번호" required>
          <button class="btn btn-warning">비밀번호 변경</button>
        </form>
      </div>
      <form class="mt-3" method="post" action="{{ url_for('delete_user') }}" onsubmit="return confirm('삭제 시 해당 사용자의 모든 기록도 삭제됩니다. 계속할까요?')">
        <select class="form-select mb-2" name="user_id">
          {% for u in users if u.role!='admin' %}<option value="{{u.id}}">{{u.id}} ({{u.role}})</option>{% endfor %}
        </select>
        <button class="btn btn-danger">선택 사용자 삭제</button>
      </form>
    """, att=att, users=users, q_id=q_id, q_date=q_date)
    return render_template_string(BASE, title="관리자", body=body)

@app.route("/admin/register", methods=["POST"])
def register_user():
    if (r := admin_required()): return r
    nid = request.form.get("new_id","").strip()
    npw = request.form.get("new_pw","")
    if not nid or not npw:
        flash("아이디/비밀번호를 입력하세요.","error"); return redirect(url_for("admin"))
    db = get_db(); c = dict_cur(db)
    c.execute("SELECT 1 FROM users WHERE id=%s",(nid,))
    if c.fetchone():
        flash("이미 존재하는 아이디입니다.","error"); return redirect(url_for("admin"))
    c2 = db.cursor()
    c2.execute("INSERT INTO users(id,password,role) VALUES(%s,%s,'user')",
               (nid, generate_password_hash(npw)))
    db.commit(); flash(f"사용자 '{nid}' 등록 완료","success")
    return redirect(url_for("admin"))

@app.route("/admin/change-password", methods=["POST"])
def change_password():
    if (r := admin_required()): return r
    uid = request.form.get("user_id","").strip()
    npw = request.form.get("new_pw","")
    if not uid or not npw:
        flash("대상/비밀번호를 입력하세요.","error"); return redirect(url_for("admin"))
    db = get_db(); c = db.cursor()
    c.execute("UPDATE users SET password=%s WHERE id=%s",
              (generate_password_hash(npw), uid))
    db.commit(); flash("비밀번호 변경 완료","success")
    return redirect(url_for("admin"))

@app.route("/admin/delete", methods=["POST"])
def delete_user():
    if (r := admin_required()): return r
    uid = request.form.get("user_id","").strip()
    if uid=="admin":
        flash("admin 계정은 삭제할 수 없습니다.","error"); return redirect(url_for("admin"))
    db = get_db(); c = db.cursor()
    c.execute("DELETE FROM users WHERE id=%s",(uid,))
    db.commit(); flash(f"'{uid}' 삭제 완료","success")
    return redirect(url_for("admin"))

@app.route("/admin/export")
def export_csv():
    if (r := admin_required()): return r
    q_id = request.args.get("q_id","").strip()
    q_date = request.args.get("q_date","").strip()
    sql = """
      SELECT user_id,date,clock_in_time,clock_out_time,
             tardiness_reason,early_leave_reason,overtime_details
      FROM attendance
    """
    cond, params = [], []
    if q_id: cond.append("user_id ILIKE %s"); params.append(f"%{q_id}%")
    if q_date: cond.append("date=%s"); params.append(q_date)
    if cond: sql += " WHERE " + " AND ".join(cond)
    sql += " ORDER BY date DESC, user_id"
    db = get_db(); c = dict_cur(db)
    c.execute(sql, params); rows = c.fetchall()
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["사용자","날짜","출근","퇴근","지각 사유","조퇴 사유","야근 내용"])
    for r in rows:
        w.writerow([r["user_id"], r["date"], r["clock_in_time"], r["clock_out_time"],
                    r["tardiness_reason"] or "", r["early_leave_reason"] or "", r["overtime_details"] or ""])
    buf.seek(0)
    return send_file(io.BytesIO(buf.getvalue().encode("utf-8-sig")),
                     mimetype="text/csv", as_attachment=True, download_name="attendance.csv")

# -------------------- Holidays (admin) --------------------
def populate_holidays(year: int, state_code: str = STATE_DEFAULT) -> int:
    db = get_db(); cur = db.cursor()
    added = 0
    de_all = holidays.Germany(years=year)               # 전국
    de_state = holidays.Germany(years=year, prov=state_code)  # 주(州)
    for d, name in de_all.items():
        cur.execute("""
          INSERT INTO holidays(day,name,state_code,is_company_off)
          VALUES (%s,%s,%s,false)
          ON CONFLICT (day) DO NOTHING
        """, (d, name, None))
        added += cur.rowcount
    for d, name in de_state.items():
        cur.execute("""
          INSERT INTO holidays(day,name,state_code,is_company_off)
          VALUES (%s,%s,%s,false)
          ON CONFLICT (day) DO NOTHING
        """, (d, name, state_code))
        added += cur.rowcount
    db.commit()
    return added

@app.route("/admin/holidays")
def admin_list_holidays():
    if (r := admin_required()): return r
    year = request.args.get("year")
    state = request.args.get("state", STATE_DEFAULT)
    db = get_db(); c = dict_cur(db)
    if year:
        c.execute("SELECT day,name,state_code,is_company_off FROM holidays WHERE EXTRACT(YEAR FROM day)=%s ORDER BY day", (int(year),))
    else:
        c.execute("SELECT day,name,state_code,is_company_off FROM holidays ORDER BY day")
    rows = c.fetchall()
    body = render_template_string("""
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h3 class="mb-0">공휴일 관리</h3>
        <a class="btn btn-secondary btn-sm" href="{{ url_for('admin') }}">← 관리자 홈</a>
      </div>
      <form class="row g-2 mb-3" method="get">
        <div class="col-auto"><input class="form-control" name="year" placeholder="연도(예: 2025)" value="{{ request.args.get('year','') }}"></div>
        <div class="col-auto"><input class="form-control" name="state" placeholder="주(예: BY)" value="{{ request.args.get('state', state) }}"></div>
        <div class="col-auto"><button class="btn btn-outline-primary">필터</button></div>
      </form>
      <div class="card mb-4"><div class="card-body">
        <h5 class="card-title">연도별 공휴일 자동 채우기</h5>
        <form class="row g-2" method="post" action="{{ url_for('admin_populate_holidays') }}">
          <div class="col-auto"><input class="form-control" name="year" required placeholder="연도(예: 2025)"></div>
          <div class="col-auto"><input class="form-control" name="state" value="{{ state }}" placeholder="주(예: BY)"></div>
          <div class="col-auto"><button class="btn btn-success">채우기</button></div>
        </form>
      </div></div>
      <div class="card mb-4"><div class="card-body">
        <h5 class="card-title">수동 추가</h5>
        <form class="row g-2" method="post" action="{{ url_for('admin_add_holiday') }}">
          <div class="col-auto"><input type="date" name="day" class="form-control" required></div>
          <div class="col-auto"><input name="name" class="form-control" placeholder="공휴일명" required></div>
          <div class="col-auto"><input name="state" class="form-control" placeholder="주 코드 (전국이면 비움)"></div>
          <div class="col-auto form-check mt-2">
            <input class="form-check-input" type="checkbox" name="company_off" id="company_off">
            <label class="form-check-label" for="company_off">회사 휴무일</label>
          </div>
          <div class="col-auto"><button class="btn btn-primary">추가</button></div>
        </form>
      </div></div>
      <div class="table-responsive">
        <table class="table table-sm table-striped align-middle">
          <thead><tr><th>날짜</th><th>명칭</th><th>주(州)</th><th>회사휴무</th><th>작업</th></tr></thead>
          <tbody>
            {% for r in rows %}
            <tr>
              <td>{{ r.day }}</td>
              <td>{{ r.name }}</td>
              <td>{{ r.state_code or '전국' }}</td>
              <td>{% if r.is_company_off %}<span class="badge text-bg-success">Yes</span>{% else %}<span class="badge text-bg-secondary">No</span>{% endif %}</td>
              <td class="d-flex gap-2">
                <form method="post" action="{{ url_for('admin_toggle_company_off') }}"><input type="hidden" name="day" value="{{ r.day }}"><button class="btn btn-sm btn-outline-warning">회사휴무 토글</button></form>
                <form method="post" action="{{ url_for('admin_delete_holiday') }}" onsubmit="return confirm('삭제할까요?')"><input type="hidden" name="day" value="{{ r.day }}"><button class="btn btn-sm btn-outline-danger">삭제</button></form>
              </td>
            </tr>{% endfor %}
          </tbody>
        </table>
      </div>
    """, rows=rows, state=STATE_DEFAULT)
    return render_template_string(BASE, title="공휴일 관리", body=body)

@app.route("/admin/holidays/populate", methods=["POST"])
def admin_populate_holidays():
    if (r := admin_required()): return r
    year = int(request.form.get("year"))
    state = (request.form.get("state") or STATE_DEFAULT).upper()
    n = populate_holidays(year, state)
    flash(f"{year}년 {state} 공휴일 {n}건이 추가/유지되었습니다.", "success")
    return redirect(url_for("admin_list_holidays", year=year, state=state))

@app.route("/admin/holidays/add", methods=["POST"])
def admin_add_holiday():
    if (r := admin_required()): return r
    day = request.form.get("day"); name = request.form.get("name","").strip()
    state = (request.form.get("state") or None)
    company_off = True if request.form.get("company_off") else False
    if not day or not name:
        flash("날짜/명칭을 입력하세요.","error"); return redirect(url_for("admin_list_holidays"))
    db = get_db(); c = db.cursor()
    c.execute("""
      INSERT INTO holidays(day,name,state_code,is_company_off)
      VALUES (%s,%s,%s,%s)
      ON CONFLICT (day) DO NOTHING
    """, (day, name, state, company_off))
    db.commit(); flash("공휴일이 추가되었습니다.","success")
    return redirect(url_for("admin_list_holidays"))

@app.route("/admin/holidays/delete", methods=["POST"])
def admin_delete_holiday():
    if (r := admin_required()): return r
    day = request.form.get("day")
    db = get_db(); c = db.cursor()
    c.execute("DELETE FROM holidays WHERE day=%s", (day,))
    db.commit(); flash("삭제되었습니다.","success")
    return redirect(url_for("admin_list_holidays"))

@app.route("/admin/holidays/toggle", methods=["POST"])
def admin_toggle_company_off():
    if (r := admin_required()): return r
    day = request.form.get("day")
    db = get_db(); c = db.cursor()
    c.execute("UPDATE holidays SET is_company_off = NOT is_company_off WHERE day=%s", (day,))
    db.commit(); flash("회사 휴무 플래그가 변경되었습니다.","success")
    return redirect(url_for("admin_list_holidays"))

# -------------------- Working days & Weekly report --------------------
def get_holiday_set(d1: date, d2: date, state_code: str | None):
    db = get_db(); c = dict_cur(db)
    if state_code:
        c.execute("""
          SELECT day FROM holidays
          WHERE day BETWEEN %s AND %s AND (state_code IS NULL OR state_code=%s)
        """, (d1, d2, state_code))
    else:
        c.execute("SELECT day FROM holidays WHERE day BETWEEN %s AND %s", (d1, d2))
    rows = c.fetchall()
    # 회사 휴무 추가
    c.execute("SELECT day FROM holidays WHERE is_company_off=TRUE AND day BETWEEN %s AND %s", (d1, d2))
    rows += c.fetchall()
    return {r["day"] for r in rows}

def get_vacation_map(user_id: str, d1: date, d2: date):
    db = get_db(); c = dict_cur(db)
    c.execute("""
      SELECT start_date,end_date,type,status
      FROM vacations
      WHERE user_id=%s AND NOT (end_date < %s OR start_date > %s)
    """, (user_id, d1, d2))
    rows = c.fetchall()
    vac = {}
    for r in rows:
        if r["status"] != "approved": continue
        s, e, t = r["start_date"], r["end_date"], r["type"]
        for d in daterange(max(s,d1), min(e,d2)):
            if t in ("half_am","half_pm"):
                vac[d] = min(1.0, vac.get(d, 0.0) + 0.5)
            else:
                vac[d] = 1.0
    return vac

def business_days_between(d1: date, d2: date, user_id: str, state_code: str | None = STATE_DEFAULT):
    holidays_set = get_holiday_set(d1, d2, state_code)
    vac_map = get_vacation_map(user_id, d1, d2)
    total = 0.0
    for d in daterange(d1, d2):
        if d.weekday() >= 5:  # 토/일
            continue
        if d in holidays_set:
            continue
        total += max(0.0, 1.0 - vac_map.get(d, 0.0))
    return total

@app.route("/reports/weekly")
def weekly_report():
    if (r := require_login()): return r
    user = request.args.get("user", session["user_id"])
    state = request.args.get("state", STATE_DEFAULT)
    q_from = request.args.get("from")
    q_to = request.args.get("to")
    if not (q_from and q_to):
        # 기본: 이번 주 월~일
        today = now_berlin().date()
        start = today - timedelta(days=today.weekday())
        end = start + timedelta(days=6)
    else:
        start = datetime.strptime(q_from, "%Y-%m-%d").date()
        end = datetime.strptime(q_to, "%Y-%m-%d").date()

    working_days = business_days_between(start, end, user, state)

    # 총 근로시간
    db = get_db(); c = dict_cur(db)
    c.execute("""
      SELECT date, clock_in_time, clock_out_time
      FROM attendance WHERE user_id=%s AND date BETWEEN %s AND %s
    """, (user, start, end))
    rows = c.fetchall()
    total_secs = 0
    for r in rows:
        if r["clock_in_time"] and r["clock_out_time"]:
            t1 = datetime.strptime(f"{r['date']} {r['clock_in_time']}", "%Y-%m-%d %H:%M:%S")
            t2 = datetime.strptime(f"{r['date']} {r['clock_out_time']}", "%Y-%m-%d %H:%M:%S")
            total_secs += max(0, int((t2 - t1).total_seconds()))
    hh = total_secs // 3600; mm = (total_secs % 3600) // 60

    body = render_template_string("""
      <h3>주간 리포트</h3>
      <form class="row g-2 my-2" method="get">
        <div class="col-auto"><input type="date" class="form-control" name="from" value="{{ start }}"></div>
        <div class="col-auto"><input type="date" class="form-control" name="to" value="{{ end }}"></div>
        <div class="col-auto"><input class="form-control" name="user" value="{{ user }}"></div>
        <div class="col-auto"><input class="form-control" name="state" value="{{ state }}"></div>
        <div class="col-auto"><button class="btn btn-primary">조회</button></div>
      </form>
      <ul class="mt-3">
        <li><b>기간:</b> {{ start }} ~ {{ end }}</li>
        <li><b>사용자:</b> {{ user }}, <b>주(州):</b> {{ state }}</li>
        <li><b>근무일수(공휴일/주말/휴가 반영):</b> {{ '%.1f'|format(working_days) }} 일</li>
        <li><b>총 근로시간:</b> {{ hh }}시간 {{ mm }}분</li>
      </ul>
    """, start=start, end=end, user=user, state=state, working_days=working_days, hh=hh, mm=mm)
    return render_template_string(BASE, title="주간 리포트", body=body)

# -------------------- Main --------------------
if __name__ == "__main__":
    # 로컬 테스트용
    app.run(host="0.0.0.0", port=5000, debug=True)
