#!/usr/bin/env python3
"""
==============================================================================
File:        api_server.py
Component:   Linux Sentinel -- Forensic Workbench API
Description: A lightweight FastAPI application providing secure data access.
Role:        Serves as the backend for the local dashboard. Provides read-only
             queries against the SQLite telemetry database, handles JWT-based
             authentication, and hosts the static HTML/JS frontend assets.
Author:      Robert Weber
==============================================================================
"""

from fastapi import FastAPI, Query, HTTPException, Depends, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import sqlite3
import yaml
import os
import logging
import time
import requests
from pathlib import Path
from typing import Optional, List
from logging.handlers import RotatingFileHandler

app = FastAPI(title="Sentinel Forensic Workbench", version="0.2")

# ==========================================
# Logging & Alerting Architecture
# ==========================================
LOG_DIR = Path("/var/log/linux-sentinel/dashboard")
LOG_DIR.mkdir(parents=True, exist_ok=True)

log_formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(module)s:%(funcName)s:%(lineno)d | %(message)s')

file_handler = RotatingFileHandler(LOG_DIR / "api.log", maxBytes=5*1024*1024, backupCount=3)
file_handler.setFormatter(log_formatter)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

logger = logging.getLogger("sentinel_api")
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

ALERT_WEBHOOK_URL = os.getenv("SENTINEL_API_WEBHOOK", None)

def trigger_critical_alert(message: str, exc_info=None):
    logger.critical(message, exc_info=exc_info)
    if ALERT_WEBHOOK_URL:
        try:
            payload = {"text": f"**Sentinel Workbench API Fault**\n`{message}`"}
            requests.post(ALERT_WEBHOOK_URL, json=payload, timeout=2.0)
        except Exception as e:
            logger.error(f"Failed to dispatch webhook alert: {e}")

@app.middleware("http")
async def verbose_request_logging(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000

    if request.url.path.startswith("/api/"):
        logger.info(f"{request.client.host} - \"{request.method} {request.url.path}\" {response.status_code} [{process_time:.2f}ms]")

    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_msg = f"Unhandled Exception on {request.method} {request.url.path}: {str(exc)}"
    trigger_critical_alert(error_msg, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error. Administrators have been notified."})

# ==========================================
# Configuration Parser
# ==========================================
CONFIG_PATH = os.getenv("SENTINEL_UI_CONFIG", "/app/config.yaml")

def load_config():
    if not Path(CONFIG_PATH).exists():
        print(f"[!] WARNING: Config file not found at {CONFIG_PATH}. Using fallback defaults.")
        return {}
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

config = load_config()

DB_PATH = Path(config.get("database", {}).get("core_db_path", "/var/log/linux-sentinel/sentinel.db"))
print(f"[*] Forensic Workbench initialized. Target DB: {DB_PATH.absolute()}")

AUTH_DB_PATH = Path(config.get("database", {}).get("auth_db_path", "/app/data/auth.db"))

SECRET_KEY = config.get("security", {}).get("jwt_secret_key", "DEFAULT_INSECURE_KEY")
ALGORITHM = config.get("security", {}).get("jwt_algorithm", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = config.get("security", {}).get("access_token_expire_minutes", 60)
FRAME_OPTIONS = config.get("security", {}).get("frame_options", "DENY")

# ==========================================
# Security Middleware
# ==========================================
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;"
    response.headers["X-Frame-Options"] = FRAME_OPTIONS
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response

# ==========================================
# Authentication & Identity Management
# ==========================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v2/auth/login")

def init_auth_db():
    os.makedirs(AUTH_DB_PATH.parent, exist_ok=True)
    conn = sqlite3.connect(AUTH_DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            must_change_pwd BOOLEAN DEFAULT 0
        )
    """)

    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    if "must_change_pwd" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN must_change_pwd BOOLEAN DEFAULT 0")

    cursor.execute("SELECT password_hash FROM users WHERE username='admin'")
    row = cursor.fetchone()

    if row:
        if pwd_context.verify("admin", row[0]):
            cursor.execute("UPDATE users SET must_change_pwd = 1 WHERE username='admin'")
    else:
        default_hash = pwd_context.hash("admin")
        cursor.execute("INSERT INTO users (username, password_hash, role, must_change_pwd) VALUES (?, ?, ?, ?)",
                      ("admin", default_hash, "admin", 1))

    conn.commit()
    conn.close()

init_auth_db()

def get_auth_db():
    conn = sqlite3.connect(AUTH_DB_PATH, check_same_thread=False)
    conn.isolation_level = None
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_auth_db)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    cursor.close()

    if user is None:
        raise credentials_exception
    return dict(user)

def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user

# ==========================================
# Database Configuration & Lifecycle
# ==========================================

def get_db():
    if not DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database not mounted or unavailable.")

    db_uri = f"file:{DB_PATH}?mode=ro"

    conn = None
    try:
        conn = sqlite3.connect(db_uri, uri=True, check_same_thread=False, timeout=15.0)
        conn.isolation_level = None
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA mmap_size=268435456;")
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        if conn:
            conn.close()

def get_ml_db():
    ml_db_path = DB_PATH.parent / "baselines.db"

    if not ml_db_path.exists():
        logger.warning(f"ML Database not found at {ml_db_path}")
        yield None
        return

    conn = None
    try:
        db_uri = f"file:{ml_db_path}?mode=ro"
        conn = sqlite3.connect(db_uri, uri=True, check_same_thread=False, timeout=15.0)
        conn.isolation_level = None
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA mmap_size=268435456;")
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        if conn:
            conn.close()

class AlertQuery(BaseModel):
    limit: int = Field(default=500, le=5000)
    min_score: float = Field(default=0.0, ge=0.0, le=1.0)
    search: Optional[str] = Field(default=None, max_length=100)

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "analyst"

# ==========================================
# API Endpoints
# ==========================================
@app.post("/api/v2/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: sqlite3.Connection = Depends(get_auth_db)):
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (form_data.username,))
        user = cursor.fetchone()

        if not user or not pwd_context.verify(form_data.password, user["password_hash"]):
            logger.warning(f"Failed login attempt for username: {form_data.username}")
            raise HTTPException(status_code=401, detail="Incorrect username or password")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        expire = datetime.utcnow() + access_token_expires
        to_encode = {"sub": user["username"], "exp": expire, "role": user["role"]}
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

        logger.info(f"Successful login for user: {user['username']}")
        user_dict = dict(user)

        return {
            "access_token": encoded_jwt,
            "token_type": "bearer",
            "role": user_dict["role"],
            "must_change_pwd": bool(user_dict.get("must_change_pwd", 0))
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication DB Fault: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during authentication")

@app.post("/api/v2/auth/users")
def create_user(user: UserCreate, current_user: dict = Depends(require_admin), db: sqlite3.Connection = Depends(get_auth_db)):
    try:
        cursor = db.cursor()
        hashed_password = pwd_context.hash(user.password)
        cursor.execute("INSERT INTO users (username, password_hash, role, must_change_pwd) VALUES (?, ?, ?, ?)",
                      (user.username, hashed_password, user.role, 1))
        db.commit()
        logger.info(f"Admin '{current_user['username']}' successfully created user '{user.username}'")
        return {"msg": f"User {user.username} created successfully"}

    except sqlite3.IntegrityError:
        logger.warning(f"Admin '{current_user['username']}' attempted to create duplicate user '{user.username}'")
        raise HTTPException(status_code=400, detail="Username already exists")
    except Exception as e:
        logger.error(f"User Creation DB Fault: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during user creation")

@app.get("/api/v2/metrics")
def get_metrics(response: Response, db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    try:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM events")
        total = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as crit FROM events WHERE level = 'CRITICAL'")
        crit = cursor.fetchone()["crit"]

        return {"total_alerts": total, "critical_alerts": crit}
    except sqlite3.OperationalError as e:
        if "no such table" in str(e).lower():
            return {"total_alerts": 0, "critical_alerts": 0}
        logger.error(f"Metrics DB Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Metrics query failed")
    except Exception as e:
        logger.error(f"Metrics API Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Metrics query failed")

@app.get("/api/v2/alerts/query")
def query_alerts(response: Response, query: AlertQuery = Depends(), db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    try:
        cursor = db.cursor()
        sql = "SELECT * FROM events WHERE anomaly_score >= ?"
        params = [query.min_score]

        if query.search:
            sql += " AND (comm LIKE ? OR mitre_technique LIKE ? OR message LIKE ?)"
            wildcard = f"%{query.search}%"
            params.extend([wildcard, wildcard, wildcard])

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(query.limit)

        cursor.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]
    except sqlite3.OperationalError as e:
        if "no such table" in str(e).lower():
            return []
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Query DB Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database query failed: {e}")

@app.get("/api/v2/alerts/cluster")
def get_clustered_alerts(limit: int = 50, db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    try:
        cursor = db.cursor()
        cutoff_ts = int(datetime.utcnow().timestamp()) - 604800

        sql = """
            SELECT
                comm,
                mitre_tactic,
                mitre_technique,
                level,
                COUNT(event_id) as hit_count,
                MAX(timestamp) as last_seen,
                MAX(anomaly_score) as max_score
            FROM events
            WHERE timestamp >= ?
            GROUP BY comm, mitre_technique
            ORDER BY max_score DESC, last_seen DESC
            LIMIT ?
        """
        cursor.execute(sql, [cutoff_ts, limit])
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Cluster Query Fault: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Cluster query failed")

@app.get("/api/v2/forensics/timeline/{pid}")
def get_process_timeline(pid: int, db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    try:
        cursor = db.cursor()
        sql = """
            SELECT timestamp, event_id, level, mitre_technique, comm, target_file, dest_ip, message
            FROM events
            WHERE pid = ? OR ppid = ?
            ORDER BY timestamp ASC
        """
        cursor.execute(sql, [pid, pid])
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Timeline Query Fault [PID {pid}]: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Timeline query failed")

@app.get("/api/v2/forensics/{event_id}")
def get_forensic_context(event_id: str, db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    try:
        cursor = db.cursor()
        cursor.execute("SELECT timestamp, pid FROM events WHERE event_id = ?", [event_id])
        target = cursor.fetchone()

        if not target:
            logger.warning(f"Forensic context requested for unknown event ID: {event_id}")
            raise HTTPException(status_code=404, detail="Event not found")

        ts, pid = target["timestamp"], target["pid"]

        cursor.execute("""
            SELECT * FROM events
            WHERE pid = ? AND timestamp BETWEEN ? AND ?
            ORDER BY timestamp ASC
        """, [pid, ts - 5, ts + 5])

        return {"target_event_id": event_id, "timeline": [dict(row) for row in cursor.fetchall()]}

    except HTTPException:
        raise # Allow the 404 to pass through cleanly
    except Exception as e:
        logger.error(f"Forensic Context Query Fault [Event {event_id}]: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Forensic query failed")

class PasswordChangeRequest(BaseModel):
    new_password: str

@app.post("/api/v2/auth/change_password")
def change_password(req: PasswordChangeRequest, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_auth_db)):
    try:
        hashed_password = pwd_context.hash(req.new_password)
        cursor = db.cursor()
        cursor.execute("UPDATE users SET password_hash = ?, must_change_pwd = 0 WHERE username = ?", (hashed_password, current_user["username"]))
        db.commit()
        cursor.close()
        logger.info(f"User '{current_user['username']}' successfully updated their password.")
        return {"detail": "Password updated successfully"}
    except Exception as e:
        logger.error(f"Password Update Fault: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during password update")

@app.get("/api/v2/ml/trends")
def get_ml_trends(db: sqlite3.Connection = Depends(get_db), ml_db: sqlite3.Connection = Depends(get_ml_db), current_user: dict = Depends(get_current_user)):
    try:
        cursor = db.cursor()
        trends = []
        try:
            cursor.execute("""
                SELECT timestamp, anomaly_score, comm
                FROM events
                WHERE anomaly_score > 0.0
                ORDER BY timestamp DESC LIMIT 200
            """)
            trends = [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.warning(f"Trend Query Blocked: {e}")

        total_profiles, active_roles = 0, 0
        if ml_db:
            ml_cursor = ml_db.cursor()
            try:
                ml_cursor.execute("SELECT COUNT(*) as c FROM ueba_process_profiles")
                total_profiles = ml_cursor.fetchone()["c"]
                ml_cursor.execute("SELECT COUNT(*) as c FROM ueba_role_profiles")
                active_roles = ml_cursor.fetchone()["c"]
            except Exception as e:
                logger.warning(f"Trend Stats Query Blocked: {e}")

        return {
            "trends": trends,
            "stats": {"total_process_profiles": total_profiles, "active_roles": active_roles}
        }
    except Exception as e:
        logger.error(f"ML Trends Query Fault: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch ML trends")

@app.get("/api/v2/ml/profiles")
def get_ml_profiles(ml_db: sqlite3.Connection = Depends(get_ml_db), current_user: dict = Depends(get_current_user)):
    processes, roles = [], []

    if ml_db:
        try:
            cursor = ml_db.cursor()
            try:
                cursor.execute("""
                    SELECT process_hash, event_count, mean_delta, m2_delta
                    FROM ueba_process_profiles
                    ORDER BY event_count DESC LIMIT 100
                """)
                processes = [dict(row) for row in cursor.fetchall()]
            except Exception as e:
                logger.warning(f"Process Profile Query Blocked: {e}")

            try:
                cursor.execute("""
                    SELECT binary_name, instance_count, max_velocity, mean_entropy
                    FROM ueba_role_profiles
                    ORDER BY instance_count DESC LIMIT 100
                """)
                roles = [dict(row) for row in cursor.fetchall()]
            except Exception as e:
                logger.warning(f"Role Profile Query Blocked: {e}")
        except Exception as e:
            logger.error(f"ML Profiles Query Fault: {e}", exc_info=True)

    return {"processes": processes, "roles": roles}

# ==========================================
# Static Routing
# ==========================================
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def read_root():
    return FileResponse("static/index.html")

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    from fastapi import Response
    return Response(content=b"", media_type="image/x-icon")