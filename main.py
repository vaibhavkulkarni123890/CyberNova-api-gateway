import os
import json
import random
import time
import asyncio
import platform
import socket
import sqlite3
import pymysql
import bcrypt
import jwt
import pytz
import smtplib
import ssl
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

from agent import (
    scan_real_processes,
    scan_real_network_connections,
    scan_real_open_ports,
    get_real_system_info
)

# Initialize FastAPI
app = FastAPI(
    title="CyberNova API",
    version="3.0",
    description="Real-time security scans, no mock data."
)

# CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Config
IST = pytz.timezone("Asia/Kolkata")
JWT_SECRET = os.getenv("JWT_SECRET", "plus-one")
JWT_ALGORITHM = "HS256"
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER", "cybernova073@gmail.com")
EMAIL_PASS = os.getenv("EMAIL_PASS", "hsrz fymn gplp enbp")

# Database
USE_MYSQL = bool(os.getenv("MYSQL_HOST") and os.getenv("MYSQL_PASSWORD"))
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_PORT = int(os.getenv("MYSQLPORT", "3306"))
MYSQL_USER = os.getenv("MYSQLUSER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_ROOT_PASSWORD")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "railway")
SQLITE_PATH = "cybernova.db"

# Auth Model
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    company: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class WaitlistEntry(BaseModel):
    email: EmailStr

class ThreatAlert(BaseModel):
    threat_type: str
    severity: str
    source_ip: str
    description: str
    risk_score: int

# User data
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: int, email: str) -> str:
    return jwt.encode({
        "user_id": user_id,
        "email": email,
        "exp": datetime.now(IST) + timedelta(days=7)
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

security = HTTPBearer()

# WebSocket manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

# Database connection
@contextmanager
def get_db_connection():
    if USE_MYSQL:
        conn = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=False
        )
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(SQLITE_PATH, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=1000")
        conn.execute("PRAGMA temp_store=memory")
        try:
            yield conn
        finally:
            conn.close()

# Initialize tables
def init_database():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                company TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS waitlist (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                email TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_scans (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                system_info TEXT,
                threats_detected INTEGER DEFAULT 0,
                scan_status TEXT DEFAULT 'completed',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                scan_id TEXT NOT NULL,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                hostname TEXT,
                service_info TEXT,
                activity_description TEXT,
                status TEXT,
                pid INTEGER,
                process_name TEXT,
                process_exe TEXT,
                process_cmdline TEXT,
                threat_level TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_processes (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                scan_id TEXT NOT NULL,
                pid INTEGER,
                name TEXT,
                cpu_percent REAL,
                memory_percent REAL,
                threat_level TEXT,
                threat_reasons TEXT,
                exe_path TEXT,
                cmdline TEXT,
                username TEXT,
                network_activity TEXT,
                behavior_analysis TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risky_ports (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                scan_id TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                threat_level TEXT,
                reason TEXT,
                recommendation TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_history (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                user_id INTEGER NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                description TEXT,
                risk_score INTEGER,
                is_resolved BOOLEAN DEFAULT FALSE,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_recommendations (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                scan_id TEXT NOT NULL,
                type TEXT,
                priority TEXT,
                title TEXT,
                description TEXT,
                action TEXT,
                details TEXT,
                is_sent BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analytics (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                metric_type TEXT NOT NULL,
                metric_value REAL NOT NULL,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

# Authentication endpoints
@app.post("/api/auth/register")
async def register_user(user_data: UserRegister, background_tasks: BackgroundTasks):
    """Register new user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_data.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered")
        password_hash = hash_password(user_data.password)
        cursor.execute(
            "INSERT INTO users (email, password_hash, full_name, company) VALUES (?, ?, ?, ?)",
            (user_data.email, password_hash, user_data.full_name, user_data.company)
        )
        user_id = cursor.lastrowid
        conn.commit()
    token = create_jwt_token(user_id, user_data.email)
    welcome_email = f"Hi {user_data.full_name},\n\nWelcome to CyberNova AI!\nLogin: http://localhost:3000/dashboard"
    background_tasks.add_task(send_email, user_data.email, "Welcome to CyberNova", welcome_email)
    return {
        "message": "User registered",
        "token": token,
        "user": {
            "id": user_id,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "company": user_data.company
        }
    }

@app.post("/api/auth/login")
async def login_user(user_login: UserLogin):
    """Login user"""
    with get_db_connection() as conn:
        result = conn.execute("SELECT * FROM users WHERE email = ? AND is_active = TRUE", (user_login.email,)).fetchone()
        if not result or not verify_password(user_login.password, result["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        token = create_jwt_token(result["id"], result["email"])
        return {
            "message": "Login successful",
            "token": token,
            "user": {
                "id": result["id"],
                "email": result["email"],
                "full_name": result["full_name"],
                "company": result["company"]
            }
        }

# Waitlist
@app.post("/api/waitlist")
async def join_waitlist(waitlist_entry: WaitlistEntry, background_tasks: BackgroundTasks):
    """Add email to waitlist"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO waitlist (email) VALUES (?)", (waitlist_entry.email,))
        conn.commit()
    background_tasks.add_task(send_email, waitlist_entry.email, "Waitlist Joined", "Thanks for joining our waitlist!")
    return {"message": "Successfully joined waitlist"}

# Dashboard endpoints: real data only, no mock
@app.get("/api/dashboard/stats")
async def dashboard_stats(current_user: dict = Depends(get_current_user)):
    """Get real stats from the latest scan"""
    with get_db_connection() as conn:
        latest_scan = conn.execute(
            "SELECT * FROM system_scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
            (current_user["id"],)
        ).fetchone()
        if latest_scan:
            scan_id = latest_scan["scan_id"]
            process_threats = conn.execute(
                "SELECT COUNT(*) as count FROM suspicious_processes WHERE scan_id = ? AND threat_level IN ('high', 'critical')",
                (scan_id,)
            ).fetchone()["count"]
            port_threats = conn.execute(
                "SELECT COUNT(*) as count FROM risky_ports WHERE scan_id = ? AND threat_level IN ('high', 'critical')",
                (scan_id,)
            ).fetchone()["count"]
            network_threats = conn.execute(
                "SELECT COUNT(*) as count FROM network_connections WHERE scan_id = ? AND threat_level IN ('high', 'critical')",
                (scan_id,)
            ).fetchone()["count"]
            total_threats = process_threats + port_threats + network_threats
            recorded_threats = latest_scan["threats_detected"] or 0
            total_threats = max(total_threats, recorded_threats)
            risk_score = min(100, max(0, total_threats * 15))
            system_health = max(0, 100 - (total_threats * 10))
            last_scan_time = latest_scan["created_at"]
            scan_status = latest_scan["scan_status"]
        else:
            total_threats = 0
            risk_score = 0
            system_health = 100
            last_scan_time = None
            scan_status = "No scans yet"
    return {
        "totalThreats": int(total_threats),
        "activeAlerts": int(total_threats),
        "riskScore": round(float(risk_score), 2),
        "systemHealth": round(float(system_health), 2),
        "lastScanTime": last_scan_time,
        "scanStatus": scan_status
    }

@app.get("/api/dashboard/alerts")
async def dashboard_alerts(current_user: dict = Depends(get_current_user)):
    """Get real alerts from the latest scan"""
    with get_db_connection() as conn:
        scan = conn.execute(
            "SELECT scan_id FROM system_scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
            (current_user["id"],)
        ).fetchone()
        if not scan:
            return []
        scan_id = scan["scan_id"]
        threats = conn.execute('''
            SELECT 'process_' || sp.name || '_' || sp.pid as id, 'Suspicious Process: ' || sp.name as title,
            'Real threat detected: ' || sp.name || ' (PID: ' || sp.pid || ')' as description,
            sp.threat_level as severity, s.created_at as timestamp, 'Local System' as sourceIp,
            CASE sp.threat_level WHEN 'critical' THEN 90 WHEN 'high' THEN 70 ELSE 50 END as riskScore,
            0 as isBlocked, 'process' as type, sp.threat_reasons as details
            FROM suspicious_processes sp
            JOIN system_scans s ON sp.scan_id = s.scan_id
            WHERE sp.scan_id = ? AND sp.threat_level IN ('high', 'critical')
            UNION ALL
            SELECT 'port_' || rp.port as id, 'Risky Port: ' || rp.port || ' (' || COALESCE(rp.service, 'Unknown') || ')' as title,
            'Real vulnerability: ' || COALESCE(rp.reason, 'Port ' || rp.port || ' is exposed') as description,
            rp.threat_level as severity, s.created_at as timestamp, 'Local System' as sourceIp,
            CASE rp.threat_level WHEN 'critical' THEN 80 WHEN 'high' THEN 60 ELSE 40 END as riskScore,
            0 as isBlocked, 'port' as type, rp.reason as details
            FROM risky_ports rp JOIN system_scans s ON rp.scan_id = s.scan_id
            WHERE rp.scan_id = ? AND rp.threat_level IN ('high', 'critical')
            UNION ALL
            SELECT 'network_' || nc.remote_ip || '_' || nc.remote_port as id, 'Suspicious Network Activity' as title,
            'Real network threat: ' || COALESCE(nc.activity_description, 'Suspicious connection detected') as description,
            nc.threat_level as severity, s.created_at as timestamp, nc.remote_ip as sourceIp,
            CASE nc.threat_level WHEN 'critical' THEN 85 WHEN 'high' THEN 65 ELSE 45 END as riskScore,
            0 as isBlocked, 'network' as type, nc.activity_description as details
            FROM network_connections nc
            JOIN system_scans s ON nc.scan_id = s.scan_id
            WHERE nc.scan_id = ? AND nc.threat_level IN ('high', 'critical')
            ORDER BY timestamp DESC
        ''', (scan_id, scan_id, scan_id)).fetchall()
        seen_ids = set()
        alerts = []
        for threat in threats:
            if threat["id"] in seen_ids:
                continue
            seen_ids.add(threat["id"])
            alerts.append({
                "id": threat["id"],
                "title": threat["title"],
                "description": threat["description"],
                "severity": threat["severity"],
                "timestamp": threat["timestamp"],
                "sourceIp": threat["sourceIp"],
                "riskScore": threat["riskScore"],
                "isBlocked": bool(threat["isBlocked"]),
                "type": threat["type"],
                "isReal": True
            })
        return alerts

# Real scan ingestion: runs agent.py's scan functions directly

@app.post("/api/scan/start")
async def start_manual_scan(background_tasks: BackgroundTasks, current_user: dict = Depends(get_current_user)):
    """Perform a real local system scan and save results—now with full error handling."""
    try:
        suspicious_processes = scan_real_processes()
        network_threats = scan_real_network_connections()
        risky_ports = scan_real_open_ports()
        system_info = get_real_system_info()

        total_threats = len(suspicious_processes) + len(network_threats) + len(risky_ports)
        scan_id = f"scan_{int(time.time())}_{random.randint(1000, 9999)}"
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO system_scans (scan_id, user_id, system_info, threats_detected, scan_status, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                current_user["id"],
                json.dumps(system_info),
                total_threats,
                "completed",
                (datetime.now(IST) + timedelta(hours=2)).isoformat()
            ))

            for process in suspicious_processes:
                cursor.execute("""
                    INSERT INTO suspicious_processes (scan_id, pid, name, cpu_percent, memory_percent, threat_level, threat_reasons, exe_path, cmdline, username)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    process["pid"],
                    process["name"],
                    process["cpu_percent"],
                    process["memory_percent"],
                    process["threat_level"],
                    json.dumps(process["threat_reasons"]),
                    process["exe_path"],
                    " ".join(process.get("cmdline", [])),
                    process["username"]
                ))

            for net in network_threats:
                cursor.execute("""
                    INSERT INTO network_connections (scan_id, local_ip, local_port, remote_ip, remote_port, status, pid, process_name, threat_level, activity_description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    net["local_ip"],
                    net["local_port"],
                    net["remote_ip"],
                    net["remote_port"],
                    net["status"],
                    net["pid"],
                    net["process_name"],
                    net["threat_level"],
                    net["activity_description"]
                ))

            for port in risky_ports:
                cursor.execute("""
                    INSERT INTO risky_ports (scan_id, port, service, threat_level, reason)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    port["port"],
                    port["service"],
                    port["threat_level"],
                    port["reason"]
                ))

            conn.commit()

        await manager.broadcast(json.dumps({
            "type": "scan_completed",
            "data": {
                "scan_id": scan_id,
                "threats_detected": total_threats,
                "timestamp": datetime.now(IST).isoformat(),
                "user_id": current_user["id"]
            }
        }))

        if background_tasks and (suspicious_processes or network_threats or risky_ports):
            subject, body = build_threat_summary_email(
                current_user["full_name"],
                scan_id,
                [p for p in suspicious_processes if p["threat_level"] in ("high", "critical")],
                [n for n in network_threats if n["threat_level"] in ("high", "critical")],
                [r for r in risky_ports if r["threat_level"] in ("high", "critical")]
            )
            background_tasks.add_task(send_email, current_user["email"], subject, body)

        return {
            "status": "success",
            "scan_id": scan_id,
            "threats_detected": total_threats,
            "system_info": system_info,
            "suspicious_processes": suspicious_processes,
            "network_threats": network_threats,
            "risky_ports": risky_ports
        }
    except Exception as e:
        # Log full traceback for debugging
        traceback.print_exc()
        # Return structured error details to frontend
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Scan failed",
                "error": str(e),
                "traceback": traceback.format_exc()
            }
        )


@app.get("/api/scan/latest")
async def get_latest_scan(current_user: dict = Depends(get_current_user)):
    """Get the latest real scan results"""
    with get_db_connection() as conn:
        scan = conn.execute(
            "SELECT * FROM system_scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
            (current_user["id"],)
        ).fetchone()
        if not scan:
            return {"message": "No scans found"}
        connections = conn.execute(
            "SELECT * FROM network_connections WHERE scan_id = ?",
            (scan["scan_id"],)
        ).fetchall()
        processes = conn.execute(
            "SELECT * FROM suspicious_processes WHERE scan_id = ?",
            (scan["scan_id"],)
        ).fetchall()
        ports = conn.execute(
            "SELECT * FROM risky_ports WHERE scan_id = ?",
            (scan["scan_id"],)
        ).fetchall()
        recommendations = conn.execute(
            "SELECT * FROM security_recommendations WHERE scan_id = ?",
            (scan["scan_id"],)
        ).fetchall()
    # Format as expected by frontend
    formatted_connections = [dict(row) for row in connections]
    formatted_processes = []
    for proc in processes:
        proc_dict = dict(proc)
        proc_dict["threat_indicators"] = json.loads(proc_dict.get("threat_reasons", "[]")) if proc_dict.get("threat_reasons") else []
        formatted_processes.append(proc_dict)
    formatted_ports = [dict(row) for row in ports]
    formatted_recommendations = [dict(row) for row in recommendations]
    return {
        "scan_info": dict(scan),
        "system_info": json.loads(scan["system_info"]) if scan["system_info"] else {},
        "network_connections": formatted_connections,
        "suspicious_processes": formatted_processes,
        "risky_ports": formatted_ports,
        "recommendations": formatted_recommendations
    }

@app.post("/api/threat/{threat_id}/resolve")
async def resolve_threat(threat_id: str, current_user: dict = Depends(get_current_user)):
    """Mark a threat as resolved"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE threats SET is_resolved = 1, resolved_at = ? WHERE id = ?",
            (datetime.now(IST).isoformat(), threat_id)
        )
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Threat not found")
    return {"success": True, "message": "Threat resolved"}

@app.post("/api/scan/reset")
async def reset_scan_data(current_user: dict = Depends(get_current_user)):
    """Reset/clear all scan data for the current user (no backups)"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Clear all scan-related data for this user
            cursor.execute("""
                DELETE FROM network_connections WHERE scan_id IN (
                    SELECT scan_id FROM system_scans WHERE user_id = ?
                )
            """, (current_user["id"],))
            cursor.execute("""
                DELETE FROM suspicious_processes WHERE scan_id IN (
                    SELECT scan_id FROM system_scans WHERE user_id = ?
                )
            """, (current_user["id"],))
            cursor.execute("""
                DELETE FROM risky_ports WHERE scan_id IN (
                    SELECT scan_id FROM system_scans WHERE user_id = ?
                )
            """, (current_user["id"],))
            cursor.execute("""
                DELETE FROM security_recommendations WHERE scan_id IN (
                    SELECT scan_id FROM system_scans WHERE user_id = ?
                )
            """, (current_user["id"],))
            cursor.execute("""
                DELETE FROM system_scans WHERE user_id = ?
            """, (current_user["id"],))
            cursor.execute("""
                DELETE FROM threat_history WHERE user_id = ?
            """, (current_user["id"],))
            conn.commit()
        return {
            "success": True,
            "message": "Scan data reset successfully",
            "timestamp": datetime.now(IST).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Reset failed: {str(e)}")

# Cleanup old scan data (background task)
async def cleanup_expired_data():
    """Remove expired scans and orphaned data every 30 minutes"""
    while True:
        try:
            await asyncio.sleep(1800)  # 30 minutes
            with get_db_connection() as conn:
                cursor = conn.cursor()
                # Remove scans older than 2 hours
                cursor.execute("""
                    DELETE FROM system_scans WHERE created_at < datetime('now', '-2 hours')
                """)
                # Remove orphaned scan data
                cursor.execute("""
                    DELETE FROM network_connections
                    WHERE scan_id NOT IN (SELECT scan_id FROM system_scans)
                """)
                cursor.execute("""
                    DELETE FROM suspicious_processes
                    WHERE scan_id NOT IN (SELECT scan_id FROM system_scans)
                """)
                cursor.execute("""
                    DELETE FROM risky_ports
                    WHERE scan_id NOT IN (SELECT scan_id FROM system_scans)
                """)
                cursor.execute("""
                    DELETE FROM security_recommendations
                    WHERE scan_id NOT IN (SELECT scan_id FROM system_scans)
                """)
                # Remove old threat history
                cursor.execute("""
                    DELETE FROM threat_history WHERE detected_at < datetime('now', '-24 hours')
                """)
                conn.commit()
        except Exception as e:
            print(f"Cleanup error: {e}")

# Email helper (real SMTP)
def send_email(to_email: str, subject: str, body: str):
    """Send a real email via SMTP"""
    if not all([EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS]):
        print("[WARN] Email not configured")
        return
    msg = MIMEMultipart()
    msg["From"] = EMAIL_USER
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls(context=context)
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, to_email, msg.as_string())
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

@app.get("/api/health")
async def health_check():
    """Simple health check endpoint"""
    with get_db_connection() as conn:
        try:
            conn.execute("SELECT 1").fetchone()
            db_status = "healthy"
        except:
            db_status = "unhealthy"
    return {
        "status": "healthy",
        "database": db_status,
        "services": {
            "authentication": "active",
            "threat_detection": "active",
            "websocket": "active"
        }
    }

@app.get("/api/admin/stats")
async def admin_stats():
    """Admin statistics (real data only)"""
    with get_db_connection() as conn:
        stats = {
            "total_users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "waitlist_count": conn.execute("SELECT COUNT(*) FROM waitlist").fetchone()[0],
            "active_connections": len(manager.active_connections)
        }
    return stats

# WebSocket endpoint (only broadcasts real scan completions)
@app.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time threat updates (broadcasts real scan completions)"""
    await manager.connect(websocket)
    try:
        while True:
            # Just keep the connection alive—broadcast happens in scan endpoints
            _ = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Initialize database and start background tasks on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database and start background cleanup task"""
    init_database()
    asyncio.create_task(cleanup_expired_data())

if __name__ == "__main__":
    # For local development, you can run this directly with Uvicorn
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)

