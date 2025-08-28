# api-gateway/main.py - Complete CyberNova AI Backend
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
import httpx, os, asyncio, json, random, hashlib, jwt, smtplib, ssl, time
try:
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
except ImportError:
    MimeText = None
    MimeMultipart = None
from starlette.responses import StreamingResponse
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
import sqlite3
import pymysql
from contextlib import contextmanager
import bcrypt
from agent import (
    perform_real_threat_scan,
    scan_real_processes,
    scan_real_network_connections,
    scan_real_open_ports,
    get_real_system_info,
    send_scan_results
)
import pytz
from dotenv import load_dotenv
import re
load_dotenv()  # Load environment variables from .env file
# from appwrite.client import Client
# from appwrite.services.users import Users
# from appwrite.services.databases import Databases
# from appwrite.exception import AppwriteException
# import logging

# Initialize Appwrite client
# client = Client()
# client.set_endpoint(os.getenv('REACT_APP_APPWRITE_ENDPOINT'))
# client.set_project(os.getenv('REACT_APP_APPWRITE_PROJECT_ID'))
# client.set_key(os.getenv('REACT_APP_APPWRITE_FUNCTION_ID'))

# Initialize Appwrite services
users_service =None
databases_service = None

app = FastAPI(
    title="CyberNova AI - Advanced Cybersecurity Platform", 
    version="3.0",
    description="Next-generation AI-powered cybersecurity platform with real-time threat detection"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"],
)
logging.basicConfig(level=logging.INFO)

# Configuration
DETECTION_SERVICE_URL = os.getenv("DETECTION_SERVICE_URL", "http://detection-service:8081")
ANALYTICS_SERVICE_URL = os.getenv("ANALYTICS_SERVICE_URL", "http://analytics-service:8083")
JWT_SECRET = os.getenv("JWT_SECRET", "plus-one")
JWT_ALGORITHM = "HS256"
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER", "cybernova073@gmail.com")
EMAIL_PASS = os.getenv("EMAIL_PASS", "hsrz fymn gplp enbp")

# Security
security = HTTPBearer()

# Database Configuration

# Replace your database configuration section with this:

# MySQL Configuration (matching your .env.example)
DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root:password@mysql:3306/cyberguard")
DB_USERNAME = os.getenv("DB_USERNAME", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")

if DATABASE_URL:
    url_pattern = r'mysql\+pymysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)'
    match = re.match(url_pattern, DATABASE_URL)
    if match:
        MYSQL_USER = match.group(1)
        MYSQL_PASSWORD = match.group(2) 
        MYSQL_HOST = match.group(3)
        MYSQL_PORT = int(match.group(4))
        MYSQL_DATABASE = match.group(5)
    else:
        # Fallback values
        MYSQL_HOST = "mysql"
        MYSQL_PORT = 3306
        MYSQL_USER = DB_USERNAME
        MYSQL_PASSWORD = DB_PASSWORD
        MYSQL_DATABASE = "cyberguard"
else:
    # Fallback when no DATABASE_URL
    MYSQL_HOST = "mysql"
    MYSQL_PORT = 3306
    MYSQL_USER = DB_USERNAME
    MYSQL_PASSWORD = DB_PASSWORD
    MYSQL_DATABASE = "cyberguard"

USE_MYSQL = bool(MYSQL_PASSWORD)
print(f"MySQL Config - Host: {MYSQL_HOST}, User: {MYSQL_USER}, Database: {MYSQL_DATABASE}")
print(f"Using MySQL: {USE_MYSQL}")

@contextmanager
def get_db_connection():
    """Get database connection (MySQL or SQLite)"""
    if USE_MYSQL:
        # Use MySQL for production/docker
        connection = None
        try:
            connection = pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DATABASE,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=False
            )
            print(f"Connected to MySQL database: {MYSQL_DATABASE}")
            yield connection
        except Exception as e:
            print(f"MySQL connection error: {e}")
            if connection:
                connection.rollback()
            raise e
        finally:
            if connection:
                connection.close()
    else:
        # Use SQLite for local development
        print("Using SQLite database for local development")
        conn = sqlite3.connect(DATABASE_PATH, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=1000")
        conn.execute("PRAGMA temp_store=memory")
        try:
            yield conn
        finally:
            conn.close()

def init_database():
    """Initialize database with all required tables (MySQL or SQLite)"""
    print("Initializing database...")
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # MySQL uses different syntax for AUTO_INCREMENT
        if USE_MYSQL:
            # MySQL syntax
            auto_increment = "AUTO_INCREMENT"
            current_timestamp = "CURRENT_TIMESTAMP"
            text_type = "TEXT"
            boolean_type = "BOOLEAN"
        else:
            # SQLite syntax  
            auto_increment = "AUTOINCREMENT"
            current_timestamp = "CURRENT_TIMESTAMP"
            text_type = "TEXT"
            boolean_type = "BOOLEAN"
    
        # Users table
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY {auto_increment},
                email {text_type} UNIQUE NOT NULL,
                password_hash {text_type} NOT NULL,
                full_name {text_type} NOT NULL,
                company {text_type},
                is_active {boolean_type} DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT {current_timestamp}
            )
        ''')
        
        # System scans table
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS system_scans (
                id INTEGER PRIMARY KEY {auto_increment},
                scan_id {text_type} UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                system_info {text_type},
                threats_detected INTEGER DEFAULT 0,
                scan_status {text_type} DEFAULT 'completed',
                created_at TIMESTAMP DEFAULT {current_timestamp},
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Network connections table
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY {auto_increment},
                scan_id {text_type} NOT NULL,
                local_ip {text_type},
                local_port INTEGER,
                remote_ip {text_type},
                remote_port INTEGER,
                hostname {text_type},
                service_info {text_type},
                activity_description {text_type},
                status {text_type},
                pid INTEGER,
                process_name {text_type},
                process_exe {text_type},
                process_cmdline {text_type},
                threat_level {text_type},
                created_at TIMESTAMP DEFAULT {current_timestamp},
                FOREIGN KEY (scan_id) REFERENCES system_scans (scan_id)
            )
        ''')
        
        # Suspicious processes table
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS suspicious_processes (
                id INTEGER PRIMARY KEY {auto_increment},
                scan_id {text_type} NOT NULL,
                pid INTEGER,
                name {text_type},
                cpu_percent REAL,
                memory_percent REAL,
                threat_level {text_type},
                threat_reasons {text_type},
                exe_path {text_type},
                cmdline {text_type},
                username {text_type},
                network_activity {text_type},
                behavior_analysis {text_type},
                created_at TIMESTAMP DEFAULT {current_timestamp},
                FOREIGN KEY (scan_id) REFERENCES system_scans (scan_id)
            )
        ''')
        
        # Risky ports table
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS risky_ports (
                id INTEGER PRIMARY KEY {auto_increment},
                scan_id {text_type} NOT NULL,
                port INTEGER,
                service {text_type},
                threat_level {text_type},
                reason {text_type},
                recommendation {text_type},
                created_at TIMESTAMP DEFAULT {current_timestamp},
                FOREIGN KEY (scan_id) REFERENCES system_scans (scan_id)
            )
        ''')
        
        # Threat history table
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS threat_history (
                id INTEGER PRIMARY KEY {auto_increment},
                user_id INTEGER NOT NULL,
                threat_type {text_type} NOT NULL,
                severity {text_type} NOT NULL,
                source_ip {text_type},
                description {text_type},
                risk_score INTEGER,
                is_resolved {boolean_type} DEFAULT FALSE,
                detected_at TIMESTAMP DEFAULT {current_timestamp},
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Security recommendations table
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS security_recommendations (
                id INTEGER PRIMARY KEY {auto_increment},
                scan_id {text_type} NOT NULL,
                type {text_type},
                priority {text_type},
                title {text_type},
                description {text_type},
                action {text_type},
                details {text_type},
                is_sent {boolean_type} DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT {current_timestamp},
                FOREIGN KEY (scan_id) REFERENCES system_scans (scan_id)
            )
        ''')
        
        # Analytics table
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS analytics (
                id INTEGER PRIMARY KEY {auto_increment},
                metric_type {text_type} NOT NULL,
                metric_value REAL NOT NULL,
                metadata {text_type},
                created_at TIMESTAMP DEFAULT {current_timestamp}
            )
        ''')
        
        conn.commit()
        print(f"Database initialized successfully using {'MySQL' if USE_MYSQL else 'SQLite'}")

# Pydantic Models
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

class User(BaseModel):
    id: int
    email: str
    full_name: str
    company: Optional[str]
    is_active: bool
    created_at: datetime

# WebSocket Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

# Database Functions

@contextmanager
def get_db_connection():
    """Get database connection (MySQL or SQLite)"""
    if USE_MYSQL:
        # Use MySQL for production
        connection = None
        try:
            connection = pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DATABASE,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=False
            )
            yield connection
        except Exception as e:
            if connection:
                connection.rollback()
            raise e
        finally:
            if connection:
                connection.close()
    else:
        # Use SQLite for local development
        conn = sqlite3.connect(DATABASE_PATH, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=1000")
        conn.execute("PRAGMA temp_store=memory")
        try:
            yield conn
        finally:
            conn.close()

# Utility Functions
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

ist = pytz.timezone('Asia/Kolkata')

def create_jwt_token(user_id: int, email: str) -> str:
    """Create JWT token"""
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.now(ist) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict[str, Any]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
    payload = verify_jwt_token(credentials.credentials)
    
    with get_db_connection() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE id = ? AND is_active = TRUE", 
            (payload["user_id"],)
        ).fetchone()
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return dict(user)

def send_email(to_email: str, subject: str, body: str):
    """Send a real email via SMTP (TLS)."""
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
        print(f"[INFO] Email sent to {to_email}")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

# Authentication Endpoints
# Replace the existing registration function and remove the waitlist endpoint

@app.post("/api/auth/register")
async def register_user(user_data: UserRegister, background_tasks: BackgroundTasks):
    """Register new user and send welcome email"""
    with get_db_connection() as conn:
        # Check if user already exists
        existing_user = conn.execute(
            "SELECT id FROM users WHERE email = ?", (user_data.email,)
        ).fetchone()
        
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Hash password and create user
        password_hash = hash_password(user_data.password)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (email, password_hash, full_name, company) VALUES (?, ?, ?, ?)",
            (user_data.email, password_hash, user_data.full_name, user_data.company)
        )
        user_id = cursor.lastrowid
        conn.commit()
    
    # Create JWT token
    token = create_jwt_token(user_id, user_data.email)
    
    # Send welcome email (only one email sent)
    welcome_email_body = f"""
Welcome to CyberNova AI!

Hi {user_data.full_name},

Your account has been successfully created! You now have access to our advanced cybersecurity platform.

What's Next:
✓ Complete your security profile
✓ Run your first security scan
✓ Set up threat monitoring
✓ Configure alert preferences
✓ Explore AI-powered analytics

Login to your dashboard: https://cybernova-de84b.web.app/

Get started with your first security scan to detect potential threats and vulnerabilities on your system.

Best regards,
The CyberNova AI Team
cybernova073@gmail.com
    """
    
    # Send email in background task
    background_tasks.add_task(
        send_email, 
        user_data.email, 
        "Welcome to CyberNova AI - Account Created Successfully!", 
        welcome_email_body
    )
    
    return {
        "message": "User registered successfully",
        "token": token,
        "user": {
            "id": user_id,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "company": user_data.company
        }
    }

# REMOVE this entire waitlist endpoint - delete it from your code:
# @app.post("/api/waitlist")
# async def join_waitlist(waitlist_entry: WaitlistEntry, background_tasks: BackgroundTasks):
#     """This endpoint should be completely removed"""

@app.post("/api/auth/login")
async def login_user(login_data: UserLogin):
    """Login user"""
    with get_db_connection() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE email = ? AND is_active = TRUE", 
            (login_data.email,)
        ).fetchone()
    
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_jwt_token(user["id"], user["email"])
    
    return {
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "company": user["company"]
        }
    }

@app.get("/api/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "full_name": current_user["full_name"],
        "company": current_user["company"],
        "created_at": current_user["created_at"]
    }


# Dashboard Endpoints
@app.get("/api/dashboard/stats")
async def dashboard_stats(current_user: dict = Depends(get_current_user)):
    """Get real dashboard statistics from actual scans (no duplicates)"""
    with get_db_connection() as conn:
        # Get latest scan data
        latest_scan = conn.execute("""
            SELECT * FROM system_scans 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 1
        """, (current_user["id"],)).fetchone()
        
        # Get current active threats from LATEST scan only
        if latest_scan:
            scan_id = latest_scan["scan_id"]
            
            # Count threats from the latest scan only
            process_threats = conn.execute("""
                SELECT COUNT(*) as count FROM suspicious_processes 
                WHERE scan_id = ? AND threat_level IN ('high', 'critical')
            """, (scan_id,)).fetchone()["count"]
            
            port_threats = conn.execute("""
                SELECT COUNT(*) as count FROM risky_ports 
                WHERE scan_id = ? AND threat_level IN ('high', 'critical')
            """, (scan_id,)).fetchone()["count"]
            
            network_threats = conn.execute("""
                SELECT COUNT(*) as count FROM network_connections 
                WHERE scan_id = ? AND threat_level IN ('high', 'critical')
            """, (scan_id,)).fetchone()["count"]
            
            total_threats = process_threats + port_threats + network_threats
            recorded_threats = latest_scan["threats_detected"] or 0
            total_threats = max(total_threats, recorded_threats)
            
        else:
            total_threats = 0
    
    # Calculate system health based on current threats
    risk_score = min(100, max(0, total_threats * 15))
    system_health = max(0, 100 - (total_threats * 10))
    
    return {
        "totalThreats": int(total_threats),
        "activeAlerts": int(total_threats),
        "riskScore": round(float(risk_score), 2),
        "systemHealth": round(float(system_health), 2),
        "lastScanTime": latest_scan["created_at"] if latest_scan else None,
        "scanStatus": latest_scan["scan_status"] if latest_scan else "No scans yet"
    }def get_threat_resolution(threat_type, severity, description):
    """Get resolution recommendations for different threat types"""
    resolutions = {
        "Suspicious Process": {
            "critical": {
                "action": "Immediate Action Required",
                "steps": [
                    "1. Terminate the suspicious process immediately",
                    "2. Run a full system antivirus scan",
                    "3. Check for unauthorized system changes",
                    "4. Update all security software",
                    "5. Consider system restore if needed"
                ],
                "prevention": "Keep antivirus updated, avoid suspicious downloads"
            },
            "high": {
                "action": "Action Recommended",
                "steps": [
                    "1. Investigate the process in Task Manager",
                    "2. Check process location and digital signature",
                    "3. Run antivirus scan if suspicious",
                    "4. Monitor system performance"
                ],
                "prevention": "Regular system scans, software updates"
            }
        },
        "Risky Port": {
            "critical": {
                "action": "Secure Network Immediately",
                "steps": [
                    "1. Close unnecessary open ports",
                    "2. Configure firewall rules",
                    "3. Check for unauthorized services",
                    "4. Update network security settings",
                    "5. Monitor network traffic"
                ],
                "prevention": "Regular firewall audits, disable unused services"
            },
            "high": {
                "action": "Review Network Security",
                "steps": [
                    "1. Verify if the service is needed",
                    "2. Configure proper access controls",
                    "3. Update service if outdated",
                    "4. Monitor port activity"
                ],
                "prevention": "Regular security audits, principle of least privilege"
            }
        },
        "Suspicious Network Activity": {
            "critical": {
                "action": "Block Suspicious Traffic",
                "steps": [
                    "1. Block suspicious IP addresses",
                    "2. Check for malware infections",
                    "3. Review network logs",
                    "4. Update firewall rules",
                    "5. Consider network isolation if needed"
                ],
                "prevention": "Use reputable DNS, avoid suspicious websites"
            },
            "high": {
                "action": "Monitor Network Activity",
                "steps": [
                    "1. Review connection details",
                    "2. Check if connection is legitimate",
                    "3. Monitor for unusual data transfer",
                    "4. Update security software"
                ],
                "prevention": "Regular network monitoring, secure browsing habits"
            }
        }
    }
    
    # Default resolution for unknown threats
    default_resolution = {
        "action": "General Security Review",
        "steps": [
            "1. Run a full system security scan",
            "2. Update all software and security patches",
            "3. Review recent system changes",
            "4. Monitor system behavior"
        ],
        "prevention": "Keep systems updated, use reputable security software"
    }
    
    threat_category = "Suspicious Process"
    if "port" in description.lower() or "service" in description.lower():
        threat_category = "Risky Port"
    elif "network" in description.lower() or "connection" in description.lower():
        threat_category = "Suspicious Network Activity"
    
    return resolutions.get(threat_category, {}).get(severity.lower(), default_resolution)

@app.get("/api/dashboard/alerts")
async def dashboard_alerts(current_user: dict = Depends(get_current_user)):
    """Get recent real threat alerts from latest scan only (no duplicates)"""
    with get_db_connection() as conn:
        # Get the latest scan for this user
        latest_scan = conn.execute("""
            SELECT scan_id FROM system_scans 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 1
        """, (current_user["id"],)).fetchone()
        
        if not latest_scan:
            return []
        
        scan_id = latest_scan["scan_id"]
        
        # Get threats from LATEST scan only to prevent duplicates
        alerts_query = """
        SELECT 
            'process_' || sp.name || '_' || sp.pid as id,
            'Suspicious Process: ' || sp.name as title,
            'Real threat detected: ' || sp.name || ' (PID: ' || sp.pid || ')' as description,
            sp.threat_level as severity,
            s.created_at as timestamp,
            'Local System' as sourceIp,
            CASE sp.threat_level 
                WHEN 'critical' THEN 90
                WHEN 'high' THEN 70
                ELSE 50
            END as riskScore,
            0 as isBlocked,
            'process' as type,
            sp.threat_reasons as details
        FROM suspicious_processes sp
        JOIN system_scans s ON sp.scan_id = s.scan_id
        WHERE sp.scan_id = ? AND sp.threat_level IN ('high', 'critical')
        
        UNION ALL
        
        SELECT 
            'port_' || rp.port as id,
            'Risky Port: ' || rp.port || ' (' || COALESCE(rp.service, 'Unknown') || ')' as title,
            'Real vulnerability: ' || COALESCE(rp.reason, 'Port ' || rp.port || ' is exposed') as description,
            rp.threat_level as severity,
            s.created_at as timestamp,
            'Local System' as sourceIp,
            CASE rp.threat_level 
                WHEN 'critical' THEN 80
                WHEN 'high' THEN 60
                ELSE 40
            END as riskScore,
            0 as isBlocked,
            'port' as type,
            rp.reason as details
        FROM risky_ports rp
        JOIN system_scans s ON rp.scan_id = s.scan_id
        WHERE rp.scan_id = ? AND rp.threat_level IN ('high', 'critical')
        
        UNION ALL
        
        SELECT 
            'network_' || nc.remote_ip || '_' || nc.remote_port as id,
            'Suspicious Network Activity' as title,
            'Real network threat: ' || COALESCE(nc.activity_description, 'Suspicious connection detected') as description,
            nc.threat_level as severity,
            s.created_at as timestamp,
            nc.remote_ip as sourceIp,
            CASE nc.threat_level 
                WHEN 'critical' THEN 85
                WHEN 'high' THEN 65
                ELSE 45
            END as riskScore,
            0 as isBlocked,
            'network' as type,
            nc.activity_description as details
        FROM network_connections nc
        JOIN system_scans s ON nc.scan_id = s.scan_id
        WHERE nc.scan_id = ? AND nc.threat_level IN ('high', 'critical')
        
        ORDER BY timestamp DESC
        """
        
        threats = conn.execute(alerts_query, (scan_id, scan_id, scan_id)).fetchall()
    
    alerts = []
    seen_ids = set()  # Additional deduplication
    
    for threat in threats:
        # Skip if we've already seen this threat ID
        if threat["id"] in seen_ids:
            continue
        seen_ids.add(threat["id"])
        
        # Get resolution recommendations
        resolution = get_threat_resolution(threat["title"], threat["severity"], threat["description"])
        
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
            "resolution": resolution,
            "isReal": True  # Mark as real threat
        })
    
    return alerts

@app.get("/api/threat/{threat_id}/details")
async def get_threat_details(threat_id: str, current_user: dict = Depends(get_current_user)):
    """Get detailed information about a specific threat"""
    with get_db_connection() as conn:
        # Parse threat ID to determine type
        if threat_id.startswith("process_"):
            process_name = threat_id.replace("process_", "")
            threat_data = conn.execute("""
                SELECT sp.*, s.created_at, s.scan_id
                FROM suspicious_processes sp
                JOIN system_scans s ON sp.scan_id = s.scan_id
                WHERE s.user_id = ? AND sp.name = ?
                ORDER BY s.created_at DESC
                LIMIT 1
            """, (current_user["id"], process_name)).fetchone()
            
            if not threat_data:
                raise HTTPException(status_code=404, detail="Threat not found")
                
            resolution = get_threat_resolution("Suspicious Process", threat_data["threat_level"], f"Process: {process_name}")
            
            return {
                "id": threat_id,
                "type": "Suspicious Process",
                "name": process_name,
                "severity": threat_data["threat_level"],
                "riskScore": 90 if threat_data["threat_level"] == "critical" else 70,
                "detectedAt": threat_data["created_at"],
                "details": {
                    "processName": process_name,
                    "threatLevel": threat_data["threat_level"],
                    "scanId": threat_data["scan_id"]
                },
                "resolution": resolution,
                "isActive": True
            }
        
        elif threat_id.startswith("port_"):
            port_num = threat_id.replace("port_", "")
            threat_data = conn.execute("""
                SELECT rp.*, s.created_at, s.scan_id
                FROM risky_ports rp
                JOIN system_scans s ON rp.scan_id = s.scan_id
                WHERE s.user_id = ? AND rp.port = ?
                ORDER BY s.created_at DESC
                LIMIT 1
            """, (current_user["id"], port_num)).fetchone()
            
            if not threat_data:
                raise HTTPException(status_code=404, detail="Threat not found")
                
            resolution = get_threat_resolution("Risky Port", threat_data["threat_level"], f"Port: {port_num}")
            threat_dict = dict(threat_data)

            return {
                "id": threat_id,
                "type": "Risky Port",
                "name": f"Port {port_num}",
                "severity": threat_data["threat_level"],
                "riskScore": 80 if threat_data["threat_level"] == "critical" else 60,
                "detectedAt": threat_data["created_at"],
                "details": {
                    "port": port_num,
                    "service": threat_dict.get("service", "Unknown"),
                    "threatLevel": threat_data["threat_level"],
                    "scanId": threat_data["scan_id"]
                },
                "resolution": resolution,
                "isActive": True
            }
        
        elif threat_id.startswith("network_"):
            threat_data = conn.execute("""
                SELECT nc.*, s.created_at, s.scan_id
                FROM network_connections nc
                JOIN system_scans s ON nc.scan_id = s.scan_id
                WHERE s.user_id = ? AND nc.threat_level IN ('high', 'critical')
                ORDER BY s.created_at DESC
                LIMIT 1
            """, (current_user["id"],)).fetchone()
            
            if not threat_data:
                raise HTTPException(status_code=404, detail="Threat not found")
                
            resolution = get_threat_resolution("Suspicious Network Activity", threat_data["threat_level"], threat_data["activity_description"])
            
            return {
                "id": threat_id,
                "type": "Suspicious Network Activity",
                "name": "Network Connection",
                "severity": threat_data["threat_level"],
                "riskScore": 85 if threat_data["threat_level"] == "critical" else 65,
                "detectedAt": threat_data["created_at"],
                "details": {
                    "description": threat_data["activity_description"],
                    "threatLevel": threat_data["threat_level"],
                    "scanId": threat_data["scan_id"]
                },
                "resolution": resolution,
                "isActive": True
            }
        
    raise HTTPException(status_code=404, detail="Threat not found")

@app.post("/api/threat/{threat_id}/resolve")
async def resolve_threat(threat_id: str, current_user: dict = Depends(get_current_user)):
    """Mark a threat as resolved"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE threat_history
            SET is_resolved = 1
            WHERE id = ? AND user_id = ?
        """, (threat_id, current_user["id"]))
        
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Threat not found")

    return {
        "success": True,
        "message": "Threat marked as resolved",
        "threatId": threat_id,
        "resolvedAt": datetime.now(ist).isoformat()
    }

@app.post("/api/dashboard/reset")
async def reset_dashboard_data(current_user: dict = Depends(get_current_user)):
    """Reset/clear all scan data for the current user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        try:
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
            
            cursor.execute("DELETE FROM system_scans WHERE user_id = ?", (current_user["id"],))
            cursor.execute("DELETE FROM threat_history WHERE user_id = ?", (current_user["id"],))
            
            conn.commit()
            
        except Exception as e:
            conn.rollback()
            raise HTTPException(status_code=500, detail=f"Reset failed: {str(e)}")
        
    return {
        "success": True,
        "message": "Dashboard data reset successfully",
        "timestamp": datetime.now(ist).isoformat()
    }

@app.get("/api/dashboard/trends")
async def dashboard_trends(current_user: dict = Depends(get_current_user)):
    """Get threat trends data"""
    trends = []
    for hour in range(24):
        threats = random.randint(10, 50)
        blocked = random.randint(5, threats)
        trends.append({
            "time": f"{hour:02d}:00",
            "threats": threats,
            "blocked": blocked
        })
    
    return trends

# System Scanning Endpoints
@app.get("/api/test")
async def test_endpoint():
    """Test endpoint to verify backend is working"""
    return {"status": "Backend is working!", "timestamp": datetime.now(ist).isoformat()}

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "CyberNova AI Backend",
        "version": "1.0.0",
        "timestamp": datetime.now(ist).isoformat()
    }

@app.post("/api/scan/start")
async def start_scan(background_tasks: BackgroundTasks, current_user: dict = Depends(get_current_user)):
    """Start a manual system scan using real threat scanner"""
    try:
        # Call the real threat scanner from agent.py
        scan_data = perform_real_threat_scan()
        
        # Generate unique scan ID
        scan_id = f"scan_{int(time.time())}_{random.randint(1000, 9999)}"
        scan_data["scan_id"] = scan_id
        
        user_id = current_user["id"]
        system_info = json.dumps(scan_data.get("system_info", {}))
        threats_detected = scan_data.get("total_threats", 0)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Insert scan record
            cursor.execute(
                """
                INSERT INTO system_scans (scan_id, user_id, system_info, threats_detected, scan_status, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_id, user_id, system_info, threats_detected, "completed", (datetime.now(ist) + timedelta(hours=2)).isoformat())
            )

            # Insert suspicious processes
            for proc in scan_data.get("suspicious_processes", []):
                cursor.execute(
                    """
                    INSERT INTO suspicious_processes (scan_id, pid, name, cpu_percent, memory_percent, threat_level, threat_reasons, exe_path, cmdline, username)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        proc.get("pid"),
                        proc.get("name"),
                        proc.get("cpu_percent"),
                        proc.get("memory_percent"),
                        proc.get("threat_level"),
                        json.dumps(proc.get("threat_reasons", [])),
                        proc.get("exe_path"),
                        proc.get("cmdline"),
                        proc.get("username"),
                    )
                )

            # Insert network threats
            for nt in scan_data.get("network_threats", []):
                cursor.execute(
                    """
                    INSERT INTO network_connections (scan_id, local_ip, local_port, remote_ip, remote_port, status, pid, process_name, threat_level, activity_description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        nt.get("local_ip"),
                        nt.get("local_port"),
                        nt.get("remote_ip"),
                        nt.get("remote_port"),
                        nt.get("status"),
                        nt.get("pid"),
                        nt.get("process_name"),
                        nt.get("threat_level"),
                        nt.get("activity_description"),
                    )
                )

            # Insert risky ports
            for rp in scan_data.get("risky_ports", []):
                cursor.execute(
                    """
                    INSERT INTO risky_ports (scan_id, port, service, threat_level, reason)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        rp.get("port"),
                        rp.get("service"),
                        rp.get("threat_level"),
                        rp.get("reason"),
                    )
                )

            conn.commit()

        # Send email notification for high-severity threats
        high_threats = [p for p in scan_data.get("suspicious_processes", []) if p.get("threat_level", "").lower() in ["high", "critical"]]
        high_threats.extend([n for n in scan_data.get("network_threats", []) if n.get("threat_level", "").lower() in ["high", "critical"]])
        high_threats.extend([r for r in scan_data.get("risky_ports", []) if r.get("threat_level", "").lower() in ["high", "critical"]])
        
        if high_threats and background_tasks:
            threat_summary = f"Detected {len(high_threats)} high/critical threats in scan {scan_id}"
            background_tasks.add_task(
                send_email,
                current_user["email"],
                f"Security Alert: {len(high_threats)} Threats Detected",
                threat_summary
            )

        # Broadcast over websocket
        await manager.broadcast(json.dumps({
            "type": "scan_completed", 
            "data": {
                "scan_id": scan_id, 
                "threats_detected": threats_detected,
                "timestamp": datetime.now(ist).isoformat(),
                "user_id": current_user["id"],
            }
        }))

        return {
            "status": "success",
            "scan_id": scan_id,
            "threats_detected": threats_detected,
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.get("/api/scan/latest")
async def get_latest_scan(current_user: dict = Depends(get_current_user)):
    """Get latest scan results"""
    with get_db_connection() as conn:
        # Get latest scan
        scan = conn.execute("""
            SELECT * FROM system_scans 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 1
        """, (current_user["id"],)).fetchone()
        
        if not scan:
            return {"message": "No scans found"}
        
        # Get scan details
        connections = conn.execute("""
            SELECT * FROM network_connections 
            WHERE scan_id = ?
        """, (scan["scan_id"],)).fetchall()
        
        processes = conn.execute("""
            SELECT * FROM suspicious_processes 
            WHERE scan_id = ?
        """, (scan["scan_id"],)).fetchall()
        
        ports = conn.execute("""
            SELECT * FROM risky_ports 
            WHERE scan_id = ?
        """, (scan["scan_id"],)).fetchall()
        
        recommendations = conn.execute("""
            SELECT * FROM security_recommendations 
            WHERE scan_id = ?
        """, (scan["scan_id"],)).fetchall()

    # Transform data for frontend compatibility
    transformed_connections = []
    for conn in connections:
        conn_dict = dict(conn)
        conn_dict["activity_name"] = conn_dict.get("activity_description", "Network Activity")
        conn_dict["website"] = conn_dict.get("hostname", "Unknown")
        conn_dict["description"] = f"Network connection to {conn_dict.get('hostname', 'unknown host')}"
        conn_dict["how_occurred"] = "Established during normal system operation"
        conn_dict["why_dangerous"] = "Potentially suspicious network activity detected"
        conn_dict["immediate_impact"] = "May indicate security compromise"
        transformed_connections.append(conn_dict)
    
    transformed_processes = []
    for proc in processes:
        proc_dict = dict(proc)
        # Parse JSON fields if they exist
        if proc_dict.get("threat_reasons"):
            try:
                proc_dict["threat_indicators"] = json.loads(proc_dict["threat_reasons"])
            except:
                proc_dict["threat_indicators"] = [proc_dict.get("threat_reasons", "")]
        
        # Add missing fields for frontend
        proc_dict["description"] = f"Suspicious process: {proc_dict.get('name', 'Unknown')}"
        proc_dict["how_occurred"] = "Process started by malicious software or user action"
        proc_dict["why_dangerous"] = "This process may be performing malicious activities"
        proc_dict["immediate_impact"] = "System security may be compromised"
        proc_dict["first_seen"] = proc_dict.get("created_at", "Unknown")
        transformed_processes.append(proc_dict)

    return {
        "scan_info": dict(scan),
        "system_info": json.loads(scan["system_info"]) if scan["system_info"] else {},
        "network_connections": transformed_connections,
        "suspicious_processes": transformed_processes,
        "risky_ports": [dict(row) for row in ports],
        "recommendations": [dict(row) for row in recommendations]
    }

@app.post("/api/real-scan/results")
async def receive_scan_results(scan_data: dict, current_user=Depends(get_current_user), background_tasks: BackgroundTasks = None):
    """Receive real scan results from external agent"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            user_id = current_user["id"]
            scan_id = f"scan_{int(time.time())}_{random.randint(1000,9999)}"

            # Cleanup old scans for this user (older than 1 minute)
            cursor.execute("""
                DELETE FROM suspicious_processes WHERE scan_id IN (
                    SELECT scan_id FROM system_scans WHERE user_id = ? AND created_at < datetime('now', '-1 minutes')
                )
            """, (user_id,))

            cursor.execute("""
                DELETE FROM network_connections WHERE scan_id IN (
                    SELECT scan_id FROM system_scans WHERE user_id = ? AND created_at < datetime('now', '-1 minutes')
                )
            """, (user_id,))

            cursor.execute("""
                DELETE FROM risky_ports WHERE scan_id IN (
                    SELECT scan_id FROM system_scans WHERE user_id = ? AND created_at < datetime('now', '-1 minutes')
                )
            """, (user_id,))

            cursor.execute("""
                DELETE FROM system_scans WHERE user_id = ? AND created_at < datetime('now', '-1 minutes')
            """, (user_id,))

            # Insert main scan record
            cursor.execute("""
                INSERT INTO system_scans (scan_id, user_id, system_info, threats_detected, scan_status, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                user_id,
                json.dumps(scan_data.get("system_info", {})),
                scan_data.get("total_threats", 0),
                "completed",
                (datetime.now(ist) + timedelta(hours=1)).isoformat(),
            ))

            # Insert suspicious processes
            for proc in scan_data.get("suspicious_processes", []):
                cursor.execute("""
                    INSERT INTO suspicious_processes (scan_id, pid, name, cpu_percent, memory_percent,
                    threat_level, threat_reasons, exe_path, cmdline, username)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    proc.get("pid"),
                    proc.get("name"),
                    proc.get("cpu_percent"),
                    proc.get("memory_percent"),
                    proc.get("threat_level"),
                    json.dumps(proc.get("threat_reasons", [])),
                    proc.get("exe_path"),
                    proc.get("cmdline"),
                    proc.get("username"),
                ))

            # Insert network threats
            for nt in scan_data.get("network_threats", []):
                cursor.execute("""
                    INSERT INTO network_connections (scan_id, local_ip, local_port, remote_ip, remote_port,
                    hostname, activity_description, status, pid, process_name, threat_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    nt.get("local_ip"),
                    nt.get("local_port"),
                    nt.get("remote_ip"),
                    nt.get("remote_port"),
                    nt.get("hostname"),
                    nt.get("activity_description"),
                    nt.get("status"),
                    nt.get("pid"),
                    nt.get("process_name"),
                    nt.get("threat_level"),
                ))

            # Insert risky ports
            for rp in scan_data.get("risky_ports", []):
                cursor.execute("""
                    INSERT INTO risky_ports (scan_id, port, service, threat_level, reason)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    rp.get("port"),
                    rp.get("service"),
                    rp.get("threat_level"),
                    rp.get("reason"),
                ))

            conn.commit()

        # Broadcast update over websocket
        await manager.broadcast(json.dumps({
            "type": "scan_completed",
            "data": {
                "scan_id": scan_id,
                "threats_detected": scan_data.get("total_threats", 0),
                "timestamp": datetime.now(ist).isoformat(),
                "user_id": current_user["id"]
            }
        }))

        return {
            "status": "success",
            "scan_id": scan_id,
            "threats_detected": scan_data.get("total_threats", 0),
            "message": "Scan results successfully processed and saved"
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed processing scan results: {str(e)}")

# WebSocket endpoint
@app.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time threat updates"""
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(5)
            
            # Send periodic updates
            if random.random() < 0.3:  # 30% chance of new threat
                threat_update = {
                    "type": "threat_update",
                    "data": {
                        "threat_type": random.choice(["Malware", "Phishing", "DDoS", "Brute Force"]),
                        "severity": random.choice(["low", "medium", "high", "critical"]),
                        "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                        "risk_score": random.randint(20, 95),
                        "timestamp": datetime.now(ist).isoformat()
                    }
                }
                await manager.send_personal_message(json.dumps(threat_update), websocket)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)# Background cleanup and monitoring functions
async def cleanup_expired_data():
    """Clean up expired scan data every hour and prevent duplicates"""
    while True:
        try:
            await asyncio.sleep(1800)  # Run every 30 minutes
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Clean up old scans (keep only last 2 hours)
                cursor.execute("DELETE FROM system_scans WHERE created_at < datetime('now', '-2 hours')")
                
                # Clean up orphaned data
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
                
                # Remove duplicate threat history entries
                cursor.execute("""
                    DELETE FROM threat_history 
                    WHERE id NOT IN (
                        SELECT MIN(id) FROM threat_history 
                        GROUP BY user_id, threat_type, description
                    )
                """)
                
                # Keep only recent threat history (last 24 hours)
                cursor.execute("""
                    DELETE FROM threat_history 
                    WHERE detected_at < datetime('now', '-24 hours')
                """)
                
                conn.commit()
                
            print(f"Cleanup completed at {datetime.now(ist)}")
                
        except Exception as e:
            print(f"Cleanup error: {e}")

# Additional utility endpoints
@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Get the status of a specific scan"""
    with get_db_connection() as conn:
        scan = conn.execute("""
            SELECT * FROM system_scans 
            WHERE scan_id = ? AND user_id = ?
        """, (scan_id, current_user["id"])).fetchone()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": scan["scan_id"],
        "status": scan["scan_status"],
        "threats_detected": scan["threats_detected"],
        "created_at": scan["created_at"]
    }

@app.delete("/api/scan/reset")
async def reset_scan_data(current_user: dict = Depends(get_current_user)):
    """Reset all scan data for the current user"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get all scan IDs for this user
            scan_ids = cursor.execute("""
                SELECT scan_id FROM system_scans WHERE user_id = ?
            """, (current_user["id"],)).fetchall()
            
            # Delete all related data
            for scan_row in scan_ids:
                scan_id = scan_row["scan_id"]
                cursor.execute("DELETE FROM suspicious_processes WHERE scan_id = ?", (scan_id,))
                cursor.execute("DELETE FROM network_connections WHERE scan_id = ?", (scan_id,))
                cursor.execute("DELETE FROM risky_ports WHERE scan_id = ?", (scan_id,))
                cursor.execute("DELETE FROM security_recommendations WHERE scan_id = ?", (scan_id,))
            
            # Delete scan records
            cursor.execute("DELETE FROM system_scans WHERE user_id = ?", (current_user["id"],))
            cursor.execute("DELETE FROM threat_history WHERE user_id = ?", (current_user["id"],))
            
            conn.commit()
        
        return {
            "status": "success",
            "message": "All scan data has been reset successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset scan data: {str(e)}")

@app.post("/api/admin/clear-all-mock-data")
async def clear_all_mock_data():
    """Clear all data from the database (public endpoint for demo)"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Clear all tables
            cursor.execute("DELETE FROM suspicious_processes")
            cursor.execute("DELETE FROM network_connections") 
            cursor.execute("DELETE FROM risky_ports")
            cursor.execute("DELETE FROM security_recommendations")
            cursor.execute("DELETE FROM system_scans")
            cursor.execute("DELETE FROM threat_history")
            
            conn.commit()
        
        return {
            "status": "success",
            "message": "All data has been cleared successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear data: {str(e)}")

@app.get("/api/admin/stats")
async def admin_stats():
    """Admin statistics (public endpoint for demo)"""
    with get_db_connection() as conn:
        stats = {
            "total_users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "waitlist_count": conn.execute("SELECT COUNT(*) FROM waitlist").fetchone()[0],
            "total_scans": conn.execute("SELECT COUNT(*) FROM system_scans").fetchone()[0],
            "active_connections": len(manager.active_connections)
        }
    
    return stats

# Health and monitoring endpoints
@app.get("/health")
async def health():
    """Health check endpoint"""
    with get_db_connection() as conn:
        try:
            conn.execute("SELECT 1").fetchone()
            db_status = "healthy"
        except:
            db_status = "unhealthy"
    
    return {
        "status": "healthy",
        "timestamp": datetime.now(ist).isoformat(),
        "database": db_status,
        "version": "3.0",
        "services": {
            "authentication": "active",
            "threat_detection": "active",
            "analytics": "active",
            "websocket": "active"
        }
    }

# Fixed Appwrite integration functions
# Replace the existing Appwrite functions with these corrected versions:

async def create_user_in_appwrite(email: str, password: str, name: str) -> dict:
    """Create user in Appwrite - fixed for proper API usage"""
    try:
        import uuid
        user_id = str(uuid.uuid4())
        
        # Create user with proper Appwrite API
        user = users_service.create(
            user_id=user_id,
            email=email,
            password=password,
            name=name
        )
        return {"success": True, "user": user}
    
    except AppwriteException as e:
        print(f"Appwrite user creation error: {e}")
        return {"success": False, "error": str(e)}
    except Exception as e:
        print(f"General error creating user: {e}")
        return {"success": False, "error": str(e)}

async def get_appwrite_users():
    """Get users from Appwrite - fixed for proper API usage"""
    try:
        # Use proper list method without any parameters that might cause request body issues
        users_list = users_service.list()
        return {"success": True, "users": users_list}
    
    except AppwriteException as e:
        print(f"Appwrite list users error: {e}")
        return {"success": False, "error": str(e)}
    except Exception as e:
        print(f"General error listing users: {e}")
        return {"success": False, "error": str(e)}
# Enhanced threat analytics endpoint
@app.get("/api/threats/analytics")
async def threat_analytics(current_user: dict = Depends(get_current_user)):
    """Get threat analytics and AI insights"""
    with get_db_connection() as conn:
        # Get recent scan data for analytics
        recent_scans = conn.execute("""
            SELECT * FROM system_scans 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 10
        """, (current_user["id"],)).fetchall()
        
        if not recent_scans:
            return {
                "threat_types": [],
                "severity_distribution": [],
                "risk_assessment": {
                    "overall_risk_score": 0,
                    "max_risk_score": 0,
                    "high_risk_count": 0,
                    "risk_level": "low",
                    "recommendations": ["No scan data available yet. Run a security scan to get insights."]
                },
                "predictions": []
            }
        
        # Calculate threat distribution from actual scan data
        latest_scan = recent_scans[0]
        scan_id = latest_scan["scan_id"]
        
        # Get threat counts by type
        process_count = conn.execute("""
            SELECT COUNT(*) as count FROM suspicious_processes WHERE scan_id = ?
        """, (scan_id,)).fetchone()["count"]
        
        port_count = conn.execute("""
            SELECT COUNT(*) as count FROM risky_ports WHERE scan_id = ?
        """, (scan_id,)).fetchone()["count"]
        
        network_count = conn.execute("""
            SELECT COUNT(*) as count FROM network_connections WHERE scan_id = ?
        """, (scan_id,)).fetchone()["count"]
        
        threat_types = []
        if process_count > 0:
            threat_types.append({"threat_type": "Suspicious Processes", "count": process_count})
        if port_count > 0:
            threat_types.append({"threat_type": "Risky Ports", "count": port_count})
        if network_count > 0:
            threat_types.append({"threat_type": "Network Threats", "count": network_count})
        
        # Get severity distribution from latest scan
        severity_dist = []
        for severity in ["low", "medium", "high", "critical"]:
            total_severity_count = 0
            
            # Count processes with this severity
            proc_severity = conn.execute("""
                SELECT COUNT(*) as count FROM suspicious_processes 
                WHERE scan_id = ? AND threat_level = ?
            """, (scan_id, severity)).fetchone()["count"]
            total_severity_count += proc_severity
            
            # Count ports with this severity
            port_severity = conn.execute("""
                SELECT COUNT(*) as count FROM risky_ports 
                WHERE scan_id = ? AND threat_level = ?
            """, (scan_id, severity)).fetchone()["count"]
            total_severity_count += port_severity
            
            # Count network connections with this severity
            network_severity = conn.execute("""
                SELECT COUNT(*) as count FROM network_connections 
                WHERE scan_id = ? AND threat_level = ?
            """, (scan_id, severity)).fetchone()["count"]
            total_severity_count += network_severity
            
            if total_severity_count > 0:
                severity_dist.append({"severity": severity, "count": total_severity_count})
        
        # Calculate risk assessment
        total_threats = latest_scan["threats_detected"] or 0
        high_critical_count = sum([s["count"] for s in severity_dist if s["severity"] in ["high", "critical"]])
        
        avg_risk = min(100, max(0, total_threats * 15))
        risk_level = "critical" if avg_risk > 80 else "high" if avg_risk > 50 else "medium" if avg_risk > 20 else "low"
        
        # Generate recommendations based on actual scan data
        recommendations = []
        if high_critical_count > 0:
            recommendations.append("Immediate action required - Critical threats detected")
            recommendations.append("Review and terminate suspicious processes")
            recommendations.append("Secure exposed ports and services")
        elif total_threats > 5:
            recommendations.append("Multiple security issues detected - Schedule maintenance")
            recommendations.append("Update security software and patches")
        else:
            recommendations.append("Security posture is acceptable")
            recommendations.append("Continue regular monitoring")
    
    return {
        "threat_types": threat_types,
        "severity_distribution": severity_dist,
        "risk_assessment": {
            "overall_risk_score": round(float(avg_risk), 2),
            "max_risk_score": 100,
            "high_risk_count": high_critical_count,
            "risk_level": risk_level,
            "recommendations": recommendations
        },
        "predictions": generate_threat_predictions()
    }

def generate_threat_predictions():
    """Generate threat prediction data based on trends"""
    predictions = []
    base_time = datetime.now(ist)
    
    for i in range(24):  # Next 24 hours
        time_point = base_time + timedelta(hours=i)
        predicted_count = random.randint(5, 25)
        
        predictions.append({
            "time": time_point.isoformat(),
            "predicted_threat_count": predicted_count,
            "confidence": round(random.uniform(0.7, 0.95), 2)
        })
    
    return predictions

# Real-time system information endpoints
@app.get("/api/system/info")
async def get_system_info():
    """Get real-time system information"""
    try:
        # Call the real system info function from agent
        system_info = get_real_system_info()
        return {
            "status": "success",
            "data": system_info,
            "timestamp": datetime.now(ist).isoformat()
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to get system info: {str(e)}",
            "timestamp": datetime.now(ist).isoformat()
        }

@app.get("/api/system/processes")
async def get_system_processes():
    """Get real-time process information"""
    try:
        # Call the real process scanner from agent
        processes = scan_real_processes()
        return {
            "status": "success",
            "data": processes,
            "timestamp": datetime.now(ist).isoformat()
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to get process info: {str(e)}",
            "timestamp": datetime.now(ist).isoformat()
        }

@app.get("/api/system/network")
async def get_network_connections():
    """Get real-time network connection information"""
    try:
        # Call the real network scanner from agent
        connections = scan_real_network_connections()
        return {
            "status": "success",
            "data": connections,
            "timestamp": datetime.now(ist).isoformat()
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to get network info: {str(e)}",
            "timestamp": datetime.now(ist).isoformat()
        }

@app.get("/api/system/ports")
async def get_open_ports():
    """Get real-time open ports information"""
    try:
        # Call the real port scanner from agent
        ports = scan_real_open_ports()
        return {
            "status": "success",
            "data": ports,
            "timestamp": datetime.now(ist).isoformat()
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to get port info: {str(e)}",
            "timestamp": datetime.now(ist).isoformat()
        }

# Initialize database and start background tasks
async def startup_cleanup():
    """One-time cleanup of all data on startup"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            print("Cleaning up old data on startup...")
            
            # Remove all old scan data to start fresh
            cursor.execute("DELETE FROM network_connections")
            cursor.execute("DELETE FROM suspicious_processes") 
            cursor.execute("DELETE FROM risky_ports")
            cursor.execute("DELETE FROM security_recommendations")
            cursor.execute("DELETE FROM system_scans WHERE created_at < datetime('now', '-1 hour')")
            cursor.execute("DELETE FROM threat_history WHERE detected_at < datetime('now', '-1 hour')")
            
            conn.commit()
            
        print("Startup cleanup completed successfully")
        
    except Exception as e:
        print(f"Startup cleanup error: {e}")

@app.on_event("startup")
async def startup_event():
    """Initialize database and start background tasks"""
    try:
        # Initialize database
        init_database()
        print("CyberNova AI Backend Starting...")
        print("Email Service: cybernova073@gmail.com")
        print("Launch Date: September 15, 2025")
        print("Threat detection engine started")
        
        # Clean up any existing data first
        await startup_cleanup()
        
        # Start background cleanup task
        asyncio.create_task(cleanup_expired_data())
        print("Background tasks started successfully")
        
    except Exception as e:
        print(f"Startup failed: {e}")
        import traceback
        traceback.print_exc()

# Legacy compatibility endpoints (for backward compatibility)
@app.get("/api/threats/stats")
async def legacy_threat_stats():
    """Legacy endpoint for threat statistics"""
    return {
        "totalThreats": 0,
        "blockedThreats": 0,
        "criticalThreats": 0,
        "averageRiskScore": 0.0
    }

# Main application entry point
if __name__ == "__main__":
    import uvicorn
    import socket
    import psutil
    import platform
    
    # Support deployment platforms that use PORT environment variable
    port = int(os.getenv("PORT", 8080))
    print("Starting CyberNova AI Backend...")
    print(f"Server will be available at: http://localhost:{port}")
    print(f"API Documentation: http://localhost:{port}/docs")
    print(f"Health Check: http://localhost:{port}/api/health")
    
    # Print system info for debugging
    print(f"System: {platform.system()} {platform.release()}")
    print(f"Python: {platform.python_version()}")
    print(f"Hostname: {socket.gethostname()}")
    
    uvicorn.run(app, host="0.0.0.0", port=port)
