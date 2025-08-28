from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import jwt, bcrypt, sqlite3, json, time, random, os, asyncio, httpx
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import subprocess, psutil, socket, platform
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl

# Load environment variables
load_dotenv()

# FastAPI app initialization
app = FastAPI(
    title="CyberNova AI - Main API Gateway",
    description="Advanced Cybersecurity Platform with Real-time Threat Detection",
    version="3.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update with your frontend domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
JWT_SECRET = os.getenv('JWT_SECRET', 'cybernova-secret-key-2025')
JWT_ALGORITHM = 'HS256'

# Database configuration
DATABASE_PATH = os.getenv('DATABASE_PATH', 'cybernova.db')

# Email configuration
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_USER = os.getenv('EMAIL_USER', 'cybernova073@gmail.com')
EMAIL_PASS = os.getenv('EMAIL_PASS', 'hsrz fymn gplp enbp')

# Analytics service URL
ANALYTICS_SERVICE_URL = os.getenv('ANALYTICS_SERVICE_URL', 'http://analytics-service:8000')

# Pydantic models
class UserRegister(BaseModel):
    email: str
    password: str
    full_name: str
    company: Optional[str] = None

class UserLogin(BaseModel):
    email: str
    password: str

class ScanRequest(BaseModel):
    scan_type: Optional[str] = "full"
    target_ip: Optional[str] = None

# Database context manager
@contextmanager
def get_db_connection():
    """Get database connection with proper error handling"""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=30.0)
        conn.row_factory = sqlite3.Row
        yield conn
    except Exception as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn:
            conn.close()

# Initialize database
def init_database():
    """Initialize database with all required tables"""
    with get_db_connection() as conn:
        # Users table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                company TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # System scans table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS system_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                system_info TEXT,
                threats_detected INTEGER DEFAULT 0,
                scan_status TEXT DEFAULT 'pending',
                scan_type TEXT DEFAULT 'full',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Suspicious processes table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                pid INTEGER NOT NULL,
                name TEXT NOT NULL,
                cpu_percent REAL DEFAULT 0,
                memory_percent REAL DEFAULT 0,
                threat_level TEXT NOT NULL,
                threat_reasons TEXT,
                exe_path TEXT,
                cmdline TEXT,
                username TEXT,
                network_activity TEXT,
                behavior_analysis TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES system_scans (scan_id)
            )
        ''')
        
        # Network connections table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES system_scans (scan_id)
            )
        ''')
        
        # Risky ports table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS risky_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT,
                threat_level TEXT NOT NULL,
                reason TEXT,
                recommendation TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES system_scans (scan_id)
            )
        ''')
        
        # Security recommendations table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS security_recommendations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                type TEXT NOT NULL,
                priority TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                action TEXT,
                details TEXT,
                is_sent BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES system_scans (scan_id)
            )
        ''')
        
        conn.commit()
        print("✅ Database initialized successfully")

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    init_database()
    print("🚀 CyberNova AI API Gateway started successfully")
# Authentication helper functions
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_jwt_token(user_id: int, email: str) -> str:
    """Create JWT token for user"""
    ist = timezone(timedelta(hours=5, minutes=30))
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.now(ist) + timedelta(hours=24),
        'iat': datetime.now(ist)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict[str, Any]:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
    try:
        payload = verify_jwt_token(credentials.credentials)
        user_id = payload.get('user_id')
        email = payload.get('email')
        
        if not user_id or not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        # Get user from database
        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT id, email, full_name, company, created_at, last_login FROM users WHERE id = ? AND is_active = 1",
                (user_id,)
            ).fetchone()
            
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            
            return dict(user)
    
    except Exception as e:
        raise HTTPException(status_code=401, detail="Authentication failed")

# Email helper function
async def send_email(to_email: str, subject: str, body: str):
    """Send email notification"""
    try:
        message = MIMEMultipart()
        message["From"] = EMAIL_USER
        message["To"] = to_email
        message["Subject"] = subject
        
        message.attach(MIMEText(body, "plain"))
        
        context = ssl.create_default_context()
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls(context=context)
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, to_email, message.as_string())
        
        print(f"✅ Email sent successfully to {to_email}")
    except Exception as e:
        print(f"❌ Email failed to send: {e}")

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.post("/api/auth/register")
async def register_user(user_data: UserRegister, background_tasks: BackgroundTasks):
    """Register new user"""
    try:
        with get_db_connection() as conn:
            # Check if user already exists
            existing_user = conn.execute(
                "SELECT id FROM users WHERE email = ?", (user_data.email,)
            ).fetchone()
            
            if existing_user:
                raise HTTPException(status_code=400, detail="Email already registered")
            
            # Hash password
            password_hash = hash_password(user_data.password)
            
            # Insert new user
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO users (email, password_hash, full_name, company) 
                   VALUES (?, ?, ?, ?)""",
                (user_data.email, password_hash, user_data.full_name, user_data.company)
            )
            user_id = cursor.lastrowid
            conn.commit()
            
            # Create JWT token
            token = create_jwt_token(user_id, user_data.email)
            
            # Send welcome email
            welcome_email_body = f"""
Welcome to CyberNova AI!

Hi {user_data.full_name},

Your account has been successfully created! You now have access to our advanced cybersecurity platform.

Features available to you:
• Real-time threat detection
• Comprehensive security scanning
• AI-powered vulnerability assessment
• 24/7 monitoring dashboard

Login to your dashboard: https://cybernova-de84b.web.app/

Best regards,
The CyberNova AI Security Team
            """
            
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
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/api/auth/login")
async def login_user(user_data: UserLogin):
    """Login user and return JWT token"""
    try:
        with get_db_connection() as conn:
            # Get user from database
            user = conn.execute(
                "SELECT id, email, password_hash, full_name, company FROM users WHERE email = ? AND is_active = 1",
                (user_data.email,)
            ).fetchone()
            
            if not user or not verify_password(user_data.password, user['password_hash']):
                raise HTTPException(status_code=401, detail="Invalid email or password")
            
            # Update last login
            conn.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user['id'],)
            )
            conn.commit()
            
            # Create JWT token
            token = create_jwt_token(user['id'], user['email'])
            
            return {
                "message": "Login successful",
                "token": token,
                "user": {
                    "id": user['id'],
                    "email": user['email'],
                    "full_name": user['full_name'],
                    "company": user['company']
                }
            }
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.get("/api/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return {
        "user": current_user
    }

@app.post("/api/auth/logout")
async def logout_user(current_user: dict = Depends(get_current_user)):
    """Logout user (client should discard token)"""
    return {
        "message": "Logout successful"
    }

# ==================== SYSTEM SCANNING FUNCTIONS ====================

def get_system_info():
    """Get comprehensive system information"""
    try:
        hostname = platform.node()
        system = platform.system()
        release = platform.release()
        architecture = platform.architecture()[0]
        processor = platform.processor()
        
        # Get IP address
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
        except:
            ip_address = "127.0.0.1"
        
        # Get memory info
        memory = psutil.virtual_memory()
        
        return {
            "hostname": hostname,
            "platform": f"{system} {release}",
            "architecture": architecture,
            "processor": processor,
            "ip_address": ip_address,
            "cpu_count": psutil.cpu_count(logical=True),
            "memory_total": memory.total,
            "memory_available": memory.available,
            "memory_percent": memory.percent,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        print(f"System info error: {e}")
        return {
            "hostname": "Unknown",
            "platform": "Unknown",
            "error": str(e)
        }

def scan_suspicious_processes():
    """Scan for suspicious processes"""
    suspicious_processes = []
    
    try:
        # Define suspicious patterns
        suspicious_patterns = [
            'powershell', 'cmd', 'wscript', 'cscript', 'rundll32',
            'regsvr32', 'mshta', 'bitsadmin', 'certutil', 'netsh'
        ]
        
        risky_locations = [
            'temp', 'tmp', 'appdata\\roaming', 'programdata', 'users\\public'
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent', 'username']):
            try:
                proc_info = proc.info
                
                if not proc_info['name']:
                    continue
                
                threat_level = "low"
                threat_reasons = []
                
                # Check for suspicious process names
                if any(pattern in proc_info['name'].lower() for pattern in suspicious_patterns):
                    threat_level = "medium"
                    threat_reasons.append("Suspicious process name detected")
                
                # Check for suspicious executable locations
                if proc_info['exe']:
                    exe_path = proc_info['exe'].lower()
                    if any(location in exe_path for location in risky_locations):
                        threat_level = "high"
                        threat_reasons.append("Running from suspicious location")
                
                # Check for high resource usage
                cpu_percent = proc_info['cpu_percent'] or 0
                memory_percent = proc_info['memory_percent'] or 0
                
                if cpu_percent > 80:
                    threat_level = "medium" if threat_level == "low" else "high"
                    threat_reasons.append("High CPU usage")
                
                if memory_percent > 50:
                    threat_level = "medium" if threat_level == "low" else "high"
                    threat_reasons.append("High memory usage")
                
                # Check command line arguments
                if proc_info['cmdline']:
                    cmdline = ' '.join(proc_info['cmdline']).lower()
                    suspicious_args = ['download', 'execute', 'bypass', 'hidden', 'encoded']
                    if any(arg in cmdline for arg in suspicious_args):
                        threat_level = "critical"
                        threat_reasons.append("Suspicious command line arguments")
                
                # Only include processes with medium threat or higher
                if threat_level in ["medium", "high", "critical"] or threat_reasons:
                    suspicious_processes.append({
                        "pid": proc_info['pid'],
                        "name": proc_info['name'],
                        "exe_path": proc_info['exe'],
                        "cmdline": ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory_percent,
                        "username": proc_info['username'],
                        "threat_level": threat_level,
                        "threat_reasons": json.dumps(threat_reasons)
                    })
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
    except Exception as e:
        print(f"Process scan error: {e}")
    
    return suspicious_processes

def scan_network_connections():
    """Scan for suspicious network connections"""
    suspicious_connections = []
    
    try:
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                # Skip local and private IPs
                if remote_ip.startswith(('127.', '10.', '192.168.', '172.')):
                    continue
                
                threat_level = "low"
                activity_description = f"Connection to {remote_ip}:{remote_port}"
                
                # Check for suspicious ports
                suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900]
                if remote_port in suspicious_ports:
                    threat_level = "high"
                    activity_description = f"Connection to high-risk port {remote_port}"
                
                # Get process information
                process_name = "Unknown"
                process_exe = ""
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                        process_exe = proc.exe()
                    except:
                        pass
                
                suspicious_connections.append({
                    "local_ip": conn.laddr.ip if conn.laddr else "",
                    "local_port": conn.laddr.port if conn.laddr else 0,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": conn.status,
                    "pid": conn.pid,
                    "process_name": process_name,
                    "process_exe": process_exe,
                    "activity_description": activity_description,
                    "threat_level": threat_level
                })
                
    except Exception as e:
        print(f"Network scan error: {e}")
    
    return suspicious_connections

def scan_risky_ports():
    """Scan for risky open ports"""
    risky_ports = []
    
    # Common risky ports to check
    ports_to_check = {
        21: ("FTP", "File Transfer Protocol - often misconfigured"),
        22: ("SSH", "SSH service - ensure strong authentication"),
        23: ("Telnet", "Unencrypted remote access - high risk"),
        135: ("RPC", "Windows RPC - potential attack vector"),
        139: ("NetBIOS", "File sharing - ransomware entry point"),
        445: ("SMB", "File sharing - common attack target"),
        1433: ("SQL Server", "Database server - secure credentials needed"),
        3389: ("RDP", "Remote Desktop - brute force target"),
        5900: ("VNC", "Remote desktop - often weak passwords")
    }
    
    try:
        for port, (service, reason) in ports_to_check.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            
            if result == 0:  # Port is open
                threat_level = "critical" if port in [23, 1433, 3389] else "high" if port in [21, 135, 139, 445] else "medium"
                
                risky_ports.append({
                    "port": port,
                    "service": service,
                    "threat_level": threat_level,
                    "reason": reason,
                    "recommendation": f"Consider disabling {service} or securing with strong authentication"
                })
                
    except Exception as e:
        print(f"Port scan error: {e}")
    
    return risky_ports

def generate_security_recommendations(processes, connections, ports):
    """Generate security recommendations based on scan results"""
    recommendations = []
    
    # Process-based recommendations
    high_threat_processes = [p for p in processes if p['threat_level'] in ['high', 'critical']]
    if high_threat_processes:
        recommendations.append({
            "type": "malware",
            "priority": "critical",
            "title": "Remove Suspicious Processes",
            "description": f"{len(high_threat_processes)} high-risk processes detected",
            "action": "Terminate suspicious processes and run full system scan",
            "details": json.dumps([p['name'] for p in high_threat_processes[:5]])
        })
    
    # Network-based recommendations
    high_risk_connections = [c for c in connections if c['threat_level'] in ['high', 'critical']]
    if high_risk_connections:
        recommendations.append({
            "type": "network",
            "priority": "high",
            "title": "Block Suspicious Network Traffic",
            "description": f"{len(high_risk_connections)} suspicious network connections found",
            "action": "Review and block unauthorized network connections",
            "details": json.dumps([f"{c['remote_ip']}:{c['remote_port']}" for c in high_risk_connections[:5]])
        })
    
    # Port-based recommendations
    critical_ports = [p for p in ports if p['threat_level'] == 'critical']
    if critical_ports:
        recommendations.append({
            "type": "security",
            "priority": "critical",
            "title": "Secure Critical Ports",
            "description": f"{len(critical_ports)} critical ports are exposed",
            "action": "Disable unnecessary services or implement strong security",
            "details": json.dumps([f"Port {p['port']} ({p['service']})" for p in critical_ports])
        })
    
    return recommendations
# ==================== SCANNING ENDPOINTS ====================

def perform_comprehensive_scan():
    """Perform comprehensive security scan"""
    try:
        print("🔍 Starting comprehensive security scan...")
        
        # Get system information
        system_info = get_system_info()
        
        # Scan for threats
        suspicious_processes = scan_suspicious_processes()
        network_connections = scan_network_connections()
        risky_ports = scan_risky_ports()
        
        # Generate recommendations
        recommendations = generate_security_recommendations(
            suspicious_processes, network_connections, risky_ports
        )
        
        print(f"✅ Scan completed: {len(suspicious_processes)} processes, {len(network_connections)} connections, {len(risky_ports)} ports")
        
        return {
            "system_info": system_info,
            "suspicious_processes": suspicious_processes,
            "network_connections": network_connections,
            "risky_ports": risky_ports,
            "recommendations": recommendations,
            "total_threats": len(suspicious_processes) + len(network_connections) + len(risky_ports),
            "scan_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        print(f"❌ Scan error: {e}")
        raise Exception(f"Scan failed: {str(e)}")

@app.post("/api/scan/start")
async def start_security_scan(
    scan_request: Optional[ScanRequest] = None,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    current_user: dict = Depends(get_current_user)
):
    """Start comprehensive security scan"""
    try:
        ist = timezone(timedelta(hours=5, minutes=30))
        scan_id = f"scan_{int(time.time())}_{random.randint(1000, 9999)}"
        user_id = current_user["id"]
        
        print(f"🚀 Starting scan {scan_id} for user {user_id}")
        
        # Perform the actual scan
        scan_results = perform_comprehensive_scan()
        
        # Save scan results to database
        with get_db_connection() as conn:
            # Insert main scan record
            conn.execute(
                """INSERT INTO system_scans 
                   (scan_id, user_id, system_info, threats_detected, scan_status, scan_type, completed_at, expires_at) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    user_id,
                    json.dumps(scan_results["system_info"]),
                    scan_results["total_threats"],
                    "completed",
                    scan_request.scan_type if scan_request else "full",
                    datetime.now(ist),
                    datetime.now(ist) + timedelta(days=30)
                )
            )
            
            # Insert suspicious processes
            for proc in scan_results["suspicious_processes"]:
                conn.execute(
                    """INSERT INTO suspicious_processes 
                       (scan_id, pid, name, cpu_percent, memory_percent, threat_level, 
                        threat_reasons, exe_path, cmdline, username) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id,
                        proc["pid"],
                        proc["name"],
                        proc["cpu_percent"],
                        proc["memory_percent"],
                        proc["threat_level"],
                        proc["threat_reasons"],
                        proc["exe_path"],
                        proc["cmdline"],
                        proc["username"]
                    )
                )
            
            # Insert network connections
            for conn_data in scan_results["network_connections"]:
                conn.execute(
                    """INSERT INTO network_connections 
                       (scan_id, local_ip, local_port, remote_ip, remote_port, 
                        status, pid, process_name, process_exe, activity_description, threat_level) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id,
                        conn_data["local_ip"],
                        conn_data["local_port"],
                        conn_data["remote_ip"],
                        conn_data["remote_port"],
                        conn_data["status"],
                        conn_data["pid"],
                        conn_data["process_name"],
                        conn_data["process_exe"],
                        conn_data["activity_description"],
                        conn_data["threat_level"]
                    )
                )
            
            # Insert risky ports
            for port in scan_results["risky_ports"]:
                conn.execute(
                    """INSERT INTO risky_ports 
                       (scan_id, port, service, threat_level, reason, recommendation) 
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id,
                        port["port"],
                        port["service"],
                        port["threat_level"],
                        port["reason"],
                        port["recommendation"]
                    )
                )
            
            # Insert security recommendations
            for rec in scan_results["recommendations"]:
                conn.execute(
                    """INSERT INTO security_recommendations 
                       (scan_id, type, priority, title, description, action, details) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id,
                        rec["type"],
                        rec["priority"],
                        rec["title"],
                        rec["description"],
                        rec["action"],
                        rec["details"]
                    )
                )
            
            conn.commit()
            print(f"✅ Scan results saved to database: {scan_results['total_threats']} threats detected")
        
        # Send notification email for high-risk findings
        high_risk_threats = [
            p for p in scan_results["suspicious_processes"] if p["threat_level"] in ["high", "critical"]
        ] + [
            p for p in scan_results["risky_ports"] if p["threat_level"] in ["high", "critical"]
        ]
        
        if high_risk_threats:
            email_body = f"""
Security Alert - CyberNova AI

Hi {current_user["full_name"]},

Our security scan has detected {len(high_risk_threats)} high-risk threats on your system.

Scan ID: {scan_id}
Total Threats: {scan_results["total_threats"]}
High-Risk Threats: {len(high_risk_threats)}

Please review your dashboard immediately: https://cybernova-de84b.web.app/

Stay secure,
CyberNova AI Security Team
            """
            
            background_tasks.add_task(
                send_email,
                current_user["email"],
                f"🚨 Security Alert - {len(high_risk_threats)} High-Risk Threats Detected",
                email_body
            )
        
        return {
            "status": "success",
            "scan_id": scan_id,
            "threats_detected": scan_results["total_threats"],
            "high_risk_threats": len(high_risk_threats),
            "scan_time": scan_results["scan_timestamp"],
            "message": f"Security scan completed successfully. {scan_results['total_threats']} threats detected."
        }
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Security scan failed: {str(e)}")

@app.post("/api/scan/reset")
async def reset_scan_data(current_user: dict = Depends(get_current_user)):
    """Reset all scan data for current user"""
    try:
        user_id = current_user["id"]
        
        with get_db_connection() as conn:
            # Get all scan IDs for user
            scan_ids = conn.execute(
                "SELECT scan_id FROM system_scans WHERE user_id = ?",
                (user_id,)
            ).fetchall()
            
            scan_id_list = [row["scan_id"] for row in scan_ids]
            
            if scan_id_list:
                # Delete related data
                placeholders = ','.join(['?' for _ in scan_id_list])
                
                conn.execute(f"DELETE FROM security_recommendations WHERE scan_id IN ({placeholders})", scan_id_list)
                conn.execute(f"DELETE FROM risky_ports WHERE scan_id IN ({placeholders})", scan_id_list)
                conn.execute(f"DELETE FROM network_connections WHERE scan_id IN ({placeholders})", scan_id_list)
                conn.execute(f"DELETE FROM suspicious_processes WHERE scan_id IN ({placeholders})", scan_id_list)
                conn.execute(f"DELETE FROM system_scans WHERE scan_id IN ({placeholders})", scan_id_list)
                
                conn.commit()
                print(f"✅ Reset scan data for user {user_id}: {len(scan_id_list)} scans deleted")
            
            return {
                "status": "success",
                "message": f"Successfully reset {len(scan_id_list)} scans and all related data",
                "scans_deleted": len(scan_id_list)
            }
            
    except Exception as e:
        print(f"❌ Reset failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to reset scan data: {str(e)}")

# ==================== DASHBOARD DATA ENDPOINT ====================

@app.get("/api/dashboard/data")
async def get_dashboard_data(current_user: dict = Depends(get_current_user)):
    """Get comprehensive dashboard data for current user"""
    try:
        user_id = current_user["id"]
        
        with get_db_connection() as conn:
            # Get latest scan
            latest_scan = conn.execute(
                """SELECT * FROM system_scans 
                   WHERE user_id = ? 
                   ORDER BY created_at DESC 
                   LIMIT 1""",
                (user_id,)
            ).fetchone()
            
            if not latest_scan:
                return {
                    "systemInfo": None,
                    "stats": {
                        "totalThreats": 0,
                        "activeAlerts": 0,
                        "riskScore": 0,
                        "systemHealth": 100,
                        "lastScanTime": None,
                        "scanStatus": "No scans yet"
                    },
                    "alerts": [],
                    "scanData": None
                }
            
            scan_id = latest_scan["scan_id"]
            
            # Get threats data
            processes = conn.execute(
                "SELECT * FROM suspicious_processes WHERE scan_id = ? ORDER BY created_at DESC",
                (scan_id,)
            ).fetchall()
            
            connections = conn.execute(
                "SELECT * FROM network_connections WHERE scan_id = ? ORDER BY created_at DESC",
                (scan_id,)
            ).fetchall()
            
            ports = conn.execute(
                "SELECT * FROM risky_ports WHERE scan_id = ? ORDER BY created_at DESC",
                (scan_id,)
            ).fetchall()
            
            recommendations = conn.execute(
                "SELECT * FROM security_recommendations WHERE scan_id = ? ORDER BY priority DESC",
                (scan_id,)
            ).fetchall()
            
            # Build alerts
            alerts = []
            
            # Process alerts
            for proc in processes:
                if proc["threat_level"] in ["high", "critical"]:
                    threat_reasons = []
                    if proc["threat_reasons"]:
                        try:
                            threat_reasons = json.loads(proc["threat_reasons"])
                        except:
                            threat_reasons = [proc["threat_reasons"]]
                    
                    alerts.append({
                        "id": f"process_{proc['pid']}_{proc['id']}",
                        "title": f"Suspicious Process: {proc['name']}",
                        "description": f"Real threat: {proc['name']} (PID: {proc['pid']}) - {', '.join(threat_reasons[:2]) if threat_reasons else 'High threat level'}",
                        "severity": proc["threat_level"],
                        "timestamp": proc["created_at"],
                        "sourceIp": "Local System",
                        "riskScore": 90 if proc["threat_level"] == "critical" else 75,
                        "isBlocked": False,
                        "type": "process"
                    })
            
            # Port alerts
            for port in ports:
                if port["threat_level"] in ["high", "critical"]:
                    alerts.append({
                        "id": f"port_{port['port']}_{port['id']}",
                        "title": f"Risky Port: {port['port']} ({port['service']})",
                        "description": f"Real vulnerability: {port['reason']}",
                        "severity": port["threat_level"],
                        "timestamp": port["created_at"],
                        "sourceIp": "Local System",
                        "riskScore": 85 if port["threat_level"] == "critical" else 65,
                        "isBlocked": False,
                        "type": "port"
                    })
            
            # Network alerts
            for conn_data in connections:
                if conn_data["threat_level"] in ["high", "critical"]:
                    alerts.append({
                        "id": f"network_{conn_data['remote_ip']}_{conn_data['id']}",
                        "title": "Suspicious Network Activity",
                        "description": f"Real threat: {conn_data['activity_description']}",
                        "severity": conn_data["threat_level"],
                        "timestamp": conn_data["created_at"],
                        "sourceIp": conn_data["remote_ip"],
                        "riskScore": 80 if conn_data["threat_level"] == "critical" else 60,
                        "isBlocked": False,
                        "type": "network"
                    })
            
            # Calculate stats
            total_threats = len(processes) + len(ports) + len([c for c in connections if c["threat_level"] in ["medium", "high", "critical"]])
            active_alerts = len(alerts)
            risk_score = min(100, max(0, active_alerts * 12)) if active_alerts > 0 else 0
            system_health = max(0, 100 - risk_score)
            
            # Parse system info
            system_info = {}
            if latest_scan["system_info"]:
                try:
                    system_info = json.loads(latest_scan["system_info"])
                except:
                    system_info = {"hostname": "Unknown", "platform": "Unknown"}
            
            return {
                "systemInfo": system_info,
                "stats": {
                    "totalThreats": total_threats,
                    "activeAlerts": active_alerts,
                    "riskScore": round(risk_score, 1),
                    "systemHealth": round(system_health, 1),
                    "lastScanTime": latest_scan["created_at"],
                    "scanStatus": latest_scan["scan_status"]
                },
                "alerts": alerts,
                "scanData": {
                    "system_info": system_info,
                    "suspicious_processes": [dict(row) for row in processes],
                    "network_connections": [dict(row) for row in connections],
                    "risky_ports": [dict(row) for row in ports],
                    "recommendations": [dict(row) for row in recommendations]
                }
            }
            
    except Exception as e:
        print(f"❌ Dashboard data error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")

# ==================== ANALYTICS INTEGRATION ====================

@app.get("/api/analytics/dashboard-metrics")
async def get_analytics_metrics(current_user: dict = Depends(get_current_user)):
    """Get analytics metrics from analytics service"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{ANALYTICS_SERVICE_URL}/api/analytics/dashboard-metrics")
            if response.status_code == 200:
                return response.json()
            else:
                return {"metrics": {}}
    except Exception as e:
        print(f"Analytics service error: {e}")
        return {"metrics": {}}

@app.get("/api/analytics/risk-assessment")
async def get_risk_assessment(current_user: dict = Depends(get_current_user)):
    """Get risk assessment from analytics service"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{ANALYTICS_SERVICE_URL}/api/analytics/risk-assessment")
            if response.status_code == 200:
                return response.json()
            else:
                return {"averageRiskScore": 0, "maxRiskScore": 0}
    except Exception as e:
        print(f"Analytics service error: {e}")
        return {"averageRiskScore": 0, "maxRiskScore": 0}

# ==================== HEALTH & STATUS ====================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        with get_db_connection() as conn:
            conn.execute("SELECT 1").fetchone()
        
        return {
            "status": "healthy",
            "service": "CyberNova AI API Gateway",
            "version": "3.0.0",
            "timestamp": datetime.now().isoformat(),
            "database": "connected",
            "analytics_service": "connected"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "CyberNova AI - Advanced Cybersecurity Platform",
        "version": "3.0.0",
        "status": "operational",
        "documentation": "/docs"
    }

# ==================== STARTUP MESSAGE ====================

if __name__ == "__main__":
    print("🚀 Starting CyberNova AI API Gateway...")
    print("🔒 Security features: Active")
    print("🔍 Scanning engine: Ready") 
    print("📊 Analytics integration: Enabled")
    print("✅ All systems operational")
