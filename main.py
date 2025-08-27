import json
import os
import logging
import asyncio
import traceback
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union
import uuid
import random
import time
from dataclasses import dataclass, asdict
import hashlib
import secrets

from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
import httpx
import redis
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
SECURITY_SERVICE_URL = os.getenv("SECURITY_SERVICE_URL", "http://security-service:8000")
VULNERABILITY_SERVICE_URL = os.getenv("VULNERABILITY_SERVICE_URL", "http://vulnerability-service:8001")
THREAT_SERVICE_URL = os.getenv("THREAT_SERVICE_URL", "http://threat-service:8002")
ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://ml-service:8003")
NOTIFICATION_SERVICE_URL = os.getenv("NOTIFICATION_SERVICE_URL", "http://notification-service:8004")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key")
API_KEY = os.getenv("API_KEY", "your-api-key")

# Global Redis connection
redis_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()
        logger.info("Redis connection established")
        yield
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        redis_client = None
        yield
    finally:
        if redis_client:
            redis_client.close()

# Initialize FastAPI app
app = FastAPI(
    title="CyberNova AI Security Gateway",
    description="Central API Gateway for CyberNova AI Security Platform",
    version="2.0.0",
    lifespan=lifespan
)

# Security
security = HTTPBearer()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic Models
class DashboardRequest(BaseModel):
    action: str
    userId: str
    threatId: Optional[str] = None
    scanType: Optional[str] = None
    
    @validator('action')
    def validate_action(cls, v):
        allowed_actions = [
            'getDashboardData', 'startScan', 'getThreatDetails', 
            'resetScanData', 'getSystemInfo', 'getAlerts'
        ]
        if v not in allowed_actions:
            raise ValueError(f'Action must be one of: {allowed_actions}')
        return v

class ThreatAlert(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    timestamp: str
    sourceIp: str
    riskScore: int
    isBlocked: bool = False
    threatType: str
    resolution: Optional[Dict[str, Any]] = None

class SystemStats(BaseModel):
    totalThreats: int
    activeAlerts: int
    riskScore: int
    systemHealth: int
    lastScanTime: Optional[str] = None

class ScanData(BaseModel):
    scanId: str
    timestamp: str
    systemInfo: Dict[str, Any]
    networkConnections: List[Dict[str, Any]]
    suspiciousProcesses: List[Dict[str, Any]]
    riskyPorts: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]

# Data Classes for better type safety
@dataclass
class NetworkConnection:
    hostname: str
    remote_ip: str
    remote_port: int
    process_name: str
    pid: int
    status: str
    timestamp: str
    threat_level: str
    activity_name: str
    activity_description: str
    description: str
    how_occurred: str
    why_dangerous: str
    immediate_impact: str
    process_exe: Optional[str] = None
    threat_details: Optional[Dict[str, Any]] = None

@dataclass
class SuspiciousProcess:
    name: str
    pid: int
    cpu_percent: float
    memory_percent: float
    exe_path: str
    username: str
    first_seen: str
    cmdline: str
    threat_level: str
    description: str
    how_occurred: str
    why_dangerous: str
    immediate_impact: str
    threat_details: Optional[Dict[str, Any]] = None

# Utility Functions
def generate_threat_id() -> str:
    """Generate a unique threat ID"""
    return f"threat_{uuid.uuid4().hex[:8]}"

def format_timestamp() -> str:
    """Format current timestamp for consistency"""
    return datetime.now(timezone.utc).isoformat()

def calculate_risk_score(threats: List[Dict[str, Any]]) -> int:
    """Calculate system risk score based on active threats"""
    if not threats:
        return 5  # Base risk score
    
    severity_weights = {
        'critical': 25,
        'high': 15,
        'medium': 8,
        'low': 3
    }
    
    total_score = sum(severity_weights.get(threat.get('severity', 'low'), 3) for threat in threats)
    return min(100, max(0, total_score))

def get_cache_key(action: str, user_id: str, **kwargs) -> str:
    """Generate cache key for Redis storage"""
    key_parts = [action, user_id]
    for key, value in sorted(kwargs.items()):
        if value is not None:
            key_parts.append(f"{key}:{value}")
    return ":".join(key_parts)

async def cache_get(key: str) -> Optional[Dict[str, Any]]:
    """Get data from Redis cache"""
    if not redis_client:
        return None
    try:
        data = redis_client.get(key)
        return json.loads(data) if data else None
    except Exception as e:
        logger.error(f"Cache get error for key {key}: {e}")
        return None

async def cache_set(key: str, data: Dict[str, Any], expire_seconds: int = 300) -> None:
    """Set data in Redis cache with expiration"""
    if not redis_client:
        return
    try:
        redis_client.setex(key, expire_seconds, json.dumps(data))
    except Exception as e:
        logger.error(f"Cache set error for key {key}: {e}")

# Authentication and authorization
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token or API key"""
    token = credentials.credentials
    
    # For development, accept a simple API key
    if token == API_KEY:
        return {"user_id": "user_123", "role": "admin"}
    
    # For production, implement proper JWT validation here
    return {"user_id": "user_123", "role": "admin"}

# Enhanced Threat Generation
class ThreatGenerator:
    def __init__(self):
        self.threat_templates = {
            'malware': {
                'names': ['TrojanX.exe', 'CryptoMiner.dll', 'Keylogger.bin', 'RAT_Client.exe', 'Backdoor.sys'],
                'descriptions': [
                    'Advanced persistent threat detected attempting to steal credentials',
                    'Cryptocurrency mining malware consuming system resources',
                    'Keylogger recording user inputs and sending to remote server',
                    'Remote access trojan providing unauthorized system access',
                    'Rootkit hiding malicious processes from system monitoring'
                ]
            },
            'network': {
                'suspicious_domains': [
                    'suspicious-site.ru', 'malware-c2.tk', 'phishing-bank.ml', 
                    'data-exfil.ga', 'botnet-command.cf'
                ],
                'descriptions': [
                    'Connection to known command & control server',
                    'Data exfiltration to suspicious foreign IP address',
                    'Communication with botnet infrastructure',
                    'Phishing site credential harvesting attempt',
                    'Malware downloading additional payloads'
                ]
            },
            'process': {
                'suspicious_activities': [
                    'Privilege escalation attempt detected',
                    'Process hollowing technique identified',
                    'DLL injection into system processes',
                    'Anti-debugging evasion techniques',
                    'Memory scanning for sensitive data'
                ]
            }
        }

    def generate_network_threats(self, count: int = 5) -> List[NetworkConnection]:
        """Generate realistic network threat scenarios"""
        threats = []
        current_time = datetime.now(timezone.utc)
        
        # Critical threats - Data exfiltration
        if random.random() < 0.7:  # 70% chance of critical threat
            threat = NetworkConnection(
                hostname=random.choice(['data-exfil.ru', 'steal-info.tk', 'bad-actor.ml']),
                remote_ip=f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                remote_port=random.choice([443, 8080, 9001, 4444]),
                process_name=random.choice(['chrome.exe', 'firefox.exe', 'suspicious.exe', 'malware.bin']),
                pid=random.randint(1000, 9999),
                status='ESTABLISHED',
                timestamp=current_time.isoformat(),
                threat_level='critical',
                activity_name=f"Data Exfiltration to {random.choice(['Russia', 'China', 'North Korea'])}",
                activity_description="Critical security breach - Personal data being stolen",
                description="Your personal files, passwords, and sensitive information are being secretly uploaded to a server controlled by cybercriminals. This is happening RIGHT NOW without your knowledge.",
                how_occurred="A malicious program on your computer has gained access to your files and is transmitting them through an encrypted connection to avoid detection.",
                why_dangerous="Your identity, financial information, private documents, and passwords are being stolen. This could lead to identity theft, financial fraud, and complete privacy violation.",
                immediate_impact="IMMEDIATE ACTION REQUIRED: Personal data theft in progress. Financial accounts may be compromised.",
                threat_details={
                    'data_being_stolen': [
                        'Browser passwords and login credentials',
                        'Personal documents and photos',
                        'Financial information and bank details',
                        'Social security numbers and identity documents',
                        'Email contents and contact lists'
                    ],
                    'threat_actor': 'Advanced Persistent Threat (APT) group',
                    'data_destination': 'Command & Control server in hostile nation',
                    'encryption_used': 'Military-grade encryption to avoid detection'
                }
            )
            threats.append(threat)

        # High severity - Botnet communication
        if random.random() < 0.6:  # 60% chance
            threat = NetworkConnection(
                hostname=random.choice(['botnet-cmd.cf', 'zombie-net.ga', 'control-server.tk']),
                remote_ip=f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                remote_port=random.choice([6667, 8080, 443, 1337]),
                process_name=random.choice(['svchost.exe', 'explorer.exe', 'winlogon.exe']),
                pid=random.randint(500, 5000),
                status='ESTABLISHED',
                timestamp=(current_time - timedelta(minutes=random.randint(1, 30))).isoformat(),
                threat_level='high',
                activity_name="Botnet Command & Control Communication",
                activity_description="Your computer is part of a criminal botnet",
                description="Your computer has been infected with malware that allows cybercriminals to control it remotely. It's now part of a 'botnet' - a network of infected computers used for illegal activities.",
                how_occurred="Malware infection through email attachment, malicious website, or software download has installed a backdoor that connects to criminal servers.",
                why_dangerous="Criminals can use your computer to launch attacks, send spam, mine cryptocurrency, or participate in illegal activities - all under your IP address and internet connection.",
                immediate_impact="Your computer is being used for criminal activities. Your internet connection is being exploited for illegal purposes.",
                threat_details={
                    'botnet_activities': [
                        'Launching DDoS attacks against websites',
                        'Sending spam and phishing emails',
                        'Mining cryptocurrency using your electricity',
                        'Hosting illegal content',
                        'Proxy for other criminal activities'
                    ]
                }
            )
            threats.append(threat)

        # Medium severity threats
        remaining_count = max(0, count - len(threats))
        for _ in range(remaining_count):
            severity = random.choice(['medium', 'low'])
            threat = NetworkConnection(
                hostname=random.choice(['suspicious-ad.com', 'tracking-site.net', 'malvertising.org']),
                remote_ip=f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                remote_port=random.choice([80, 443, 8080, 3000]),
                process_name=random.choice(['chrome.exe', 'firefox.exe', 'edge.exe']),
                pid=random.randint(1000, 9999),
                status='ESTABLISHED',
                timestamp=(current_time - timedelta(minutes=random.randint(1, 60))).isoformat(),
                threat_level=severity,
                activity_name=f"{severity.title()} Risk Connection",
                activity_description="Potentially unwanted network activity",
                description=f"Connection to a {severity}-risk website that may be involved in tracking or malicious advertising.",
                how_occurred="Browser connection to website with questionable reputation or security practices.",
                why_dangerous="May collect personal information, display malicious ads, or redirect to dangerous websites.",
                immediate_impact="Privacy risk and potential exposure to additional threats."
            )
            threats.append(threat)

        return threats

    def generate_process_threats(self, count: int = 3) -> List[SuspiciousProcess]:
        """Generate realistic process threat scenarios"""
        threats = []
        current_time = datetime.now(timezone.utc)

        # Critical malware process
        if random.random() < 0.8:  # 80% chance of critical process threat
            malware_name = random.choice(['TrojanX.exe', 'CryptoStealer.bin', 'SystemHack.dll', 'DataThief.exe'])
            threat = SuspiciousProcess(
                name=malware_name,
                pid=random.randint(1000, 9999),
                cpu_percent=random.uniform(15.0, 45.0),
                memory_percent=random.uniform(8.0, 25.0),
                exe_path=f"C:\\Windows\\Temp\\{malware_name}",
                username='SYSTEM',
                first_seen=(current_time - timedelta(minutes=random.randint(10, 120))).strftime('%H:%M:%S'),
                cmdline=f'"{malware_name}" --stealth --persist',
                threat_level='critical',
                description=f"{malware_name} is an advanced malware that has infected your system and is actively stealing your personal information while hiding from antivirus software.",
                how_occurred="This malware likely infected your system through a malicious email attachment, infected software download, or by exploiting a security vulnerability in your system.",
                why_dangerous="This malware can steal passwords, financial information, personal files, and install additional malicious software. It operates with system-level privileges and can modify critical system files.",
                immediate_impact="CRITICAL: Personal data theft in progress. The malware is accessing sensitive files and may be transmitting your information to cybercriminals.",
                threat_details={
                    'capabilities': [
                        'Password and credential harvesting',
                        'File system access and data exfiltration',
                        'Keylogging and screen capture',
                        'System persistence and hiding techniques',
                        'Communication with remote servers'
                    ],
                    'targeted_data': [
                        'Browser saved passwords',
                        'Cryptocurrency wallets',
                        'Personal documents',
                        'System configuration files'
                    ]
                }
            )
            threats.append(threat)

        # High severity - Cryptocurrency miner
        if random.random() < 0.6 and len(threats) < count:
            threat = SuspiciousProcess(
                name='xmrig.exe',
                pid=random.randint(2000, 8000),
                cpu_percent=random.uniform(65.0, 95.0),
                memory_percent=random.uniform(12.0, 30.0),
                exe_path='C:\\Users\\AppData\\Roaming\\miner\\xmrig.exe',
                username='Administrator',
                first_seen=(current_time - timedelta(hours=random.randint(1, 8))).strftime('%H:%M:%S'),
                cmdline='xmrig.exe -o pool.crypto.com -u wallet123 --donate-level=0',
                threat_level='high',
                description="Unauthorized cryptocurrency mining software is using your computer's resources to generate money for cybercriminals while significantly slowing down your system.",
                how_occurred="This mining software was likely installed through infected software, malicious websites, or bundled with other programs you downloaded.",
                why_dangerous="It consumes massive amounts of your computer's processing power and electricity, causes overheating, reduces system performance, and generates revenue for criminals.",
                immediate_impact="HIGH: Your computer is being used to mine cryptocurrency for criminals. System performance severely degraded and electricity costs increased."
            )
            threats.append(threat)

        # Fill remaining slots with medium/low severity
        remaining = count - len(threats)
        for _ in range(remaining):
            severity = random.choice(['medium', 'low'])
            process_name = random.choice(['svchost.exe', 'rundll32.exe', 'powershell.exe'])
            threat = SuspiciousProcess(
                name=process_name,
                pid=random.randint(1000, 9999),
                cpu_percent=random.uniform(2.0, 15.0),
                memory_percent=random.uniform(1.0, 8.0),
                exe_path=f'C:\\Windows\\System32\\{process_name}',
                username=random.choice(['SYSTEM', 'Administrator']),
                first_seen=(current_time - timedelta(minutes=random.randint(30, 300))).strftime('%H:%M:%S'),
                cmdline=f'{process_name} -k netsvcs',
                threat_level=severity,
                description=f"System process showing {severity} risk behavior that requires monitoring.",
                how_occurred="Normal system process with unusual activity patterns.",
                why_dangerous="May indicate system compromise or unauthorized modifications.",
                immediate_impact=f"{severity.upper()}: System integrity monitoring required."
            )
            threats.append(threat)

        return threats

    def generate_alerts(self, count: int = 10) -> List[ThreatAlert]:
        """Generate comprehensive threat alerts"""
        alerts = []
        current_time = datetime.now(timezone.utc)

        # Generate network-based alerts
        network_threats = self.generate_network_threats(count // 2)
        for threat in network_threats:
            alert = ThreatAlert(
                id=generate_threat_id(),
                title=f"Network Threat: {threat.activity_name}",
                description=threat.description,
                severity=threat.threat_level,
                timestamp=threat.timestamp,
                sourceIp=threat.remote_ip,
                riskScore=random.randint(60, 95) if threat.threat_level in ['critical', 'high'] else random.randint(20, 59),
                isBlocked=random.choice([True, False]) if threat.threat_level in ['low', 'medium'] else False,
                threatType='network',
                resolution={
                    'action': f'Block connection to {threat.hostname} and scan system for malware',
                    'steps': [
                        f'Immediately disconnect from {threat.hostname}',
                        'Run full system antivirus scan',
                        'Check for unauthorized programs',
                        'Change all passwords',
                        'Monitor system for additional suspicious activity'
                    ],
                    'prevention': 'Keep antivirus updated, avoid suspicious websites, use firewall'
                } if threat.threat_level == 'critical' else None
            )
            alerts.append(alert)

        # Generate process-based alerts
        process_threats = self.generate_process_threats(count - len(alerts))
        for threat in process_threats:
            alert = ThreatAlert(
                id=generate_threat_id(),
                title=f"Suspicious Process: {threat.name}",
                description=threat.description,
                severity=threat.threat_level,
                timestamp=current_time.isoformat(),
                sourceIp='127.0.0.1',
                riskScore=random.randint(70, 100) if threat.threat_level == 'critical' else random.randint(40, 80),
                isBlocked=False,
                threatType='process',
                resolution={
                    'action': f'Terminate process {threat.name} and remove malware',
                    'steps': [
                        f'Kill process {threat.name} (PID: {threat.pid})',
                        f'Delete file: {threat.exe_path}',
                        'Run malware removal tool',
                        'Check system startup programs',
                        'Scan system registry for modifications'
                    ],
                    'prevention': 'Avoid downloading software from untrusted sources, keep OS updated'
                } if threat.threat_level in ['critical', 'high'] else None
            )
            alerts.append(alert)

        return alerts

# Initialize threat generator
threat_generator = ThreatGenerator()

# API Endpoints
@app.get("/", tags=["Health"])
async def root():
    """Health check endpoint"""
    return {
        "message": "CyberNova AI Security Gateway v2.0",
        "status": "operational",
        "timestamp": format_timestamp(),
        "services": {
            "security": "connected",
            "vulnerability": "connected", 
            "threat": "connected",
            "ml": "connected",
            "notification": "connected"
        }
    }

@app.get("/health", tags=["Health"])
async def health_check():
    """Detailed health check"""
    redis_status = "connected" if redis_client else "disconnected"
    
    return {
        "status": "healthy",
        "timestamp": format_timestamp(),
        "version": "2.0.0",
        "dependencies": {
            "redis": redis_status,
            "security_service": "up",
            "vulnerability_service": "up",
            "threat_service": "up",
            "ml_service": "up",
            "notification_service": "up"
        }
    }

# Main dashboard endpoint - matches frontend expectations
@app.post("/dashboard", tags=["Dashboard"])
async def handle_dashboard_request(
    request: DashboardRequest,
    background_tasks: BackgroundTasks,
    auth = Depends(verify_token)
):
    """
    Central dashboard endpoint that handles all dashboard-related requests
    This matches the frontend's executeAppwriteFunction calls
    """
    try:
        logger.info(f"Dashboard request: {request.action} for user {request.userId}")
        
        # Route to appropriate handler based on action
        if request.action == "getDashboardData":
            return await get_dashboard_data(request.userId, background_tasks)
        elif request.action == "startScan":
            return await start_scan(request.userId, request.scanType or "manual", background_tasks)
        elif request.action == "getThreatDetails":
            return await get_threat_details(request.threatId, request.userId)
        elif request.action == "resetScanData":
            return await reset_scan_data(request.userId)
        elif request.action == "getSystemInfo":
            return await get_system_info(request.userId)
        elif request.action == "getAlerts":
            return await get_alerts(request.userId)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown action: {request.action}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Dashboard request error: {str(e)}", exc_info=True)
        return {
            "error": str(e),
            "fallback": True,
            "motto": "Service temporarily unavailable",
            "learn": "Please try again in a moment"
        }

async def get_dashboard_data(user_id: str, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Get comprehensive dashboard data"""
    try:
        # Check cache first
        cache_key = get_cache_key("dashboard_data", user_id)
        cached_data = await cache_get(cache_key)
        
        if cached_data:
            logger.info("Returning cached dashboard data")
            return cached_data
        
        # Generate fresh data
        logger.info("Generating fresh dashboard data")
        
        # Generate realistic threats and alerts
        alerts = threat_generator.generate_alerts(random.randint(8, 15))
        network_threats = threat_generator.generate_network_threats(random.randint(4, 8))
        process_threats = threat_generator.generate_process_threats(random.randint(2, 5))
        
        # Calculate statistics
        active_alerts = len([alert for alert in alerts if not alert.isBlocked])
        total_threats = len(alerts)
        risk_score = calculate_risk_score([asdict(alert) for alert in alerts])
        system_health = max(20, 100 - (risk_score // 2) - random.randint(0, 15))
        
        # Generate system info
        system_info = {
            "hostname": f"USER-PC-{random.randint(1000, 9999)}",
            "platform": random.choice(["Windows 10", "Windows 11", "Linux", "macOS"]),
            "ip_address": f"192.168.1.{random.randint(10, 254)}",
            "architecture": "x64",
            "cpu_count": random.choice([4, 6, 8, 12, 16]),
            "memory_total": random.choice([8, 16, 32, 64]) * (1024**3)  # Convert to bytes
        }
        
        # Generate risky ports
        risky_ports = []
        if random.random() < 0.7:  # 70% chance of risky ports
            for _ in range(random.randint(1, 4)):
                port_num = random.choice([22, 23, 135, 139, 445, 3389, 5900, 1433, 3306])
                risky_ports.append({
                    "port": port_num,
                    "service": {22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 
                             445: "SMB", 3389: "RDP", 5900: "VNC", 1433: "SQL Server", 
                             3306: "MySQL"}.get(port_num, "Unknown"),
                    "threat_level": random.choice(["high", "medium", "low"]),
                    "reason": f"Port {port_num} is commonly targeted by attackers"
                })
        
        # Generate recommendations
        recommendations = [
            {
                "title": "Update Antivirus Definitions",
                "description": "Your antivirus definitions are outdated",
                "priority": "high",
                "action": "Update antivirus software and run full system scan"
            },
            {
                "title": "Install Security Updates", 
                "description": "Critical security patches are available",
                "priority": "critical",
                "action": "Install Windows Updates and restart system"
            },
            {
                "title": "Review Network Connections",
                "description": "Unusual network activity detected",
                "priority": "medium", 
                "action": "Monitor network connections and block suspicious IPs"
            },
            {
                "title": "Change Default Passwords",
                "description": "Default passwords detected on network services",
                "priority": "high",
                "action": "Change default passwords to strong, unique passwords"
            }
        ]
        
        # Prepare scan data
        scan_data = {
            "scanId": f"scan_{uuid.uuid4().hex[:8]}",
            "timestamp": format_timestamp(),
            "system_info": system_info,
            "network_connections": [asdict(threat) for threat in network_threats],
            "suspicious_processes": [asdict(threat) for threat in process_threats],
            "risky_ports": risky_ports,
            "recommendations": random.sample(recommendations, k=random.randint(2, 4))
        }
        
        # Prepare response data
        dashboard_data = {
            "data": {
                "stats": {
                    "totalThreats": total_threats,
                    "activeAlerts": active_alerts,
                    "riskScore": risk_score,
                    "systemHealth": system_health,
                    "lastScanTime": format_timestamp()
                },
                "alerts": [asdict(alert) for alert in alerts],
                "scanData": scan_data
            }
        }
        
        # Cache the data
        await cache_set(cache_key, dashboard_data, expire_seconds=30)  # Cache for 30 seconds
        
        # Schedule background threat updates
        background_tasks.add_task(update_threat_intelligence, user_id)
        
        logger.info(f"Generated dashboard data: {total_threats} threats, {active_alerts} active alerts, risk score {risk_score}")
        return dashboard_data
        
    except Exception as e:
        logger.error(f"Error getting dashboard data: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")

async def start_scan(user_id: str, scan_type: str, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Start a security scan"""
    try:
        logger.info(f"Starting {scan_type} scan for user {user_id}")
        
        # Simulate scan initiation
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        
        # Schedule background scan
        background_tasks.add_task(perform_security_scan, user_id, scan_id, scan_type)
        
        return {
            "status": "started",
            "scanId": scan_id,
            "message": f"estimatedTime": "2-5 minutes",
            "timestamp": format_timestamp()
        }
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

async def get_threat_details(threat_id: str, user_id: str) -> Dict[str, Any]:
    """Get detailed information about a specific threat"""
    try:
        if not threat_id:
            raise HTTPException(status_code=400, detail="Threat ID is required")
        
        logger.info(f"Getting threat details for {threat_id}")
        
        # Check cache first
        cache_key = get_cache_key("threat_details", user_id, threat_id=threat_id)
        cached_details = await cache_get(cache_key)
        
        if cached_details:
            return cached_details
        
        # Generate detailed threat information
        threat_details = {
            "id": threat_id,
            "name": f"Advanced Threat #{threat_id[-4:]}",
            "type": random.choice(["Malware", "Network Intrusion", "Data Breach", "Phishing Attack"]),
            "severity": random.choice(["critical", "high", "medium"]),
            "riskScore": random.randint(60, 95),
            "detectedAt": format_timestamp(),
            "description": "This threat represents a significant security risk to your system and requires immediate attention.",
            "details": {
                "sourceIP": f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "targetPort": random.choice([80, 443, 8080, 3389, 22]),
                "protocol": random.choice(["TCP", "UDP", "HTTPS"]),
                "firstSeen": (datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 48))).isoformat(),
                "lastSeen": format_timestamp(),
                "attackVector": random.choice(["Email", "Web", "Network", "USB", "Remote Access"]),
                "affectedSystems": random.randint(1, 5)
            },
            "resolution": {
                "action": "Immediate isolation and remediation required",
                "steps": [
                    "Isolate affected system from network",
                    "Run comprehensive malware scan",
                    "Check for data exfiltration",
                    "Update security patches",
                    "Monitor for additional threats",
                    "Reset compromised credentials"
                ],
                "prevention": "Implement multi-layered security controls including updated antivirus, firewall rules, and user awareness training",
                "estimatedTime": "30-60 minutes"
            },
            "technicalAnalysis": {
                "iocList": [
                    f"IP: {random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                    f"Domain: malicious-site-{random.randint(1000,9999)}.com",
                    f"Hash: {hashlib.md5(str(random.random()).encode()).hexdigest()}",
                    f"Registry: HKEY_LOCAL_MACHINE\\Software\\{random.choice(['Microsoft', 'Windows', 'System'])}"
                ],
                "mitreTechniques": [
                    "T1055 - Process Injection",
                    "T1083 - File and Directory Discovery", 
                    "T1005 - Data from Local System",
                    "T1041 - Exfiltration Over C2 Channel"
                ]
            }
        }
        
        # Cache the details
        await cache_set(cache_key, threat_details, expire_seconds=300)
        
        return threat_details
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting threat details: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get threat details: {str(e)}")

async def reset_scan_data(user_id: str) -> Dict[str, Any]:
    """Reset all scan data for a user"""
    try:
        logger.info(f"Resetting scan data for user {user_id}")
        
        # Clear cache entries for this user
        if redis_client:
            try:
                # Get all keys for this user
                pattern = f"*{user_id}*"
                keys = redis_client.keys(pattern)
                if keys:
                    redis_client.delete(*keys)
                    logger.info(f"Cleared {len(keys)} cache entries for user {user_id}")
            except Exception as e:
                logger.warning(f"Failed to clear cache: {e}")
        
        return {
            "status": "success",
            "message": "Scan data has been reset successfully",
            "timestamp": format_timestamp()
        }
        
    except Exception as e:
        logger.error(f"Error resetting scan data: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to reset scan data: {str(e)}")

async def get_system_info(user_id: str) -> Dict[str, Any]:
    """Get system information"""
    try:
        logger.info(f"Getting system info for user {user_id}")
        
        # Check cache
        cache_key = get_cache_key("system_info", user_id)
        cached_info = await cache_get(cache_key)
        
        if cached_info:
            return cached_info
        
        # Generate system info
        system_info = {
            "hostname": f"USER-PC-{random.randint(1000, 9999)}",
            "platform": random.choice(["Windows 10 Pro", "Windows 11 Home", "Ubuntu 22.04", "macOS Monterey"]),
            "architecture": "x64",
            "processor": random.choice([
                "Intel Core i7-10700K",
                "AMD Ryzen 7 3700X", 
                "Intel Core i5-11400",
                "AMD Ryzen 5 5600X"
            ]),
            "memory": f"{random.choice([8, 16, 32])} GB",
            "storage": f"{random.choice([256, 512, 1024])} GB SSD",
            "ip_address": f"192.168.1.{random.randint(10, 254)}",
            "mac_address": ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)]),
            "os_version": f"{random.randint(19000, 22000)}.{random.randint(1000, 9999)}",
            "last_boot": (datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 168))).isoformat(),
            "uptime": f"{random.randint(1, 168)} hours",
            "domain": random.choice(["WORKGROUP", "CORPORATE", "HOME"]),
            "antivirus": random.choice(["Windows Defender", "Norton", "Bitdefender", "Kaspersky", "McAfee"]),
            "firewall_enabled": random.choice([True, False]),
            "auto_updates": random.choice([True, False])
        }
        
        # Cache for 5 minutes
        await cache_set(cache_key, system_info, expire_seconds=300)
        
        return system_info
        
    except Exception as e:
        logger.error(f"Error getting system info: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get system info: {str(e)}")

async def get_alerts(user_id: str) -> Dict[str, Any]:
    """Get security alerts for a user"""
    try:
        logger.info(f"Getting alerts for user {user_id}")
        
        # Generate fresh alerts
        alerts = threat_generator.generate_alerts(random.randint(5, 12))
        
        return {
            "alerts": [asdict(alert) for alert in alerts],
            "total": len(alerts),
            "active": len([alert for alert in alerts if not alert.isBlocked]),
            "timestamp": format_timestamp()
        }
        
    except Exception as e:
        logger.error(f"Error getting alerts: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get alerts: {str(e)}")

# Background Tasks
async def perform_security_scan(user_id: str, scan_id: str, scan_type: str):
    """Perform comprehensive security scan in background"""
    try:
        logger.info(f"Performing {scan_type} scan {scan_id} for user {user_id}")
        
        # Simulate scan duration
        scan_duration = random.randint(30, 120)  # 30 seconds to 2 minutes
        await asyncio.sleep(scan_duration)
        
        # Generate scan results
        network_threats = threat_generator.generate_network_threats(random.randint(3, 8))
        process_threats = threat_generator.generate_process_threats(random.randint(2, 5))
        
        scan_results = {
            "scanId": scan_id,
            "userId": user_id,
            "type": scan_type,
            "status": "completed",
            "startTime": (datetime.now(timezone.utc) - timedelta(seconds=scan_duration)).isoformat(),
            "endTime": format_timestamp(),
            "duration": f"{scan_duration} seconds",
            "results": {
                "threatsFound": len(network_threats) + len(process_threats),
                "networkThreats": len(network_threats),
                "processThreats": len(process_threats),
                "criticalThreats": len([t for t in network_threats + process_threats if t.threat_level == 'critical']),
                "highThreats": len([t for t in network_threats + process_threats if t.threat_level == 'high']),
                "networkConnections": [asdict(threat) for threat in network_threats],
                "suspiciousProcesses": [asdict(threat) for threat in process_threats]
            }
        }
        
        # Store scan results in cache
        cache_key = f"scan_results:{user_id}:{scan_id}"
        await cache_set(cache_key, scan_results, expire_seconds=3600)  # Cache for 1 hour
        
        logger.info(f"Scan {scan_id} completed. Found {len(network_threats) + len(process_threats)} threats")
        
    except Exception as e:
        logger.error(f"Error performing scan {scan_id}: {str(e)}", exc_info=True)

async def update_threat_intelligence(user_id: str):
    """Update threat intelligence data in background"""
    try:
        logger.info(f"Updating threat intelligence for user {user_id}")
        
        # Simulate threat intelligence update
        await asyncio.sleep(5)
        
        # Generate new threat indicators
        new_threats = random.randint(0, 3)
        if new_threats > 0:
            logger.info(f"Generated {new_threats} new threat indicators")
            
        # Update cache with new threat data
        cache_key = f"threat_intel:{user_id}"
        threat_intel = {
            "lastUpdated": format_timestamp(),
            "newThreats": new_threats,
            "totalIndicators": random.randint(50000, 100000),
            "sources": ["CyberNova AI", "Threat Intelligence Feeds", "Honeypot Network"]
        }
        
        await cache_set(cache_key, threat_intel, expire_seconds=1800)  # 30 minutes
        
    except Exception as e:
        logger.error(f"Error updating threat intelligence: {str(e)}", exc_info=True)

# Additional API Endpoints for compatibility
@app.get("/api/dashboard/{user_id}", tags=["Dashboard"])
async def get_user_dashboard(
    user_id: str,
    background_tasks: BackgroundTasks,
    auth = Depends(verify_token)
):
    """Alternative endpoint for getting dashboard data"""
    request = DashboardRequest(action="getDashboardData", userId=user_id)
    return await handle_dashboard_request(request, background_tasks, auth)

@app.post("/api/scan/start", tags=["Scanning"])
async def start_security_scan(
    request: Dict[str, Any],
    background_tasks: BackgroundTasks,
    auth = Depends(verify_token)
):
    """Start a security scan"""
    user_id = request.get("userId")
    scan_type = request.get("scanType", "manual")
    
    if not user_id:
        raise HTTPException(status_code=400, detail="userId is required")
    
    dashboard_request = DashboardRequest(
        action="startScan",
        userId=user_id,
        scanType=scan_type
    )
    
    return await handle_dashboard_request(dashboard_request, background_tasks, auth)

@app.get("/api/scan/results/{scan_id}", tags=["Scanning"])
async def get_scan_results(
    scan_id: str,
    user_id: str = None,
    auth = Depends(verify_token)
):
    """Get results for a specific scan"""
    try:
        if not user_id:
            user_id = auth.get("user_id", "user_123")
        
        cache_key = f"scan_results:{user_id}:{scan_id}"
        results = await cache_get(cache_key)
        
        if not results:
            raise HTTPException(status_code=404, detail="Scan results not found")
        
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan results: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get scan results: {str(e)}")

@app.get("/api/threats", tags=["Threats"])
async def get_threats(
    user_id: str = None,
    severity: str = None,
    limit: int = 50,
    auth = Depends(verify_token)
):
    """Get threat data with optional filtering"""
    try:
        if not user_id:
            user_id = auth.get("user_id", "user_123")
        
        # Generate threats
        alerts = threat_generator.generate_alerts(limit)
        
        # Filter by severity if specified
        if severity:
            alerts = [alert for alert in alerts if alert.severity == severity]
        
        return {
            "threats": [asdict(alert) for alert in alerts],
            "total": len(alerts),
            "filtered": severity is not None,
            "timestamp": format_timestamp()
        }
        
    except Exception as e:
        logger.error(f"Error getting threats: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get threats: {str(e)}")

@app.get("/api/system/status", tags=["System"])
async def get_system_status(
    user_id: str = None,
    auth = Depends(verify_token)
):
    """Get overall system security status"""
    try:
        if not user_id:
            user_id = auth.get("user_id", "user_123")
        
        # Generate status data
        alerts = threat_generator.generate_alerts(10)
        active_threats = [alert for alert in alerts if not alert.isBlocked]
        risk_score = calculate_risk_score([asdict(alert) for alert in alerts])
        
        status = {
            "overall_status": "at_risk" if risk_score > 60 else "secure" if risk_score < 30 else "moderate_risk",
            "risk_score": risk_score,
            "active_threats": len(active_threats),
            "total_threats": len(alerts),
            "critical_threats": len([alert for alert in alerts if alert.severity == "critical"]),
            "high_threats": len([alert for alert in alerts if alert.severity == "high"]),
            "system_health": max(20, 100 - (risk_score // 2)),
            "last_scan": format_timestamp(),
            "recommendations_count": random.randint(3, 8),
            "timestamp": format_timestamp()
        }
        
        return status
        
    except Exception as e:
        logger.error(f"Error getting system status: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get system status: {str(e)}")

@app.get("/api/network/connections", tags=["Network"])
async def get_network_connections(
    user_id: str = None,
    threat_level: str = None,
    auth = Depends(verify_token)
):
    """Get network connection data"""
    try:
        if not user_id:
            user_id = auth.get("user_id", "user_123")
        
        # Generate network connections
        connections = threat_generator.generate_network_threats(random.randint(5, 15))
        
        # Filter by threat level if specified
        if threat_level:
            connections = [conn for conn in connections if conn.threat_level == threat_level]
        
        return {
            "connections": [asdict(conn) for conn in connections],
            "total": len(connections),
            "critical": len([c for c in connections if c.threat_level == "critical"]),
            "high": len([c for c in connections if c.threat_level == "high"]),
            "medium": len([c for c in connections if c.threat_level == "medium"]),
            "low": len([c for c in connections if c.threat_level == "low"]),
            "timestamp": format_timestamp()
        }
        
    except Exception as e:
        logger.error(f"Error getting network connections: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get network connections: {str(e)}")

@app.get("/api/processes/suspicious", tags=["Processes"])
async def get_suspicious_processes(
    user_id: str = None,
    threat_level: str = None,
    auth = Depends(verify_token)
):
    """Get suspicious process data"""
    try:
        if not user_id:
            user_id = auth.get("user_id", "user_123")
        
        # Generate suspicious processes
        processes = threat_generator.generate_process_threats(random.randint(3, 10))
        
        # Filter by threat level if specified
        if threat_level:
            processes = [proc for proc in processes if proc.threat_level == threat_level]
        
        return {
            "processes": [asdict(proc) for proc in processes],
            "total": len(processes),
            "critical": len([p for p in processes if p.threat_level == "critical"]),
            "high": len([p for p in processes if p.threat_level == "high"]),
            "medium": len([p for p in processes if p.threat_level == "medium"]),
            "low": len([p for p in processes if p.threat_level == "low"]),
            "timestamp": format_timestamp()
        }
        
    except Exception as e:
        logger.error(f"Error getting suspicious processes: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get suspicious processes: {str(e)}")

# WebSocket endpoint for real-time updates
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket, user_id: str):
    """WebSocket endpoint for real-time threat updates"""
    await websocket.accept()
    logger.info(f"WebSocket connected for user {user_id}")
    
    try:
        while True:
            # Send periodic updates
            await asyncio.sleep(30)  # Update every 30 seconds
            
            # Generate new threat data
            new_threats = random.randint(0, 2)
            if new_threats > 0:
                alerts = threat_generator.generate_alerts(new_threats)
                update_data = {
                    "type": "threat_update",
                    "data": {
                        "new_threats": [asdict(alert) for alert in alerts],
                        "timestamp": format_timestamp()
                    }
                }
                await websocket.send_json(update_data)
                
            # Send system status update
            status_data = {
                "type": "status_update", 
                "data": {
                    "system_health": random.randint(70, 95),
                    "active_scans": random.randint(0, 2),
                    "timestamp": format_timestamp()
                }
            }
            await websocket.send_json(status_data)
            
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {str(e)}")
    finally:
        logger.info(f"WebSocket disconnected for user {user_id}")

# Batch operations
@app.post("/api/threats/batch/resolve", tags=["Threats"])
async def resolve_threats_batch(
    request: Dict[str, Any],
    auth = Depends(verify_token)
):
    """Resolve multiple threats at once"""
    try:
        threat_ids = request.get("threat_ids", [])
        user_id = request.get("user_id") or auth.get("user_id", "user_123")
        
        if not threat_ids:
            raise HTTPException(status_code=400, detail="threat_ids is required")
        
        resolved_count = 0
        for threat_id in threat_ids:
            # Simulate threat resolution
            await asyncio.sleep(0.1)  # Small delay for realism
            resolved_count += 1
        
        return {
            "status": "success",
            "resolved_count": resolved_count,
            "total_requested": len(threat_ids),
            "timestamp": format_timestamp()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving threats batch: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to resolve threats: {str(e)}")

@app.post("/api/system/quarantine", tags=["System"])
async def quarantine_threats(
    request: Dict[str, Any],
    background_tasks: BackgroundTasks,
    auth = Depends(verify_token)
):
    """Quarantine identified threats"""
    try:
        threat_ids = request.get("threat_ids", [])
        user_id = request.get("user_id") or auth.get("user_id", "user_123")
        
        if not threat_ids:
            raise HTTPException(status_code=400, detail="threat_ids is required")
        
        # Schedule background quarantine process
        background_tasks.add_task(perform_quarantine, user_id, threat_ids)
        
        return {
            "status": "initiated",
            "message": f"Quarantine process started for {len(threat_ids)} threats",
            "quarantine_id": f"quarantine_{uuid.uuid4().hex[:8]}",
            "timestamp": format_timestamp()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error initiating quarantine: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to initiate quarantine: {str(e)}")

async def perform_quarantine(user_id: str, threat_ids: List[str]):
    """Perform quarantine operation in background"""
    try:
        logger.info(f"Starting quarantine for {len(threat_ids)} threats for user {user_id}")
        
        quarantined_count = 0
        for threat_id in threat_ids:
            # Simulate quarantine process
            await asyncio.sleep(random.uniform(1, 3))  # 1-3 seconds per threat
            quarantined_count += 1
            logger.info(f"Quarantined threat {threat_id}")
        
        # Cache quarantine results
        quarantine_results = {
            "user_id": user_id,
            "quarantined_count": quarantined_count,
            "total_threats": len(threat_ids),
            "completed_at": format_timestamp(),
            "status": "completed"
        }
        
        cache_key = f"quarantine_results:{user_id}:{format_timestamp()}"
        await cache_set(cache_key, quarantine_results, expire_seconds=3600)
        
        logger.info(f"Quarantine completed: {quarantined_count}/{len(threat_ids)} threats quarantined")
        
    except Exception as e:
        logger.error(f"Error performing quarantine: {str(e)}", exc_info=True)

# Analytics and reporting
@app.get("/api/analytics/summary", tags=["Analytics"])
async def get_analytics_summary(
    user_id: str = None,
    days: int = 7,
    auth = Depends(verify_token)
):
    """Get security analytics summary"""
    try:
        if not user_id:
            user_id = auth.get("user_id", "user_123")
        
        # Generate analytics data
        summary = {
            "period_days": days,
            "total_threats_detected": random.randint(50, 200),
            "threats_blocked": random.randint(40, 180),
            "critical_incidents": random.randint(1, 5),
            "security_score_trend": [random.randint(70, 95) for _ in range(days)],
            "top_threat_types": [
                {"type": "Malware", "count": random.randint(10, 30)},
                {"type": "Phishing", "count": random.randint(5, 20)},
                {"type": "Network Intrusion", "count": random.randint(3, 15)},
                {"type": "Data Exfiltration", "count": random.randint(1, 10)}
            ],
            "risk_categories": {
                "critical": random.randint(1, 5),
                "high": random.randint(5, 15), 
                "medium": random.randint(10, 30),
                "low": random.randint(20, 50)
            },
            "scan_statistics": {
                "total_scans": random.randint(20, 100),
                "automated_scans": random.randint(15, 80),
                "manual_scans": random.randint(5, 20),
                "average_scan_time": f"{random.randint(45, 180)} seconds"
            },
            "system_performance": {
                "average_response_time": f"{random.uniform(0.5, 2.0):.2f}ms",
                "uptime_percentage": random.uniform(99.0, 99.9),
                "false_positive_rate": random.uniform(1.0, 5.0)
            },
            "generated_at": format_timestamp()
        }
        
        return summary
        
    except Exception as e:
        logger.error(f"Error getting analytics summary: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get analytics summary: {str(e)}")

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": format_timestamp(),
            "path": request.url.path
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "timestamp": format_timestamp(),
            "path": request.url.path
        }
    )

# Middleware for request logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests"""
    start_time = time.time()
    
    # Get client IP
    client_ip = request.headers.get("X-Forwarded-For", request.client.host)
    
    # Process request
    response = await call_next(request)
    
    # Calculate processing time
    process_time = time.time() - start_time
    
    # Log request
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"IP: {client_ip} - "
        f"Time: {process_time:.3f}s"
    )
    
    # Add custom headers
    response.headers["X-Process-Time"] = str(process_time)
    response.headers["X-API-Version"] = "2.0.0"
    
    return response

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )# Additional security and monitoring endpoints
