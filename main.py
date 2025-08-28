from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
import psutil
import platform
import socket
import asyncio
import json
import mathTABASE",
    version="4.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== ML THREAT MODEL ====================

class ThreatModel:
    """Advanced ML threat detection model"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.anomaly_detector = IsolationForest(contamination=0.02, random_state=42)
        self.classifier = GradientBoostingClassifier(random_state=42, n_estimators=50)
        self.trained = False
        self.bootstrap()
    
    def bootstrap(self):
        """Initialize model with synthetic training data"""
        print("🤖 Initializing ML threat detection model...")
        np.random.seed(42)
        
        # Create synthetic training data
        n_samples = 500
        X = []
        y = []
        
            
            features = 
            self.trained = True
            print("✅ ML model trained successfully")
        except Exception as e:
            random.randint(0, 10),         # Simulated file operations
            math.sime() / 3600),  # T
        
        return features
    
    def predict_threat(self, process_data):
        """Predict threat level for a process"""
        features = se
        # Rule-based scoring
        rule_score = 0
        name = process_data.get('name', '').lower()
        cpu = process_data.get('cpu_percent', 0)
        memory = process_data.get('memory_percent', 0)
        
        # Suspicious name patterns
        suspicious_names = ['powershell', 'cmd', 'wscript', 'cscript', 'rundll32', 'regsvr32', 'mshta']
        if any(pattern in name for pattern in suspicious_names):
            rule_score += 30
        
        # High resource usage
        if cpu > 80:
            rule_score += 25
        if memory > 70:
            rule_score += 20
        
        # Temporary directories
        if 'temp' in name or 'tmp' in name:
            rule_score += 15
        
        # ML predictions
        X = np.array(features).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        
        # Anomaly score (higher = more anomalous)
        anomaly_raw = self.anomaly_detector.decision_function(X_scaled)[0]
        anomaly_score = max(0, min(100, (0.5 - anomaly_raw) * 200))
        
        # Classification score
        clf_score = 0
        if self.trained:
            try:
                clf_prob = self.classifier.predict_proba(X_scaled)[0][1]
                clf_score = clf_prob * 100
            except:
                clf_score = 0
        
        # Combined score
        final_score = (0.4 * rule_score + 0.3 * clf_score + 0.3 * anomaly_score)
        final_score = min(100, final_score)
        
        # Determine severity
        if final_score >= 85:
            severity = "critical"
        elif final_score >= 70:
            severity = "high"
        elif final_score >= 50:
            severity = "medium"
        elif final_score >= 25:
            severity = "low"
        else:
            severity = "safe"
        
        return {
            "threat_score": round(final_score, 1),
            "severity": severity,
            "rule_score": round(rule_score, 1),
            "anomaly_score": round(anomaly_score, 1),
            "ml_score": round(clf_score, 1)
        }

# Initialize global threat model
threat_model = ThreatModel()

# ==================== REAL SYSTEM SCANNING ====================

def get_system_info():
    """Get real system information"""
    try:
        # Get real IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except:
        ip_address = "127.0.0.1"
    
    memory = psutil.virtual_memory()
    
    return {
        "hostname": platform.node(),
        "platform": f"{platform.system()} {platform.release()}",
        "architecture": platform.architecture()[0],
        "processor": platform.processor() or "Unknown",
        "ip_address": ip_address,
        "cpu_count": psutil.cpu_count(logical=True),
        "memory_total": memory.total,
        "memory_available": memory.available,
        "memory_percent": memory.percent,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

async def scan_processes():
    """Scan running processes for threats"""
    processes = []
    
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent', 'username']):
            try:
                proc_info = proc.info
                
                if not proc_info.get('name'):
                    continue
                
                # Get CPU and memory usage
                cpu_percent = proc_info.get('cpu_percent') or 0
                memory_percent = proc_info.get('memory_percent') or 0
                
                process_data = {
                    "pid": proc_info['pid'],
                    "name": proc_info['name'],
                    "exe_path": proc_info.get('exe') or '',
                    "cmdline": ' '.join(proc_info.get('cmdline') or []),
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory_percent,
                    "username": proc_info.get('username') or 'Unknown',
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                
                # Get ML threat prediction
                threat_prediction = threat_model.predict_threat(process_data)
                process_data.update(threat_prediction)
                
                processes.append(process_data)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
    except Exception as e:
        print(f"Process scanning error: {e}")
    
    return processes

async def scan_network_connections():
    """Scan network connections"""
    connections = []
    
    try:
        conns = psutil.net_connections(kind='inet')
        
        for conn in conns:
            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                # Skip local IPs
                if remote_ip.startswith(('127.', '10.', '192.168.', '172.')):
                    continue
                
                # Determine threat level
                threat_level = "low"
                if remote_port in [22, 23, 3389, 1433, 5900]:  # High-risk ports
                    threat_level = "high"
                elif remote_port in [135, 139, 445]:  # Medium-risk ports
                    threat_level = "medium"
                
                # Get process info
                process_name = "Unknown"
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                    except:
                        pass
                
                connections.append({
                    "local_ip": conn.laddr.ip if conn.laddr else "",
                    "local_port": conn.laddr.port if conn.laddr else 0,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": conn.status,
                    "pid": conn.pid,
                    "process_name": process_name,
                    "threat_level": threat_level,
                    "activity_description": f"Connection to {remote_ip}:{remote_port}",
                    "created_at": datetime.now(timezone.utc).isoformat()
                })
                
    except Exception as e:
        print(f"Network scanning error: {e}")
    
    return connections

async def scan_open_ports():
    """Scan for risky open ports"""
    risky_ports = []
    
    # Common risky ports
    ports_to_check = {
        21: ("FTP", "File Transfer Protocol - often misconfigured"),
        22: ("SSH", "SSH service - brute force target"),
        23: ("Telnet", "Unencrypted remote access - critical risk"),
        135: ("RPC", "Windows RPC - attack vector"),
        139: ("NetBIOS", "File sharing - ransomware risk"),
        445: ("SMB", "File sharing - common attack target"),
        1433: ("SQL Server", "Database - secure credentials needed"),
        3389: ("RDP", "Remote Desktop - brute force target"),
        5900: ("VNC", "Remote desktop - weak passwords")
    }
    
    try:
        # Get listening ports
        connections = psutil.net_connections(kind='inet')
        listening_ports = set()
        
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                listening_ports.add(conn.laddr.port)
        
        # Check risky ports
        for port in listening_ports:
            if port in ports_to_check:
                service, reason = ports_to_check[port]
                
                threat_level = "critical" if port in [23, 3389, 1433] else "high"
                
                risky_ports.append({
                    "port": port,
                    "service": service,
                    "threat_level": threat_level,
                    "reason": reason,
                    "recommendation": f"Consider securing or disabling {service}",
                    "created_at": datetime.now(timezone.utc).isoformat()
                })
                
    except Exception as e:
        print(f"Port scanning error: {e}")
    
    return risky_ports

# ==================== API ENDPOINTS ====================

@app.get("/")
async def dashboard():
    """Main dashboard endpoint - returns comprehensive scan results"""
    print("🔍 Performing real-time system scan...")
    
    try:
        # Perform comprehensive scan
        system_info = get_system_info()
        processes = await scan_processes()
        network_connections = await scan_network_connections()
        open_ports = await scan_open_ports()
        
        # Filter for threats only
        suspicious_processes = [p for p in processes if p.get('severity') in ['medium', 'high', 'critical']]
        high_threat_connections = [c for c in network_connections if c.get('threat_level') in ['high', 'critical']]
        
        # Generate alerts
        alerts = []
        
        # Process alerts
        for proc in suspicious_processes:
            alerts.append({
                "id": f"process_{proc['pid']}",
                "title": f"Suspicious Process: {proc['name']}",
                "description": f"Real threat detected: {proc['name']} (PID: {proc['pid']}) - Threat Score: {proc.get('threat_score', 0)}",
                "severity": proc['severity'],
                "timestamp": proc['created_at'],
                "sourceIp": "Local System",
                "riskScore": proc.get('threat_score', 0),
                "isBlocked": False,
                "type": "process"
            })
        
        # Network alerts
        for conn in high_threat_connections:
            alerts.append({
                "id": f"network_{conn['remote_ip']}_{conn['remote_port']}",
                "title": "Suspicious Network Connection",
                "description": f"Real network threat: {conn['activity_description']}",
                "severity": conn['threat_level'],
                "timestamp": conn['created_at'],
                "sourceIp": conn['remote_ip'],
                "riskScore": 80 if conn['threat_level'] == 'critical' else 65,
                "isBlocked": False,
                "type": "network"
            })
        
        # Port alerts
        for port in open_ports:
            alerts.append({
                "id": f"port_{port['port']}",
                "title": f"Risky Port Open: {port['port']}",
                "description": f"Real vulnerability: {port['reason']}",
                "severity": port['threat_level'],
                "timestamp": port['created_at'],
                "sourceIp": "Local System",
                "riskScore": 90 if port['threat_level'] == 'critical' else 70,
                "isBlocked": False,
                "type": "port"
            })
        
        # Calculate statistics
        total_threats = len(suspicious_processes) + len(high_threat_connections) + len(open_ports)
        active_alerts = len(alerts)
        risk_score = min(100, active_alerts * 15) if active_alerts > 0 else 0
        system_health = max(0, 100 - risk_score)
        
        # Generate recommendations
        recommendations = []
        if suspicious_processes:
            recommendations.append({
                "id": 1,
                "type": "malware",
                "priority": "critical",
                "title": "Investigate Suspicious Processes",
                "description": f"{len(suspicious_processes)} suspicious processes detected",
                "action": "Review and terminate suspicious processes",
                "details": [p['name'] for p in suspicious_processes[:5]]
            })
        
        if open_ports:
            recommendations.append({
                "id": 2,
                "type": "security",
                "priority": "high",
                "title": "Secure Open Ports",
                "description": f"{len(open_ports)} risky ports are open",
                "action": "Close unnecessary ports or implement security",
                "details": [f"Port {p['port']} ({p['service']})" for p in open_ports]
            })
        
        return JSONResponse(content={
            "systemInfo": system_info,
            "stats": {
                "totalThreats": total_threats,
                "activeAlerts": active_alerts,
                "riskScore": round(risk_score, 1),
                "systemHealth": round(system_health, 1),
                "lastScanTime": datetime.now(timezone.utc).isoformat(),
                "scanStatus": "completed"
            },
            "alerts": alerts,
            "scanData": {
                "system_info": system_info,
                "suspicious_processes": suspicious_processes,
                "network_connections": network_connections,
                "risky_ports": open_ports,
                "recommendations": recommendations
            }
        })
        
    except Exception as e:
        print(f"❌ Scan error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Scan failed: {str(e)}"}
        )

@app.get("/scan")
async def quick_scan():
    """Quick scan endpoint"""
    processes = await scan_processes()
    threats = [p for p in processes if p.get('severity') in ['medium', 'high', 'critical']]
    
    return JSONResponse(content={
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_processes": len(processes),
        "threats_detected": len(threats),
        "threats": threats
    })

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return JSONResponse(content={
        "status": "healthy",
        "service": "CyberNova AI - Real-time Threat Scanner",
        "version": "4.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ml_model": "trained" if threat_model.trained else "basic",
        "features": "Real-time scanning, ML threat detection, No database"
    })

# ==================== STARTUP ====================

@app.on_event("startup")
async def startup_event():
    print("🚀 CyberNova AI Real-time Threat Scanner Starting...")
    print("🔍 Real system scanning: ENABLED")
    print("🤖 ML threat detection: ENABLED") 
    print("💾 Database: DISABLED (Live scanning only)")
    print("✅ Ready to scan for real threats!")

if __name__ == "__main__":
    import uvicorn
    print("🔥 Starting CyberNova AI...")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)

