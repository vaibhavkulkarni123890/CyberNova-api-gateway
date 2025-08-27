# device-agent/agent.py - Real Threat Scanner
import time, json, random, requests, platform, socket, psutil, os, subprocess
from datetime import datetime, timezone
import hashlib
import re

GATEWAY = "http://localhost:8080"  # API Gateway
DEVICE_ID = f"{platform.node()}-{random.randint(1000,9999)}"
UA = f"Agent/1.0 ({platform.system()} {platform.release()})"

# Known malicious process patterns
SUSPICIOUS_PROCESSES = [
    'mimikatz', 'powershell_ise', 'cmd.exe', 'wscript', 'cscript',
    'regsvr32', 'rundll32', 'mshta', 'bitsadmin', 'certutil',
    'powershell', 'wmic', 'netsh', 'schtasks', 'at.exe'
]

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.com', '.vbs', '.js']

# Known risky ports
RISKY_PORTS = [3389, 445, 135, 139, 1433, 3306, 5432, 22, 23, 21]

SAFE_PROCESSES = {p.lower() for p in [
    'explorer.exe', 'svchost.exe', 'chrome.exe', 'steam.exe', 'wudfhost.exe',
    'language_server_windows.exe', 'vmtoolsd.exe', 'vmwaretray.exe', 'powershell.exe',
    'taskhostw.exe', 'msedge.exe', 'teams.exe', 'onedrive.exe', 'mspmsnsv.exe'
]}

def scan_real_processes():
    """Scan actual running processes for threats with refined detection to reduce false positives"""
    threats = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent', 'username']):
            try:
               
                name = proc_info.get('name', '').lower()
                cmdline = " ".join(cmdline_list).lower()
                exe_path = (proc_info.get('exe') or '').lower()
                cpu = proc_info.get('cpu_percent') or 0
                mem = proc_info.get('memory_percent') or 0

                # Skip system idle process
                if proc_info.get('pid') == 0 or name == '':
                    continue

                threat_level = 'safe'
                reasons = []

                # Whitelist known safe processes
                if name in SAFE_PROCESSES:
                    # Check suspicious command line only if resource usage high or path suspicious
                    suspicious_args = ['bypass', 'encoded', 'downloadstring', 'invoke-expression']
                    if any(arg in cmdline for arg in suspicious_args):
                        if ('temp' in exe_path) or (cpu > 50) or (mem > 50):
                            threat_level = 'high'
                            reasons.append('Suspicious command line with elevated resource usage or temp path')
                        else:
                            threat_level = 'medium'
                            reasons.append('Suspicious command line but low resource usage')
                    else:
                        threat_level = 'safe'

                else:
                    # Unknown or unlisted process - apply heuristic rules
                    if 'temp' in exe_path or 'tmp' in exe_path:
                        threat_level = 'high'
                        reasons.append('Running from temporary directory')

                    if cpu > 80:
                        threat_level = max(threat_level, 'high')
                        reasons.append(f'High CPU usage: {cpu:.1f}%')

                    if mem > 70:
                        threat_level = max(threat_level, 'high')
                        reasons.append(f'High Memory usage: {mem:.1f}%')

                    if any(pat in name for pat in SUSPICIOUS_PROCESSES):
                        threat_level = 'high'
                        reasons.append('Matches suspicious name pattern')

                    # Further reduce False Positives: 
                    # Ignore low CPU/memory if name not suspicious
                    if threat_level == 'safe' and (cpu < 50 and mem < 50):
                        threat_level = 'safe'

                # Only report if not safe
                if threat_level != 'safe':
                    threats.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'exe_path': proc_info['exe'],
                        'cmdline': ' '.join(cmdline_list),
                        'cpu_percent': cpu,
                        'memory_percent': mem,
                        'username': proc_info.get('username'),
                        'threat_level': threat_level,
                        'threat_reasons': reasons,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        print(f"Error scanning processes: {e}")

    return threats



def scan_real_network_connections():
    """Scan actual network connections for threats"""
    threats = []
    
    try:
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port = conn.laddr.port
                
                threat_level = 'safe'
                activity_description = f"Connection to {remote_ip}:{remote_port}"
                
                # Check for connections to suspicious ports
                if remote_port in [1337, 31337, 12345, 54321, 9999, 6667]:
                    threat_level = 'critical'
                    activity_description = f"Connection to suspicious port {remote_port} (commonly used by malware)"
                
                # Check for connections from risky local ports
                elif local_port in RISKY_PORTS:
                    threat_level = 'high'
                    activity_description = f"Outbound connection from risky port {local_port}"
                
                # Check for unusual high ports
                elif remote_port > 49152:
                    threat_level = 'medium'
                    activity_description = f"Connection to high port {remote_port} (may indicate P2P or malware)"
                
                # Check for private IP ranges that shouldn't be external
                elif remote_ip.startswith(('10.', '172.16.', '192.168.')):
                    threat_level = 'low'
                    activity_description = f"Connection to private IP {remote_ip}"
                
                # Only report threats
                if threat_level != 'safe':
                    try:
                        # Try to get process info
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        process_name = proc.name() if proc else 'Unknown'
                    except:
                        process_name = 'Unknown'
                    
                    threats.append({
                        "local_ip": conn.laddr.ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "status": conn.status,
                        "pid": conn.pid,
                        "process_name": process_name,
                        "threat_level": threat_level,
                        "activity_description": activity_description,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    
    except Exception as e:
        print(f"Network scan error: {e}")
    
    return threats

def scan_real_open_ports():
    """Scan for actually open ports on the system"""
    threats = []
    
    try:
        # Get listening connections
        connections = psutil.net_connections(kind='inet')
        listening_ports = []
        
        for conn in connections:
            if conn.status == 'LISTEN':
                port = conn.laddr.port
                if port not in listening_ports:
                    listening_ports.append(port)
        
        # Check each listening port for risks
        for port in listening_ports:
            threat_level = 'safe'
            service = 'Unknown'
            reason = ''
            
            # Known risky ports
            if port == 3389:
                threat_level = 'critical'
                service = 'Remote Desktop (RDP)'
                reason = 'RDP exposed - high risk of brute force attacks'
            elif port == 445:
                threat_level = 'high'
                service = 'SMB File Sharing'
                reason = 'SMB exposed - risk of ransomware and data theft'
            elif port == 22:
                threat_level = 'high'
                service = 'SSH'
                reason = 'SSH exposed - risk of brute force attacks'
            elif port == 23:
                threat_level = 'critical'
                service = 'Telnet'
                reason = 'Telnet is unencrypted and highly insecure'
            elif port == 21:
                threat_level = 'high'
                service = 'FTP'
                reason = 'FTP exposed - often unencrypted'
            elif port in [135, 139]:
                threat_level = 'medium'
                service = 'Windows RPC/NetBIOS'
                reason = 'Windows networking services exposed'
            elif port in [1433, 3306, 5432]:
                threat_level = 'high'
                service = 'Database'
                reason = 'Database port exposed to network'
            elif port < 1024 and port not in [80, 443]:
                threat_level = 'medium'
                service = f'System Service (Port {port})'
                reason = 'System service exposed'
            
            # Only report risky ports
            if threat_level != 'safe':
                threats.append({
                    "port": port,
                    "service": service,
                    "threat_level": threat_level,
                    "reason": reason,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                
    except Exception as e:
        print(f"Port scan error: {e}")
    
    return threats

def get_real_system_info():
    """Get actual system information"""
    try:
        return {
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "cpu_count": psutil.cpu_count(),
            "memory_total": psutil.virtual_memory().total,
            "disk_usage": psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent,
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }
    except Exception as e:
        print(f"System info error: {e}")
        return {"hostname": platform.node(), "os": platform.system()}

def perform_real_threat_scan():
    """Perform comprehensive real threat scan"""
    print("🔍 Starting real threat scan...")
    
    scan_results = {
        "device_id": DEVICE_ID,
        "scan_type": "real_threat_scan",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system_info": get_real_system_info(),
        "suspicious_processes": scan_real_processes(),
        "network_threats": scan_real_network_connections(),
        "risky_ports": scan_real_open_ports()
    }
    
    total_threats = (len(scan_results["suspicious_processes"]) + 
                    len(scan_results["network_threats"]) + 
                    len(scan_results["risky_ports"]))
    
    scan_results["total_threats"] = total_threats
    
    print(f"✅ Scan complete: {total_threats} threats detected")
    print(f"   - Suspicious processes: {len(scan_results['suspicious_processes'])}")
    print(f"   - Network threats: {len(scan_results['network_threats'])}")
    print(f"   - Risky ports: {len(scan_results['risky_ports'])}")
    
    return scan_results

def send_scan_results(scan_results):
    """Send scan results to API gateway"""
    try:
        response = requests.post(
            f"{GATEWAY}/api/real-scan/results",
            json=scan_results,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            print("✅ Scan results sent successfully")
            return response.json()
        else:
            print(f"❌ Failed to send results: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"❌ Error sending results: {e}")
        return None

if __name__ == "__main__":
    print("🛡️ CyberNova AI - Real Threat Scanner Starting...")
    print(f"📡 Gateway: {GATEWAY}")
    print(f"🖥️ Device: {DEVICE_ID}")
    
    while True:
        try:
            # Perform real threat scan
            scan_results = perform_real_threat_scan()
            
            # Send results to gateway
            send_scan_results(scan_results)
            
            # Wait before next scan (scan every 30 seconds)
            print("⏳ Waiting 30 seconds before next scan...")
            time.sleep(30)
            
        except KeyboardInterrupt:
            print("\n🛑 Scanner stopped by user")
            break
        except Exception as e:
            print(f"❌ Scanner error: {e}")
            time.sleep(10)  # Wait 10 seconds on error
