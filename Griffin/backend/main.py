from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import shutil
import requests
import time
import re  # NEW: Required for parsing standard .nmap text files
import xml.etree.ElementTree as ET # Built-in XML parser for Nmap XML
from dotenv import load_dotenv
from scapy.all import PcapReader, IP, TCP, UDP

# Load credentials and your NVD API Key
load_dotenv(".env2") 

app = FastAPI(title="Griffin SOC Backend Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "temp_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------------------------------------------------
# THREAT INTELLIGENCE ENGINE (Live NVD Integration)
# ---------------------------------------------------------
PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP"
}

# In-memory cache so we don't spam the NVD API for duplicate services
cve_cache = {}

def fetch_real_cves(service_name: str):
    """Queries the real NVD API for vulnerabilities related to a service."""
    if service_name in cve_cache:
        return cve_cache[service_name]

    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        print("Warning: NVD_API_KEY not found in .env2")
        return []

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    params = {
        "keywordSearch": service_name,
        "resultsPerPage": 3
    }
    headers = {
        "apiKey": api_key
    }

    try:
        # Throttle the API calls to stay under the NVD limit (50 requests / 30 seconds)
        time.sleep(0.6)
        
        response = requests.get(url, params=params, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            parsed_cves = []
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "Unknown ID")
                
                descriptions = cve_data.get("descriptions", [])
                desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available.")
                
                metrics = cve_data.get("metrics", {})
                severity = "UNKNOWN"
                if "cvssMetricV31" in metrics:
                    severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                elif "cvssMetricV30" in metrics:
                    severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
                elif "cvssMetricV2" in metrics:
                    severity = metrics["cvssMetricV2"][0]["baseSeverity"]

                parsed_cves.append({
                    "cve": cve_id,
                    "severity": severity,
                    "desc": desc_text
                })
            
            cve_cache[service_name] = parsed_cves
            return parsed_cves
            
        else:
            print(f"NVD API Error: {response.status_code} - {response.text}")
            return []

    except Exception as e:
        print(f"Failed to connect to NVD: {str(e)}")
        return []


# ---------------------------------------------------------
# AUTHENTICATION ROUTE
# ---------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(credentials: LoginRequest):
    env_user = os.getenv("ADMIN_USERNAME")
    env_pass = os.getenv("ADMIN_PASSWORD")

    if credentials.username == env_user and credentials.password == env_pass:
        return {"access_token": "soc_admin_auth_token_987654321", "token_type": "bearer"}
    else:
        raise HTTPException(status_code=401, detail="Invalid username or password")


# ---------------------------------------------------------
# PCAP & NMAP ANALYSIS ROUTE
# ---------------------------------------------------------
@app.post("/api/analyze-pcap")
async def analyze_file(file: UploadFile = File(...)):
    # UPGRADED: Now accepts .pcap, .pcapng, .xml, and .nmap
    if not file.filename.endswith(('.pcap', '.pcapng', '.xml', '.nmap')):
        raise HTTPException(status_code=400, detail="Invalid file format.")

    file_path = os.path.join(UPLOAD_DIR, file.filename)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    unique_ips = set()
    unique_ports = set()
    nmap_services = {} # Holds exact service names discovered by Nmap
    packet_count = 0
    
    # Determine the file type
    is_nmap_xml = file.filename.endswith('.xml')
    is_nmap_text = file.filename.endswith('.nmap')

    try:
        if is_nmap_xml:
            # --- NMAP XML PARSING LOGIC ---
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            for host in root.findall('host'):
                for address in host.findall('address'):
                    if address.get('addrtype') == 'ipv4':
                        unique_ips.add(address.get('addr'))
                
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            port_id = int(port.get('portid'))
                            unique_ports.add(port_id)
                            
                            service = port.find('service')
                            if service is not None:
                                svc_name = service.get('name')
                                if svc_name:
                                    nmap_services[port_id] = svc_name.upper()

        elif is_nmap_text:
            # --- NMAP TEXT PARSING LOGIC (.nmap) ---
            # Open as plain text, ignoring unreadable characters
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # Regex pattern to find lines like: Nmap scan report for 192.168.1.1
            ip_pattern = re.compile(r"Nmap scan report for .*?(\d{1,3}(?:\.\d{1,3}){3})")
            # Regex pattern to find lines like: 22/tcp open ssh
            port_pattern = re.compile(r"^(\d+)/(?:tcp|udp)\s+open\s+([^\s]+)")

            for line in lines:
                ip_match = ip_pattern.search(line)
                if ip_match:
                    unique_ips.add(ip_match.group(1))

                port_match = port_pattern.search(line.strip())
                if port_match:
                    port_id = int(port_match.group(1))
                    service_name = port_match.group(2)
                    unique_ports.add(port_id)
                    nmap_services[port_id] = service_name.upper()

        else:
            # --- SCAPY PCAP PARSING LOGIC ---
            with PcapReader(file_path) as pcap_reader:
                for pkt in pcap_reader:
                    packet_count += 1
                    
                    if IP in pkt:
                        unique_ips.add(pkt[IP].src)
                        unique_ips.add(pkt[IP].dst)
                    
                    if TCP in pkt:
                        unique_ports.add(pkt[TCP].dport)
                        unique_ports.add(pkt[TCP].sport)
                    elif UDP in pkt:
                        unique_ports.add(pkt[UDP].dport)
                        unique_ports.add(pkt[UDP].sport)
                    
                    if packet_count > 10000:
                        break

    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Failed to parse file: {str(e)}")

    if os.path.exists(file_path):
        os.remove(file_path)

    # --- Live Correlation Engine ---
    discovered_services = []
    threat_intel = []

    for port in unique_ports:
        # If Nmap gave us the exact service, use it. Otherwise, fall back to our Scapy guess map.
        service_name = nmap_services.get(port, PORT_SERVICE_MAP.get(port, "Unknown"))
        discovered_services.append({"port": port, "service": service_name})
        
        # Only query NVD for known services
        if service_name != "Unknown":
            real_cves = fetch_real_cves(service_name)
            
            for vuln in real_cves:
                threat_intel.append({
                    "port": port,
                    "service": service_name,
                    "cve": vuln["cve"],
                    "severity": vuln["severity"],
                    "desc": vuln["desc"]
                })

    # Adjust UI output based on file type
    display_packet_count = "N/A (Nmap Scan)" if (is_nmap_xml or is_nmap_text) else packet_count

    return {
        "filename": file.filename,
        "total_packets_analyzed": display_packet_count,
        "assets_discovered": list(unique_ips),
        "services": discovered_services,
        "vulnerabilities": threat_intel,
        "status": "Analysis Complete"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)