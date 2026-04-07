from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import shutil
from dotenv import load_dotenv
from scapy.all import PcapReader, IP, TCP, UDP

# Load admin credentials from your .env file
load_dotenv(".env2");

app = FastAPI(title="Griffin SOC Backend Engine")

# Allow your React frontend (typically running on port 5173 or 3000) to communicate with this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, change this to your specific frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure a temporary directory exists for uploaded PCAP files
UPLOAD_DIR = "temp_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------------------------------------------------
# AUTHENTICATION ROUTE
# ---------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(credentials: LoginRequest):
    """Validates credentials against the .env file."""
    env_user = os.getenv("ADMIN_USERNAME")
    env_pass = os.getenv("ADMIN_PASSWORD")

    if not env_user or not env_pass:
        raise HTTPException(status_code=500, detail="Server configuration error. Missing .env variables.")

    if credentials.username == env_user and credentials.password == env_pass:
        return {"access_token": "soc_admin_auth_token_987654321", "token_type": "bearer"}
    else:
        raise HTTPException(status_code=401, detail="Invalid username or password")

# ---------------------------------------------------------
# PCAP ANALYSIS ROUTE
# ---------------------------------------------------------
@app.post("/api/analyze-pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    """Receives a PCAP, saves it temporarily, and runs passive asset discovery."""
    
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Invalid file format. Only .pcap and .pcapng are allowed.")

    file_path = os.path.join(UPLOAD_DIR, file.filename)
    
    # Save the uploaded file to disk safely
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    unique_ips = set()
    unique_ports = set()
    packet_count = 0

    try:
        # Use PcapReader to stream the file (memory efficient for large captures)
        with PcapReader(file_path) as pcap_reader:
            for pkt in pcap_reader:
                packet_count += 1
                
                # Extract IP Addresses (Passive Asset Discovery)
                if IP in pkt:
                    unique_ips.add(pkt[IP].src)
                    unique_ips.add(pkt[IP].dst)
                
                # Extract Ports (Service Discovery)
                if TCP in pkt:
                    unique_ports.add(pkt[TCP].dport)
                    unique_ports.add(pkt[TCP].sport)
                elif UDP in pkt:
                    unique_ports.add(pkt[UDP].dport)
                    unique_ports.add(pkt[UDP].sport)
                
                # Stop after 10,000 packets to keep the demo fast and responsive
                if packet_count > 10000:
                    break
                    
    except Exception as e:
        # Clean up the corrupted file if parsing crashes
        os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Failed to parse PCAP: {str(e)}")

    # Clean up the temp file after successful analysis
    os.remove(file_path)

    # Return the Threat Intelligence Data back to the React frontend
    return {
        "filename": file.filename,
        "total_packets_analyzed": packet_count,
        "assets_discovered": list(unique_ips),
        "active_ports": list(unique_ports),
        "status": "Analysis Complete"
    }

if __name__ == "__main__":
    import uvicorn
    # Starts the local server on http://127.0.0.1:8000
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)