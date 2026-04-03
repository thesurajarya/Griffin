from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import shutil
import os
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

app = FastAPI(title="PCAP Vulnerability Correlator API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "temp_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Define the expected JSON payload for login
class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(credentials: LoginRequest):
    """
    Validates credentials against the secure .env file.
    """
    env_user = os.getenv("ADMIN_USERNAME")
    env_pass = os.getenv("ADMIN_PASSWORD")

    # Prevent login if .env is missing
    if not env_user or not env_pass:
        raise HTTPException(status_code=500, detail="Server configuration error.")

    if credentials.username == env_user and credentials.password == env_pass:
        # Return a fake JWT token for the frontend to store
        return {"access_token": "soc_admin_auth_token_987654321", "token_type": "bearer"}
    else:
        raise HTTPException(status_code=401, detail="Invalid username or password")

@app.post("/api/analyze-pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith(('.pcap', '.pcapng')):
        return {"error": "Invalid file format."}

    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {
        "message": "File received successfully",
        "filename": file.filename,
        "status": "Analysis pending..."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)