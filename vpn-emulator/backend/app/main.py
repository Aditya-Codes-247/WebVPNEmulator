from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# Allow CORS (Cross-Origin Requests)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Allow requests from React frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class VPNResponse(BaseModel):
    dataFlow: list

@app.get("/start-vpn/{protocol}", response_model=VPNResponse)
async def start_vpn(protocol: str):
    # VPN protocol emulation logic
    if protocol == "PPTP":
        data_flow = [
            {"label": "PPTP Start", "description": "Establishing PPTP tunnel"},
            {"label": "Authentication", "description": "Using MS-CHAP for user authentication"},
            {"label": "Data Encryption", "description": "Encrypting data using MPPE"}
        ]
    elif protocol == "L2TP":
        data_flow = [
            {"label": "L2TP Start", "description": "Establishing L2TP tunnel"},
            {"label": "IPsec", "description": "Using IPsec for encryption"},
            {"label": "Data Transmission", "description": "Encrypting data using AES-128"}
        ]
    elif protocol == "IPSec":
        data_flow = [
            {"label": "IPSec Start", "description": "IPSec tunnel established"},
            {"label": "IKE Phase 1", "description": "Negotiating security associations"},
            {"label": "Data Encryption", "description": "Encrypting data using AES-256"}
        ]
    else:
        data_flow = [{"label": "Error", "description": "Unknown protocol"}]

    return VPNResponse(dataFlow=data_flow)
