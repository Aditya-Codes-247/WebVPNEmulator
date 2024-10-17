from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

# Define the response model for VPN protocol data flow
class VPNResponse(BaseModel):
    dataFlow: list

# VPN emulation endpoint
@app.get("/start-vpn/{protocol}", response_model=VPNResponse)
async def start_vpn(protocol: str):
    """
    Endpoint to simulate VPN protocol based on user input (PPTP, L2TP, IPSec).
    Returns the data flow representing the steps of each protocol.
    """

    if protocol == "PPTP":
        data_flow = [
            {"label": "PPTP Start", "description": "Establishing PPTP tunnel"},
            {"label": "Authentication", "description": "Using MS-CHAP for user authentication"},
            {"label": "Data Encryption", "description": "Encrypting data using MPPE (Microsoft Point-to-Point Encryption)"}
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
        # Error handling for unsupported protocol
        data_flow = [{"label": "Error", "description": "Unknown protocol selected. Please select a valid VPN protocol."}]
    
    # Return the VPN protocol's data flow
    return VPNResponse(dataFlow=data_flow)
