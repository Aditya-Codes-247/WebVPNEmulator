'use client'

import React, { useState, useEffect, useRef } from 'react'
import { gsap } from 'gsap'
import { Button } from "@/src/app/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/src/app/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/app/components/ui/select"
import { Loader2 } from 'lucide-react'
import "@/public/client.png"
import "@/public/destination-server.png"
import "@/public/packet.png"
import "@/public/vpn-server.png"

const VPN_PROTOCOLS = ['OpenVPN', 'WireGuard', 'IPSec']

interface ProtocolStep {
  id: number
  description: string
}

interface ProtocolInfo {
  name: string
  steps: ProtocolStep[]
  codeImplementation: string
  output: string[]
}

const protocolImplementations: Record<string, ProtocolInfo> = {
  OpenVPN: {
    name: 'OpenVPN',
    steps: [
      { id: 1, description: 'Initiating OpenVPN connection' },
      { id: 2, description: 'Establishing TLS handshake' },
      { id: 3, description: 'Negotiating encryption parameters' },
      { id: 4, description: 'Creating virtual network interface' },
      { id: 5, description: 'Routing traffic through OpenVPN tunnel' },
    ],
    codeImplementation: `
    //Server Side code
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Configure server settings
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8080
KEY = os.urandom(16)  # AES-128 encryption key

# AES cipher initialization
cipher = AES.new(KEY, AES.MODE_CBC, iv=os.urandom(16))

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(1)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

    client_socket, address = server_socket.accept()
    print(f"Connection from {address} established")

    # Receive and decrypt data
    iv = client_socket.recv(16)  # Receive IV from client
    client_cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)

    encrypted_data = client_socket.recv(1024)
    decrypted_data = unpad(client_cipher.decrypt(encrypted_data), AES.block_size)
    print("Received decrypted data:", decrypted_data.decode())

    # Encrypt and send response
    response = b"Hello from the server!"
    encrypted_response = cipher.encrypt(pad(response, AES.block_size))
    client_socket.send(cipher.iv + encrypted_response)  # Send IV and encrypted message

    client_socket.close()

if __name__ == "__main__":
    start_server()

    // Client Side code
    import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Configure client settings
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8080
KEY = os.urandom(16)  # AES-128 encryption key

# AES cipher initialization
iv = os.urandom(16)
cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    # Encrypt and send data
    message = b"Hello from the client!"
    encrypted_message = cipher.encrypt(pad(message, AES.block_size))
    client_socket.send(iv + encrypted_message)  # Send IV and encrypted message

    # Receive and decrypt response
    iv_response = client_socket.recv(16)
    server_cipher = AES.new(KEY, AES.MODE_CBC, iv=iv_response)

    encrypted_response = client_socket.recv(1024)
    decrypted_response = unpad(server_cipher.decrypt(encrypted_response), AES.block_size)
    print("Received decrypted response:", decrypted_response.decode())

    client_socket.close()

if __name__ == "__main__":
    start_client()


    `,
    output: [
      'Initiating OpenVPN connection...',
      'TLS handshake completed',
      'Encryption parameters: AES-256-GCM',
      'Virtual interface tun0 created',
      'Connection status: CONNECTED',
      'Routed packet: <OpenVPN Encrypted Packet>'
    ]
  },
  WireGuard: {
    name: 'WireGuard',
    steps: [
      { id: 1, description: 'Initiating WireGuard connection' },
      { id: 2, description: 'Performing key exchange' },
      { id: 3, description: 'Establishing secure tunnel' },
      { id: 4, description: 'Configuring network interface' },
      { id: 5, description: 'Routing traffic through WireGuard tunnel' },
    ],
    codeImplementation: `
import os
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.hash import blake2b
from nacl.encoding import RawEncoder
from nacl.bindings import crypto_scalarmult
import socket

class WireGuardPeer:
    def __init__(self):
        # Generate a new key pair for this peer
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key

    def initiate_handshake(self, peer_public_key):
        # Derive shared secret using X25519
        shared_secret = self.private_key.exchange(peer_public_key)
        
        # Compute hashed shared secret with BLAKE2s
        hashed_secret = blake2b(shared_secret, digest_size=32, encoder=RawEncoder)
        
        # Encrypt handshake initiation message (simple example)
        return hashed_secret

    def receive_handshake(self, initiation_data, peer_public_key):
        # Verify and decrypt initiation handshake (skipped for simplicity)
        shared_secret = self.private_key.exchange(peer_public_key)
        return blake2b(shared_secret, digest_size=32, encoder=RawEncoder)

def main():
    # Example setup of two peers
    alice = WireGuardPeer()
    bob = WireGuardPeer()

    # Alice initiates a handshake with Bob
    hashed_secret_from_alice = alice.initiate_handshake(bob.public_key)
    
    # Bob receives handshake and verifies
    hashed_secret_from_bob = bob.receive_handshake(hashed_secret_from_alice, alice.public_key)

    if hashed_secret_from_alice == hashed_secret_from_bob:
        print("Handshake successful!")
    else:
        print("Handshake failed.")

if __name__ == "__main__":
    main()

    `,
    output: [
      'Initiating WireGuard connection...',
      'Key exchange completed',
      'Secure tunnel established',
      'Interface wg0 configured',
      'Connection status: ACTIVE',
      'Routed packet: <WireGuard Encrypted Packet>'
    ]
  },
  IPSec: {
    name: 'IPSec',
    steps: [
      { id: 1, description: 'Initiating IPSec connection' },
      { id: 2, description: 'Performing IKE negotiation' },
      { id: 3, description: 'Establishing Security Associations' },
      { id: 4, description: 'Configuring IPSec policies' },
      { id: 5, description: 'Routing traffic through IPSec tunnel' },
    ],
    codeImplementation: `
// Key Exchange using Diffie Hellman
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Generate DH parameters
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# Server-side DH key pair generation
server_private_key = parameters.generate_private_key()
server_public_key = server_private_key.public_key()

# Client-side DH key pair generation
client_private_key = parameters.generate_private_key()
client_public_key = client_private_key.public_key()

# Exchange public keys and generate a shared secret
shared_key = server_private_key.exchange(client_public_key)

# Derive a session key from the shared secret
session_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key)

print("Session key established:", session_key)


// AES and HMAC for encryption and Integrity
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
import os

# Encrypt a message using AES-GCM
def encrypt_data(plain_text, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_text) + encryptor.finalize()
    return iv, cipher_text, encryptor.tag

# Decrypt a message
def decrypt_data(cipher_text, iv, tag, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(cipher_text) + decryptor.finalize()

# HMAC for integrity
def generate_hmac(data, key):
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

# Example usage
message = b"Secret message for VPN"
iv, cipher_text, tag = encrypt_data(message, session_key)
hmac = generate_hmac(cipher_text, session_key)

print("Encrypted Message:", cipher_text)
print("HMAC:", hmac)
print("Decrypted Message:", decrypt_data(cipher_text, iv, tag, session_key))

// Authentication Header for packet integrity
from scapy.all import IP, Raw
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes

# Example IP packet with Scapy
def create_packet(data, src_ip, dst_ip, key):
    packet = IP(src=src_ip, dst=dst_ip) / Raw(load=data)
    
    # Calculate HMAC for the packet data (integrity)
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(bytes(packet))
    packet_hmac = h.finalize()
    
    return packet, packet_hmac

# Verify packet integrity with HMAC
def verify_packet(packet, packet_hmac, key):
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(bytes(packet))
    try:
        h.verify(packet_hmac)
        print("Packet is authentic.")
    except InvalidSignature:
        print("Packet verification failed.")

# Example usage
src_ip = "192.168.1.1"
dst_ip = "192.168.1.2"
data = b"VPN packet data"

packet, packet_hmac = create_packet(data, src_ip, dst_ip, session_key)
verify_packet(packet, packet_hmac, session_key)

    `,
    output: [
      'Initiating IPSec connection...',
      'IKE negotiation completed',
      'Security Associations established',
      'IPSec policies configured',
      'Connection status: ESTABLISHED',
      'Routed packet: <IPSec Encrypted Packet>'
    ]
  }
}

export default function VPNEmulator() {
  const [selectedProtocol, setSelectedProtocol] = useState<string>('')
  const [protocolInfo, setProtocolInfo] = useState<ProtocolInfo | null>(null)
  const [currentStep, setCurrentStep] = useState<number>(0)
  const [isLoading, setIsLoading] = useState<boolean>(false)
  const stepsRef = useRef<(HTMLLIElement | null)[]>([])
  const cardRef = useRef<HTMLDivElement>(null)
  const titleRef = useRef<HTMLHeadingElement>(null)
  const selectRef = useRef<HTMLDivElement>(null)
  const packetRef = useRef<SVGImageElement>(null)
  const outputRef = useRef<HTMLPreElement>(null)

  useEffect(() => {
    // Initial animation
    if (cardRef.current && titleRef.current && selectRef.current) {
      gsap.from(cardRef.current, { opacity: 0, y: 50, duration: 1, ease: 'power3.out' })
      gsap.from(titleRef.current, { opacity: 0, y: 20, duration: 1, delay: 0.5, ease: 'power3.out' })
      gsap.from(selectRef.current, { opacity: 0, y: 20, duration: 1, delay: 0.7, ease: 'power3.out' })
    }
  }, [])

  useEffect(() => {
    if (selectedProtocol) {
      fetchProtocolInfo(selectedProtocol)
    }
  }, [selectedProtocol])

  useEffect(() => {
    if (protocolInfo) {
      animateSteps()
    }
  }, [protocolInfo, currentStep])

  const fetchProtocolInfo = async (protocol: string) => {
    setIsLoading(true)
    try {
      // Simulating API call with setTimeout
      await new Promise(resolve => setTimeout(resolve, 1500))
      setProtocolInfo(protocolImplementations[protocol])
      setCurrentStep(0)
    } catch (error) {
      console.error('Error fetching protocol info:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const animateSteps = () => {
    if (!protocolInfo || stepsRef.current.length === 0) return

    gsap.to(stepsRef.current, {
      opacity: 0,
      y: 20,
      stagger: 0.2,
      duration: 0.5,
      ease: 'power2.out',
    })

    if (stepsRef.current[currentStep]) {
      gsap.to(stepsRef.current[currentStep], {
        opacity: 1,
        y: 0,
        duration: 0.5,
        delay: 0.5,
        ease: 'power2.out',
        onComplete: () => {
          if (currentStep < protocolInfo.steps.length - 1) {
            setTimeout(() => setCurrentStep(currentStep + 1), 1000)
          }
        },
      })
    }

    // Animate packet
    if (packetRef.current) {
      const timeline = gsap.timeline()
      
      if (currentStep === 0) {
        timeline.to(packetRef.current, { opacity: 1, scale: 1, duration: 0.5 })
      } else if (currentStep === 1) {
        timeline.to(packetRef.current, { x: 100, y: -50, duration: 1, ease: 'power1.inOut' })
      } else if (currentStep === 2) {
        timeline.to(packetRef.current, { x: 200, y: 0, duration: 1, ease: 'power1.inOut' })
      } else if (currentStep === 3) {
        timeline.to(packetRef.current, { x: 300, y: -50, duration: 1, ease: 'power1.inOut' })
      } else if (currentStep === 4) {
        timeline.to(packetRef.current, { x: 400, y: 0, duration: 1, ease: 'power1.inOut' })
      }
    }

    // Animate output
    if (outputRef.current && protocolInfo.output) {
      gsap.to(outputRef.current.children, {
        opacity: 1,
        y: 0,
        stagger: 0.5,
        duration: 0.5,
        ease: 'power2.out',
      })
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-700 flex items-center justify-center p-4">
      <Card className="w-full max-w-[90vw] bg-white/10 backdrop-blur-md" ref={cardRef}>
        <CardHeader>
          <CardTitle className="text-3xl font-bold text-center text-white" ref={titleRef}>VPN Protocol Emulator</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="mb-6" ref={selectRef}>
            <Select onValueChange={(value) => setSelectedProtocol(value)}>
              <SelectTrigger className="bg-white/20 text-white border-white/30">
                <SelectValue placeholder="Select a VPN protocol" />
              </SelectTrigger>
              <SelectContent>
                {VPN_PROTOCOLS.map((protocol) => (
                  <SelectItem key={protocol} value={protocol}>
                    {protocol}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {isLoading && (
            <div className="flex justify-center items-center h-40">
              <Loader2 className="w-8 h-8 animate-spin text-white" />
            </div>
          )}
          {protocolInfo && !isLoading && (
            <div>
              <h3 className="text-xl font-semibold mb-4 text-white">{protocolInfo.name} Protocol Steps:</h3>
              <div className="relative mb-8 h-48">
                <svg width="100%" height="100%" viewBox="0 0 500 100" className="absolute top-0 left-0">
                  <image href="/client.png" x="0" y="25" width="50" height="50" />
                  <text x="25" y="90" textAnchor="middle" fill="white" fontSize="12">Client</text>
                  
                  <image href="/vpn-server.png" x="225" y="0" width="50" height="50" />
                  <text x="250" y="65" textAnchor="middle" fill="white" fontSize="12">VPN Server</text>
                  
                  <image href="/destination-server.png" x="450" y="25" width="50" height="50" />
                  <text x="475" y="90" textAnchor="middle" fill="white" fontSize="12">Destination</text>
                  
                  <line x1="50" y1="50" x2="225" y2="25" stroke="white" strokeWidth="2" strokeDasharray="5,5" />
                  <line x1="275" y1="25" x2="450" y2="50" stroke="white" strokeWidth="2" strokeDasharray="5,5" />
                  
                  <image 
                    ref={packetRef} 
                    href="/packet.png" 
                    x="0" 
                    y="40" 
                    width="20" 
                    height="20" 
                    opacity="0" 
                    transform="scale(0.5)"
                  />
                </svg>
              </div>
              <ul className="space-y-4 mb-8">
                {protocolInfo.steps.map((step, index) => (
                  <li
                    key={step.id}
                    ref={(el) => {
                      stepsRef.current[index] = el;  // Assignment only, no return value
                    }}
                    className="opacity-0 transform translate-y-4"
                  >
                    <Card className="bg-white/20 backdrop-blur-sm border-white/30">
                      <CardContent className="p-4">
                        <p className="text-white">{step.description}</p>
                      </CardContent>
                    </Card>
                  </li>
                ))}
              </ul>
              <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-8">
                <div>
                  <h4 className="text-lg font-semibold mb-2 text-white">Code Implementation:</h4>
                  <pre className="bg-gray-800 p-4 rounded-md overflow-x-auto">
                    <code className="text-sm text-white">{protocolInfo.codeImplementation}</code>
                  </pre>
                </div>
                <div>
                  <h4 className="text-lg font-semibold mb-2 text-white">Protocol Output:</h4>
                  <pre ref={outputRef} className="bg-gray-800 p-4 rounded-md  overflow-x-auto h-full">
                    {protocolInfo.output.map((line, index) => (
                      <code key={index} className="text-sm text-white block opacity-0 transform translate-y-2">
                        {line}
                      </code>
                    ))}
                  </pre>
                </div>
              </div>
            </div>
          )}
          {currentStep === (protocolInfo?.steps.length ?? 0) - 1 && (
            <Button
              className="mt-6 bg-blue-500 hover:bg-blue-600 text-white"
              onClick={() => {
                setCurrentStep(0)
                animateSteps()
              }}
            >
              Restart Animation
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  )
}