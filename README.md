# P2P Secure Chat

A simple peer-to-peer encrypted chat application built using Python, TCP sockets, symmetric encryption (Fernet), and a Tkinter GUI. Includes real-time crypto price tracking.

---

## Overview

This project demonstrates how to build a secure messaging system using Python and TCP. Two peers exchange encrypted messages using a shared symmetric key. A graphical interface is used for both the client and server.

### Main Features
- GUI client and server  
- End-to-end encrypted messaging (AES + HMAC via Fernet)  
- Key fingerprint display for verification  
- Intro screen explaining encryption  
- Real-time crypto prices (BTC, ETH, SOL, DOGE) with 24-hour change percentages  
- Optional auto-refresh every 30 seconds  
- Background threading for non-blocking networking and API calls  

---

## How Encryption Works

A symmetric key is stored in `secret.key`.  
Both the client and server load the same key at startup.

Messages are encrypted using Fernet, which provides:
- AES-128 encryption  
- HMAC-SHA256 integrity  
- Base64 encoding  

A SHA-256 fingerprint of the key is displayed so users can verify that both peers are using the same encryption key.

---

# Set Up

Install dependencies and activate the virtual environment:

cd p2p-secure-chat
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install cryptography requests

# Running The Project

Run Server (Terminal 1)
cd src
py gui_server.py 5000

Run Client (Terminal 2)
cd src
py gui_client.py <server_ip> 5000
