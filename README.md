# Zero Trust Architecture for Enterprise Security

> **Minor Project 2: Zero Trust Architecture for Enterprise Security**  
> **Core Principle:** *"Never trust, always verify."*  
> **Contributors:** Mahi Patel & Jainam Shah (Group C)  
> **Academic Year:** 2026–2027  

---

## 📌 Project Overview

Traditional enterprise networks rely on perimeter security (the "castle-and-moat" model). Once an attacker bypasses the perimeter firewall or compromises an employee's credentials, they gain unrestricted lateral access across internal network subnets.

**Zero-Trust Console** is a full-stack security platform and local enterprise laboratory that enforces continuous, multi-layered verification on every request. It eliminates implicit trust and verifies user identity, role entitlements, device fingerprints, and token authenticity before granting access to protected workload services.

---

## 🛡️ Key Security Features

1. **Multi-Factor Authentication (MFA):**
   - Implements **RFC 6238 TOTP** (Time-Based One-Time Password).
   - Generates per-user secret keys, renders standard QR codes, and verifies 30-second rolling 6-digit codes.
2. **Role-Based Access Control (RBAC):**
   - Three standardized enterprise roles: **Admin**, **Editor**, and **Viewer**.
   - Interactive role-permission matrix controlling access to dashboard data, user management, and security policies.
3. **Session & Token Management:**
   - Short-lived JSON Web Access Tokens (**15 minutes** expiration).
   - Long-lived Refresh Tokens (**7 days**) with **strict single-use rotation** and Redis JTI revocation blacklist to prevent replay attacks.
4. **Device Fingerprinting:**
   - Client-side cryptographic browser fingerprinting bound to user sessions to detect hijacked tokens used on unrecognized machines.
5. **Network Micro-segmentation:**
   - Docker containerization dividing infrastructure into three isolated bridge networks: `frontend-net`, `app-net`, and `db-net`.
   - Prevents lateral movement from compromised frontend servers to internal databases.
6. **Data Encryption at Rest & in Transit:**
   - Field-level database encryption using **AES-256-GCM** with fresh 12-byte random IVs and 16-byte cryptographic integrity tags.
7. **Threat Lab Automated Penetration Testing:**
   - Automated attack simulator testing 9 real-world threat vectors with a **100% defense success rate**.

---

## 📂 Project Structure

```text
Zero-Trust-Architecture-for-Enterprise-Security/
├── node-express/          # Authentication Gateway & Policy Enforcement Point (Port 4000)
│   ├── server.js          # Express gateway & API router
│   ├── policyEngine.js    # Zero Trust dynamic policy decision engine
│   ├── mfaService.js      # RFC 6238 TOTP enrollment and verification
│   ├── cryptoService.js   # AES-256-GCM authenticated encryption service
│   ├── threatLab.js       # Automated 9-vector penetration testing suite
│   └── zero_trust.sqlite  # Persistent SQLite database file
├── python-fastapi/        # Protected Workload Resource Service (Port 8001)
│   ├── zero_trust_auth.py # FastAPI service validating JWT tokens
│   └── requirements.txt   # Python dependencies
├── react-frontend/        # Modern Clean-Light Web Interface (Port 5173)
│   ├── src/               # React components, auth hooks, and navigation shell
│   └── package.json       # React 18, Vite, and Tailwind CSS dependencies
├── report/                # Final 25-Page College Project Report (.docx, .pdf, notes)
│   ├── Minor_Project_2_Report.docx
│   ├── Minor_Project_2_Report.pdf
│   ├── report_notes.md
│   └── screenshots/       # Application verification screenshots
├── attacker/              # Simulated penetration testing container
├── start.bat              # Single-click launcher for all 3 services
├── run_all.bat            # Multi-service batch launcher
└── docker-compose.yml     # Multi-container micro-segmentation setup
```

---

## 🚀 Quick Start (How to Run)

### Method 1: Single-Click Launch (Recommended for Windows)

Simply double-click or run:
```cmd
start.bat
```
*This script automatically configures the environment, starts all three services in separate windows, and opens `http://localhost:5173` in your default web browser.*

---

### Method 2: Docker Compose (Micro-segmented Mode)

To run the entire multi-container architecture in Docker with isolated bridge networks:
```bash
docker compose up -d --build
```

---

### Method 3: Manual Terminal Commands

If you prefer running each service manually in separate command prompt windows:

#### 1. Start the Node.js Auth Gateway (Port 4000)
```bash
cd node-express
npm install
node server.js
```

#### 2. Start the Python FastAPI Workload Service (Port 8001)
```bash
cd python-fastapi
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python zero_trust_auth.py
```

#### 3. Start the React Frontend Console (Port 5173)
```bash
cd react-frontend
npm install
npm run dev
```

Open your browser and navigate to: **`http://localhost:5173`**

---

## 🔑 Default Test Accounts

| Role | Email Identifier | Password | Access Entitlements |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@enterprise.internal` | `admin123` | Full administrative control, policy toggles, user lifecycle management. |
| **Editor** | `user@example.com` | `password123` | Operational access, encryption testing, threat simulation. |
| **New User** | *Register on UI* | *Your choice* | Default user account with custom role assignment. |

---

## 🧪 Threat Lab Attack Vector Test Suite

The automated Threat Lab simulates nine realistic attack vectors. All vectors were cleanly blocked during verification:

| Test ID | Attack Vector Name | Origin | Expected Defense Behavior | Result | Status |
| :---: | :--- | :---: | :--- | :---: | :---: |
| **ATT-01** | Unauthenticated Request | External | Reject request without valid Bearer token | HTTP 401 | **PASS** |
| **ATT-02** | Expired Access Token | External | Reject token past its 15-minute expiration | HTTP 401 | **PASS** |
| **ATT-03** | Tampered JWT Signature | External | Reject token with forged cryptographic signature | HTTP 401 | **PASS** |
| **ATT-04** | Direct Database Breach | External | Block direct TCP connection to port 5432 | Connection Timed Out | **PASS** |
| **ATT-05** | Admin Action Without MFA | Insider | Block privileged route when MFA is not completed | HTTP 401 | **PASS** |
| **ATT-06** | Brute-Force Password Attack | External | Temporarily lock account after 5 failed attempts | HTTP 429 | **PASS** |
| **ATT-07** | Replay Revoked Refresh Token | Insider | Detect re-used token in Redis blacklist | HTTP 401 | **PASS** |
| **ATT-08** | Stolen Token (Unknown Device) | Insider | Intercept token presented with mismatched fingerprint | HTTP 403 | **PASS** |
| **ATT-09** | Dormant Account Credential | Insider | Block login on accounts inactive for >30 days | HTTP 403 | **PASS** |

**Defense Score:** **9 / 9 Passed (100% Defense Success Rate)**

---

## 📄 Documentation

The complete 25-page academic project report is available in the [`report/`](report/) directory:
- **Word Document:** [`report/Minor_Project_2_Report.docx`](report/Minor_Project_2_Report.docx)
- **PDF Document:** [`report/Minor_Project_2_Report.pdf`](report/Minor_Project_2_Report.pdf)
- **Engineering Notes:** [`report/report_notes.md`](report/report_notes.md)
