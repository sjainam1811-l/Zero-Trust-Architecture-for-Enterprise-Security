# Zero-Trust Enterprise Lab — Operation & Verification Guide

This guide contains the exact commands and testing procedures to run and demonstrate the Zero-Trust Enterprise Lab for academic reports, lab demonstrations, and security audits.

---

## 1. Quick Verification Commands Summary

| Step / Module | Execution Command | Verification Output |
| :--- | :--- | :--- |
| **Jest Automated Test Suite** | `npm test` *(inside `node-express`)* | 14 passed (100%), IAM, Policies, Tokens, AES-256-GCM |
| **Threat Lab Simulation CLI** | `node scripts/threat_lab_runner.js` | 9 vectors defended (100%), pass rate table |
| **TLS Certificate Generation** | `node scripts/generate_certs.js` | Generates 2048-bit RSA keys in `certs/` |
| **Audit Log CSV Export** | `GET /api/audit/export-csv` | CSV stream with timestamps, IPs, decisions |
| **Full Docker Lab Stack** | `docker compose up --build` | Boots 6 containers across 3 segmented networks |
| **Attacker Container Probe** | `docker exec -it zt-attacker ./attack.sh` | Demonstrates network drop on `database:5432` |

---

## 2. Running Locally (Native Node & Python)

### Step A: Initialize TLS Certificates
```bash
node scripts/generate_certs.js
```
*Expected Output:*
```
[TLS SETUP] Generating 2048-bit RSA Self-Signed Certificate for Zero-Trust Enterprise Lab...
[TLS SETUP] Success! Certificates created:
 - Private Key:  certs/server.key
 - Certificate:  certs/server.crt
[TLS SETUP] Lab TLS Encryption In-Transit ready.
```

### Step B: Run Automated Unit & Policy Tests (Jest)
```bash
cd node-express
npm test
```
*Expected Output:*
```
PASS tests/zero_trust.test.js
  Zero-Trust Architecture Enterprise Security Suite
    IAM & Authentication
      √ authenticates valid editor and returns JWT pair
      √ rejects invalid password with 401
      √ demands step-up MFA challenge for enrolled admin identity
      √ allows admin login when valid TOTP is presented
    Policy Engine & Least Privilege RBAC
      √ allows editor to access READ protected resource
      √ allows editor to access WRITE protected resource
      √ DENIES editor from executing DELETE (Least Privilege enforcement)
      √ enforces step-up MFA on administrative route
      √ allows administrative route when X-MFA-Token is valid
      √ DENIES access to dormant account inactive > 30 days
    Single-Use Refresh Token Rotation
      √ revokes previous refresh token upon exchange and blocks replay
    AES-256-GCM Data Protection
      √ encrypts and decrypts sensitive data with tamper resistance
    IAM Governance APIs
      √ returns role permissions matrix
      √ creates a new identity in persistent store

Test Suites: 1 passed, 1 total
Tests:       14 passed, 14 total
```

### Step C: Execute Automated Threat Lab Attack Simulation
```bash
node scripts/threat_lab_runner.js
```
*Expected Output:*
```
================================================================================
       ZERO-TRUST ENTERPRISE LAB — AUTOMATED THREAT SIMULATION RUNNER        
================================================================================
Target Lab Endpoint: http://127.0.0.1:4000
Framework:           NIST SP 800-207 Zero Trust Architecture Verification

  [TEST] VEC-01 - Brute-Force Login Rate-Limit Lockout                 PASS
  [TEST] VEC-02 - Stolen JWT Access Token Replay (Altered Fingerprint) PASS
  [TEST] VEC-03 - Refresh Token Replay (Single-Use Rotation Policy)    PASS
  [TEST] VEC-04 - Tampered JWT Signature & Escalated Claim Injection   PASS
  [TEST] VEC-05 - Expired JWT Lifetime Rejection                       PASS
  [TEST] VEC-06 - Insider Privilege Escalation (Editor calling Admin)  PASS
  [TEST] VEC-07 - Dormant Account Inactivity Policy Check (>30 Days)   PASS
  [TEST] VEC-08 - Privileged Route Access Without Step-Up MFA Header   PASS
  [TEST] VEC-09 - Database Network Microsegmentation Isolation         PASS

────────────────────────────────────────────────────────────────────────────────
THREAT LAB AUDIT REPORT SUMMARY
────────────────────────────────────────────────────────────────────────────────
  Total Vectors Evaluated: 9
  Passed (Defended):       9
  Failed (Vulnerable):     0
  Defense Pass Rate:       100%
```

---

## 3. Running with Docker Compose (Multi-Tier Micro-Segmentation)

### Step A: Build & Boot All Services
```bash
docker compose up -d --build
```
This launches:
1. `zt-frontend`: React Client on port 5173 (`frontend-net`)
2. `zt-auth-service`: Node.js Express API on port 4000 (`frontend-net`, `app-net`, `db-net`)
3. `zt-app-api`: Python FastAPI API on port 8001 (`frontend-net`, `app-net`, `db-net`)
4. `zt-database`: PostgreSQL 16 on port 5432 (`db-net` isolated)
5. `zt-redis`: Redis 7 on port 6379 (`db-net` isolated)
6. `zt-attacker`: Adversary container (`frontend-net` only)

### Step B: Verify Container Health
```bash
docker compose ps
```
All containers should display status `Up (healthy)`.

### Step C: Execute Adversary Simulation Inside Attacker Container
```bash
docker exec -it zt-attacker /attacker/attack.sh
```
*Expected Output:*
```
======================================================================
    ZERO-TRUST ATTACK SIMULATION — RUNNING INSIDE ATTACKER CONTAINER  
======================================================================
Current Hostname: zt-attacker
Network Context:  frontend-net
Targeting Internal Segments...

[ATTACK 1] Attempting direct TCP connection to database:5432 (db-net)...
>>> [BLOCKED BY ZERO-TRUST NETWORK SEGMENTATION] Database is strictly unreachable!

[ATTACK 2] Attempting direct TCP connection to redis:6379 (db-net)...
>>> [BLOCKED BY ZERO-TRUST NETWORK SEGMENTATION] Redis state is strictly unreachable!

[ATTACK 3] Probing public authentication edge service (auth-service:4000)...
HTTP Response Code: 200
>>> [EXPECTED] Auth service edge is reachable on frontend-net, enforcing zero-trust auth.
```

---

## 4. Default Seed Identities

| Role | Email Identifier | Password | MFA Enrolled |
| :--- | :--- | :--- | :---: |
| **Admin** | `admin@enterprise.internal` | `AdminSecret123!` | Yes (TOTP) |
| **Editor** | `user@example.com` | `password123` | No |
| **Viewer** | `viewer@example.com` | `password123` | No |
| **Auditor** | `auditor@enterprise.internal` | `password123` | Yes (TOTP) |
| **Dormant** | `dormant@enterprise.internal` | `password123` | No (>30d inactive) |
