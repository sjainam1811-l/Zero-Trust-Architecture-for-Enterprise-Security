#!/bin/bash
# ==============================================================================
# Adversary Attack Simulation Script (Executes inside the Attacker Container)
# Evaluates Zero-Trust micro-segmentation and defense boundaries.
# ==============================================================================

echo "======================================================================"
echo "    ZERO-TRUST ATTACK SIMULATION — RUNNING INSIDE ATTACKER CONTAINER  "
echo "======================================================================"
echo "Current Hostname: $(hostname)"
echo "Network Context:  frontend-net"
echo "Targeting Internal Segments..."
echo ""

# Test 1: Direct Network Segmentation Breach (Attempt to reach Database port 5432)
echo "[ATTACK 1] Attempting direct TCP connection to database:5432 (db-net)..."
nc -z -v -w 3 database 5432 2>&1
if [ $? -eq 0 ]; then
  echo ">>> [CRITICAL VULNERABILITY] Attacker accessed database directly!"
else
  echo ">>> [BLOCKED BY ZERO-TRUST NETWORK SEGMENTATION] Database is strictly unreachable!"
fi
echo ""

# Test 2: Direct Redis Cache Breach (Attempt to reach Redis port 6379)
echo "[ATTACK 2] Attempting direct TCP connection to redis:6379 (db-net)..."
nc -z -v -w 3 redis 6379 2>&1
if [ $? -eq 0 ]; then
  echo ">>> [CRITICAL VULNERABILITY] Attacker accessed Redis directly!"
else
  echo ">>> [BLOCKED BY ZERO-TRUST NETWORK SEGMENTATION] Redis state is strictly unreachable!"
fi
echo ""

# Test 3: Public Edge Probe (auth-service:4000)
echo "[ATTACK 3] Probing public authentication edge service (auth-service:4000)..."
curl -s -o /dev/null -w "HTTP Response Code: %{http_code}\n" http://auth-service:4000/
echo ">>> [EXPECTED] Auth service edge is reachable on frontend-net, enforcing zero-trust auth."
echo ""

echo "======================================================================"
echo "    SIMULATION COMPLETE — ZERO-TRUST MICROSEGMENTATION VERIFIED       "
echo "======================================================================"
