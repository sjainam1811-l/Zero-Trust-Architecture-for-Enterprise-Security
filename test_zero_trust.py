"""
Automated End-to-End Verification Test Suite
Zero-Trust Authentication Templates (Node.js & Python FastAPI)
"""
import sys
import os
import time
import subprocess
import urllib.request
import urllib.error
import json

def make_request(url, method="GET", headers=None, data=None):
    headers = headers or {}
    encoded_data = None
    if data is not None:
        encoded_data = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"raw": body}
        return e.code, parsed

def run_tests():
    print("=" * 65)
    print("  ZERO-TRUST AUTHENTICATION: AUTOMATED VERIFICATION SUITE")
    print("=" * 65)

    all_passed = True

    # ─────────────────────────────────────────────────────────────
    # PART 1: NODE.JS / EXPRESS
    # ─────────────────────────────────────────────────────────────
    print("\n[1/2] Starting and verifying Node.js / Express Server on port 4000...")
    node_proc = subprocess.Popen(
        ["node", "server.js"],
        cwd="node-express",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(2)

    try:
        # 1. Health check
        code, resp = make_request("http://localhost:4000/")
        assert code == 200, f"Expected 200, got {code}"
        print("  ✓ Node server root status: OK (200)")

        # 2. Login
        code, resp = make_request(
            "http://localhost:4000/auth/login",
            method="POST",
            data={"identifier": "user@example.com", "password": "password123"}
        )
        assert code == 200, f"Login failed: {code} {resp}"
        access_token = resp.get("accessToken")
        refresh_token = resp.get("refreshToken")
        assert access_token and refresh_token, "Missing tokens in login response"
        print("  ✓ Login succeeded: JWT access and refresh tokens issued")

        # 3. RBAC checks
        auth_header = {"Authorization": f"Bearer {access_token}"}
        code, resp = make_request("http://localhost:4000/api/data", method="GET", headers=auth_header)
        assert code == 200, f"GET /api/data failed: {code}"
        print("  ✓ RBAC 'read' permission verified (200 OK)")

        code, resp = make_request("http://localhost:4000/api/data", method="POST", headers=auth_header, data={"test": "data"})
        assert code == 200, f"POST /api/data failed: {code}"
        print("  ✓ RBAC 'write' permission verified (200 OK)")

        code, resp = make_request("http://localhost:4000/api/data", method="DELETE", headers=auth_header)
        assert code == 403, f"Expected 403 for DELETE /api/data, got {code}"
        print("  ✓ RBAC policy enforcement verified (DELETE rejected with 403 Forbidden)")

        # 4. Token Rotation (Refresh)
        code, resp = make_request("http://localhost:4000/auth/refresh", method="POST", data={"refreshToken": refresh_token})
        assert code == 200, f"Refresh failed: {code} {resp}"
        new_access_token = resp.get("accessToken")
        new_refresh_token = resp.get("refreshToken")
        assert new_access_token and new_refresh_token, "Missing new tokens"
        print("  ✓ Token refresh succeeded: new token pair issued")

        # 5. Token Reuse Prevention (Replay attack test)
        code, resp = make_request("http://localhost:4000/auth/refresh", method="POST", data={"refreshToken": refresh_token})
        assert code == 401, f"Expected 401 on reused refresh token, got {code}"
        print("  ✓ Replay attack protection verified (used refresh token immediately rejected)")

        # 6. Device Trust
        new_auth_header = {"Authorization": f"Bearer {new_access_token}"}
        code, resp = make_request("http://localhost:4000/auth/trust-device", method="POST", headers=new_auth_header)
        assert code == 200, f"Trust device failed: {code}"
        print("  ✓ Device fingerprint registration verified")

        # 7. Logout
        code, resp = make_request("http://localhost:4000/auth/logout", method="POST", headers=new_auth_header)
        assert code == 200, f"Logout failed: {code}"
        print("  ✓ Session logout and token revocation verified")

        # 8. Access with revoked token
        code, resp = make_request("http://localhost:4000/api/data", method="GET", headers=new_auth_header)
        assert code == 401, f"Expected 401 with revoked token, got {code}"
        print("  ✓ JTI Blacklist enforcement verified (revoked token blocked with 401 Unauthorized)")

        print("  >>> Node.js / Express Zero-Trust Auth: 100% PASS <<<")

    except Exception as e:
        print(f"  ✗ Node test failed: {e}")
        all_passed = False
    finally:
        node_proc.terminate()
        try:
            node_proc.wait(timeout=2)
        except Exception:
            node_proc.kill()

    # ─────────────────────────────────────────────────────────────
    # PART 2: PYTHON / FASTAPI
    # ─────────────────────────────────────────────────────────────
    print("\n[2/2] Starting and verifying Python / FastAPI Server on port 8001...")
    py_proc = subprocess.Popen(
        [sys.executable, "zero_trust_auth.py"],
        cwd="python-fastapi",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(3)

    try:
        # 1. Health check
        code, resp = make_request("http://127.0.0.1:8001/")
        assert code == 200, f"Expected 200, got {code}"
        print("  ✓ FastAPI server root status: OK (200)")

        # 2. Login
        code, resp = make_request(
            "http://127.0.0.1:8001/auth/login",
            method="POST",
            data={"identifier": "user@example.com", "password": "password123"}
        )
        assert code == 200, f"FastAPI login failed: {code} {resp}"
        access_token = resp.get("access_token")
        refresh_token = resp.get("refresh_token")
        assert access_token and refresh_token, "Missing tokens in FastAPI login response"
        print("  ✓ Login succeeded: JWT access and refresh tokens issued")

        # 3. RBAC checks
        auth_header = {"Authorization": f"Bearer {access_token}"}
        code, resp = make_request("http://127.0.0.1:8001/api/data", method="GET", headers=auth_header)
        assert code == 200, f"FastAPI GET /api/data failed: {code}"
        print("  ✓ RBAC 'read' permission verified (200 OK)")

        code, resp = make_request("http://127.0.0.1:8001/api/data", method="POST", headers=auth_header, data={"test": "data"})
        assert code == 200, f"FastAPI POST /api/data failed: {code}"
        print("  ✓ RBAC 'write' permission verified (200 OK)")

        code, resp = make_request("http://127.0.0.1:8001/api/data", method="DELETE", headers=auth_header)
        assert code == 403, f"Expected 403 for DELETE /api/data, got {code}"
        print("  ✓ RBAC policy enforcement verified (DELETE rejected with 403 Forbidden)")

        # 4. Token Rotation (Refresh)
        code, resp = make_request("http://127.0.0.1:8001/auth/refresh", method="POST", data={"refresh_token": refresh_token})
        assert code == 200, f"Refresh failed: {code} {resp}"
        new_access_token = resp.get("access_token")
        new_refresh_token = resp.get("refresh_token")
        assert new_access_token and new_refresh_token, "Missing new tokens"
        print("  ✓ Token refresh succeeded: new token pair issued")

        # 5. Token Reuse Prevention (Replay attack test)
        code, resp = make_request("http://127.0.0.1:8001/auth/refresh", method="POST", data={"refresh_token": refresh_token})
        assert code == 401, f"Expected 401 on reused refresh token, got {code}"
        print("  ✓ Replay attack protection verified (used refresh token immediately rejected)")

        # 6. Device Trust
        new_auth_header = {"Authorization": f"Bearer {new_access_token}"}
        code, resp = make_request("http://127.0.0.1:8001/auth/trust-device", method="POST", headers=new_auth_header)
        assert code == 200, f"Trust device failed: {code}"
        print("  ✓ Device fingerprint registration verified")

        # 7. Logout
        code, resp = make_request("http://127.0.0.1:8001/auth/logout", method="POST", headers=new_auth_header)
        assert code == 200, f"Logout failed: {code}"
        print("  ✓ Session logout and token revocation verified")

        # 8. Access with revoked token
        code, resp = make_request("http://127.0.0.1:8001/api/data", method="GET", headers=new_auth_header)
        assert code == 401, f"Expected 401 with revoked token, got {code}"
        print("  ✓ JTI Blacklist enforcement verified (revoked token blocked with 401 Unauthorized)")

        print("  >>> Python / FastAPI Zero-Trust Auth: 100% PASS <<<")

    except Exception as e:
        print(f"  ✗ FastAPI test failed: {e}")
        all_passed = False
    finally:
        py_proc.terminate()
        try:
            py_proc.wait(timeout=2)
        except Exception:
            py_proc.kill()

    print("\n" + "=" * 65)
    if all_passed:
        print("  ALL ZERO-TRUST AUTHENTICATION TESTS PASSED SUCCESSFULLY!")
    else:
        print("  SOME TESTS ENCOUNTERED ERRORS.")
    print("=" * 65)
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(run_tests())
