"""
Safe brute-force *simulator* for local dev testing only.

Only run against a server you own (e.g. http://127.0.0.1:5000/login).
This script sends sequential attempts with a small delay so it cannot be abused as
a fast/anonymous brute-forcer.
"""
import requests
import time
import random

# === CONFIGURE THESE ===
URL = "http://127.0.0.1:5000/login"   # change to your local dev login URL
USERNAME = "admin"                    # username to test against
PASSWORDS = [
    "123456", "password", "admin123", "letmein", "qwerty", "password1",
    "111111", "123123", "welcome", "changeme"
]
DELAY_SECONDS = 1.0   # pause between attempts (increase for slower tests)
MAX_TRIES = len(PASSWORDS)  # how many passwords to try (keeps it bounded)
# ========================

def make_headers(i):
    # simple rotating User-Agent to mimic varied clients (ok for local testing)
    agents = [
        "simulate-agent/1.0", "simulate-agent/2.0", "curl/7.80", "python-requests/2.x"
    ]
    return {"User-Agent": random.choice(agents)}

def try_password(username, password):
    try:
        r = requests.post(URL, data={"username": username, "password": password}, headers=make_headers(0), timeout=10)
        return r.status_code, r.text
    except requests.RequestException as e:
        return None, f"ERROR: {e}"

def main():
    print(f"Starting safe simulation against {URL}")
    for i, pwd in enumerate(PASSWORDS[:MAX_TRIES], start=1):
        print(f"[{i}/{MAX_TRIES}] Trying password: '{pwd}'")
        status, text = try_password(USERNAME, pwd)
        print(" -> status:", status, "| response preview:", (text or "")[:200])
        # wait before next attempt so this is not a high-speed attack
        time.sleep(DELAY_SECONDS)
    print("Simulation finished. Now check your admin dashboard page to confirm logs were recorded.")

if __name__ == "__main__":
    main()
