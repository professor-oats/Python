## Just a fancyschmancy script to keep session

import requests
import time

def ping_lab(url):
    try:
        response = requests.get(url)
        print(f"[{time.strftime('%H:%M:%S')}] Status Code: {response.status_code}")
        print("Request successful!" if response.ok else "Request failed.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def auto_ping(url, interval=60):
    print(f"Starting auto-ping every {interval} seconds. Press Ctrl+C to stop.")
    try:
        while True:
            ping_lab(url)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nAuto-ping stopped by user.")

def main():
    lab_url = input("Enter the PortSwigger lab URL: ").strip()
    if not lab_url.startswith("http"):
        print("Please enter a valid URL starting with http or https.")
        return

    choice = input("Do you want to auto-ping the lab? (y/n): ").strip().lower()
    if choice == 'y':
        interval_input = input("Enter ping interval in seconds (default is 60): ").strip()
        interval = int(interval_input) if interval_input.isdigit() else 60
        auto_ping(lab_url, interval)
    else:
        ping_lab(lab_url)

if __name__ == "__main__":
    main()
