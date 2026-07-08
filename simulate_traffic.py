import requests
import time
import random

API_URL = "http://localhost:8000"
USERNAME = "testuser"
PASSWORD = "password123"

def setup():
    # Register
    try:
        requests.post(f"{API_URL}/api/auth/register", json={"username": USERNAME, "password": PASSWORD})
    except:
        pass # Might already exist
        
    # Login
    resp = requests.post(f"{API_URL}/api/auth/login", data={"username": USERNAME, "password": PASSWORD})
    if resp.status_code == 200:
        return resp.json()["access_token"]
    print("Login failed")
    return None

def simulate_traffic(token):
    headers = {"Authorization": f"Bearer {token}"}
    actions = ["web_browsing", "file_transfer", "database_query"]
    
    print("Starting normal traffic simulation...")
    for _ in range(5):
        action = random.choice(actions)
        net = random.uniform(0.1, 5.0)
        
        payload = {
            "action_type": action,
            "device": "desktop-01",
            "network_activity": net,
            "details": f"Normal {action}"
        }
        
        resp = requests.post(f"{API_URL}/api/activity/log", json=payload, headers=headers)
        print(f"Logged NORMAL action: {action} ({net:.2f} MB) -> Score: {resp.json().get('assessment', {}).get('score')}")
        time.sleep(2)
        
    print("\n--- SIMULATING THREAT ---")
    payload = {
        "action_type": "network_connection_suspicious",
        "device": "desktop-01",
        "network_activity": 58.0,
        "details": "Unknown process reached a public remote IP over a non-standard outbound port"
    }
    resp = requests.post(f"{API_URL}/api/activity/log", json=payload, headers=headers)
    print(f"Logged ALERT action: network_connection_suspicious -> Score: {resp.json().get('assessment', {}).get('score')}")
    time.sleep(1)
    
    print("\n--- SIMULATING CRITICAL THREAT ---")
    payload = {
        "action_type": "file_transfer",
        "device": "desktop-01",
        "network_activity": 6000.0,
        "details": "Massive data exfiltration attempt"
    }
    resp = requests.post(f"{API_URL}/api/activity/log", json=payload, headers=headers)
    print(f"Logged CRITICAL action: data_exfiltration -> Score: {resp.json().get('assessment', {}).get('score')}")

if __name__ == "__main__":
    print("Waiting for server to start...")
    time.sleep(5) # Give it a few seconds if just started
    token = setup()
    if token:
        simulate_traffic(token)
