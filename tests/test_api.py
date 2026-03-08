import requests
import json
import sys

BASE_URL = "http://127.0.0.1:5000"

def test_scan(url, expected_status=None):
    print(f"\n--- Testing POST /scan with: {url} ---")
    response = requests.post(f"{BASE_URL}/scan", json={"url": url})
    
    if response.status_code != 200:
        print(f"FAILED: Status {response.status_code}")
        print(response.text)
        return
        
    data = response.json()
    print("Response payload:")
    print(json.dumps(data, indent=2))
    
    # Assertions
    assert "risk_score" in data, "Missing 'risk_score' in response"
    assert "status" in data, "Missing 'status' in response"
    assert "reasons" in data, "Missing 'reasons' in response"
    assert isinstance(data["reasons"], list), "'reasons' should be a list"
    
    if expected_status:
        assert data["status"] == expected_status, f"Expected {expected_status}, got {data['status']}"
        
    print("✅ Schema valid!")


def test_logs():
    print("\n--- Testing GET /logs ---")
    response = requests.get(f"{BASE_URL}/logs")
    
    if response.status_code != 200:
        print(f"FAILED: Status {response.status_code}")
        return
        
    data = response.json()
    
    # Assertions
    assert "total_scans" in data, "Missing 'total_scans' in response"
    assert "phishing_count" in data, "Missing 'phishing_count' in response"
    assert "safe_count" in data, "Missing 'safe_count' in response"
    assert "scans" in data, "Missing 'scans' in response"
    
    print(f"Total Scans: {data['total_scans']}")
    print(f"Phishing Count: {data['phishing_count']}")
    print(f"Safe Count: {data['safe_count']}")
    print(f"Total entries in scans array: {len(data['scans'])}")
    print("✅ Logs payload valid!")

if __name__ == "__main__":
    try:
        # Test 1: Safe URL
        test_scan("https://google.com")
        
        # Test 2: Phishing URL
        test_scan("http://free-login-verify-paypal.com/account")
        
        # Test 3: Logs Endpoint
        test_logs()
        
        print("\n🎉 ALL TESTS PASSED!")
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("\n❌ Connection Error: Ensure the Flask server is running on http://127.0.0.1:5000")
        sys.exit(1)
