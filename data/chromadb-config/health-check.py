#!/usr/bin/env python3
"""
ChromaDB Health Check
Simple health check for ChromaDB service
"""
import requests
import sys
import time


def check_health():
    try:
        response = requests.get("http://localhost:8000/api/v1/heartbeat", timeout=5)
        if response.status_code == 200:
            print("✅ ChromaDB is healthy")
            return True
        else:
            print(f"❌ ChromaDB returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ ChromaDB health check failed: {e}")
        return False


if __name__ == "__main__":
    # Wait a bit for service to start
    time.sleep(2)

    if check_health():
        sys.exit(0)
    else:
        sys.exit(1)
