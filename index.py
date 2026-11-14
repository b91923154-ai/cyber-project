import time
import requests
from zapv2 import ZAPv2

ZAP_URL = 'http://localhost:8080'
ZAP_API_KEY = 'securescan-local-key-123'
TARGET_URL = 'http://testasp.vulnweb.com' 

def run_zap_automation():
    print(f"Connecting to ZAP API at {ZAP_URL}...")
    zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_URL, 'https': ZAP_URL})
    print(f"Success! ZAP Version: {zap.core.version}")
    
    # --- NEW: CONFIGURE SPIDER LIMITS ---
    # Set the maximum depth the spider can crawl to 2 (0 is the start page, 1 is links from start, 2 is links from those)
    zap.spider.set_option_max_depth(2)
    print("Configured Spider maximum depth to 2 levels.")
    
    # 1. SPIDER (Discovery)
    print(f"\n[1/2] Starting Spider crawl for target: {TARGET_URL}")
    scan_id = zap.spider.scan(TARGET_URL)
    
    while int(zap.spider.status(scan_id)) < 100:
        print(f"Spider progress: {zap.spider.status(scan_id)}%")
        time.sleep(2)
        
    print("Spider completed! Passive scanning logs generated.")
    
    # --- NEW: CONFIGURE ACTIVE SCANNER LIMITS ---
    # Set the attack strength and alert threshold for the default policy (ID 0)
    # Threshold: Low (reports more, requires fewer payloads to confirm)
    # Strength: Medium/Default (sends a reasonable amount of payloads)
    zap.ascan.set_option_attack_policy("Default Policy")
    zap.ascan.set_option_target_params_injectable(31) # Standard injection targets
    
    # 2. ACTIVE SCAN
    print(f"\n[2/2] Starting Active Scan for target: {TARGET_URL}")
    print("WARNING: Sending active attack payloads...")
    ascan_id = zap.ascan.scan(TARGET_URL)
    
    # Production-ready resilient polling loop
    retries = 0
    max_retries = 10
    
    while True:
        try:
            progress = int(zap.ascan.status(ascan_id))
            print(f"Active Scan progress: {progress}%")
            if progress >= 100:
                break
            retries = 0  # Reset retries if connection is successful
            
        except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError):
            retries += 1
            print(f"Warning: ZAP API connection dropped under heavy load. Retrying ({retries}/{max_retries})...")
            if retries >= max_retries:
                print("Error: ZAP container crashed or became permanently unresponsive. Ending scan.")
                return
                
        except Exception as e:
            print(f"Unexpected error: {e}")
            return
            
        time.sleep(5)
        
    print("Active Scan completed!")
    
    # 3. RETRIEVE RESULTS
    print("\nFetching alerts from database...")
    alerts = zap.core.alerts(baseurl=TARGET_URL)
    
    print(f"\n--- FOUND {len(alerts)} ALERTS ---")
    for alert in alerts[:10]:
        print(f"[{alert.get('risk')}] {alert.get('name')}")
        print(f"URL: {alert.get('url')}\n")

if __name__ == "__main__":
    run_zap_automation()