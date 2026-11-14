
from zapv2 import ZAPv2

ZAP_URL = "http://localhost:8080"
ZAP_API_KEY = "securescan-local-key-123"

zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={
        "http": ZAP_URL,
        "https": ZAP_URL
    }
)

POLICY = "Default Policy"

print(f"\nZAP Version: {zap.core.version}")
print(f"Checking policy: {POLICY}\n")

# Fetch all scanner rules belonging to Default Policy
scanners = zap.ascan.scanners(
    scanpolicyname=POLICY
)

enabled = []
disabled = []

for scanner in scanners:
    if str(scanner.get("enabled", "")).lower() == "true":
        enabled.append(scanner)
    else:
        disabled.append(scanner)

print("=" * 75)
print("ENABLED ACTIVE SCAN RULES")
print("=" * 75)

for scanner in enabled:
    print(
        f"ID: {scanner.get('id')} | "
        f"Name: {scanner.get('name')} | "
        f"Threshold: {scanner.get('alertThreshold')} | "
        f"Strength: {scanner.get('attackStrength')}"
    )

print("\n" + "=" * 75)
print("DISABLED ACTIVE SCAN RULES")
print("=" * 75)

for scanner in disabled:
    print(
        f"ID: {scanner.get('id')} | "
        f"Name: {scanner.get('name')}"
    )

print("\n" + "=" * 75)
print("SUMMARY")
print("=" * 75)

print(f"Total rules: {len(scanners)}")
print(f"Enabled rules: {len(enabled)}")
print(f"Disabled rules: {len(disabled)}")
