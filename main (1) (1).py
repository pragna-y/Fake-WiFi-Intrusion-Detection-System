from data import networks

seen = {}

print("🔍 Fake WiFi Detection System\n")

# ---------- USER INPUT OPTION ----------
choice = input("Enter 1 for default scan or 2 to enter your own WiFi: ")

if choice == "2":
    ssid = input("Enter SSID: ")
    mac = input("Enter MAC Address: ")
    security = input("Enter Security (Open/WEP/WPA2/WPA3): ")
    networks = [{"ssid": ssid, "mac": mac, "security": security}]

# ---------- SUMMARY COUNTERS ----------
safe_count = 0
suspicious_count = 0
high_risk_count = 0

print("\n🔍 Scanning WiFi Networks...\n")

for net in networks:
    ssid = net["ssid"]
    mac = net["mac"]
    security = net["security"]

    print(f"Network: {ssid}")
    print(f"MAC: {mac}")
    print(f"Security: {security}")

    risk = 0
    reasons = []

    # Rule 1: Duplicate SSID
    if ssid in seen and seen[ssid] != mac:
        print("⚠️ Duplicate SSID detected")
        risk += 50
        reasons.append("Duplicate SSID")
    else:
        seen[ssid] = mac

    # Rule 2: Open network
    if security.lower() == "open":
        print("⚠️ Open network")
        risk += 30
        reasons.append("No encryption")

    # Rule 3: Weak security
    if security.lower() == "wep":
        print("⚠️ Weak security")
        risk += 20
        reasons.append("Weak encryption")

    # ---------- FINAL STATUS ----------
    if risk >= 50:
        status = "🚨 HIGH RISK (Fake WiFi)"
        high_risk_count += 1
    elif risk >= 30:
        status = "⚠️ MEDIUM RISK"
        suspicious_count += 1
    else:
        status = "✅ SAFE"
        safe_count += 1

    print(f"Risk Score: {risk}")
    print(f"Status: {status}")

    if reasons:
        print("Reasons:", ", ".join(reasons))

    print("-" * 40)

# ---------- FINAL SUMMARY ----------
print("\n📊 FINAL REPORT")
print(f"Safe Networks: {safe_count}")
print(f"Suspicious Networks: {suspicious_count}")
print(f"High Risk Networks: {high_risk_count}")