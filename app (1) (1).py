import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

from data import networks  # ✅ import from data.py

st.set_page_config(page_title="Fake WiFi IDS", layout="wide")

# ---------- TITLE ----------
st.title("🛡️ Fake WiFi Intrusion Detection Dashboard")

# ---------- SIDEBAR ----------
st.sidebar.header("⚙️ Detection Controls")
risk_threshold = st.sidebar.slider("Risk Threshold", 0, 100, 50)
show_graph = st.sidebar.checkbox("Show Risk Graph", True)

# ---------- ANALYSIS ----------
seen = {}
safe = suspicious = fake = 0

data = []

for net in networks:
    ssid = net["ssid"]
    mac = net["mac"]
    security = net["security"]

    risk = 0
    reasons = []

    # Rule 1: Duplicate SSID
    if ssid in seen and seen[ssid] != mac:
        risk += 50
        reasons.append("Duplicate SSID")
    else:
        seen[ssid] = mac

    # Rule 2: Open network
    if security.lower() == "open":
        risk += 30
        reasons.append("No encryption")

    # Rule 3: Weak encryption
    if security.lower() == "wep":
        risk += 20
        reasons.append("Weak encryption")

    # Final decision
    if risk >= risk_threshold:
        status = "🚨 Fake"
        fake += 1
    elif risk >= 30:
        status = "⚠️ Suspicious"
        suspicious += 1
    else:
        status = "✅ Safe"
        safe += 1

    data.append({
        "SSID": ssid,
        "MAC": mac,
        "Security": security,
        "Risk": risk,
        "Status": status,
        "Reasons": ", ".join(reasons)
    })

# ---------- METRICS ----------
col1, col2, col3, col4 = st.columns(4)

col1.metric("📡 Total Networks", len(networks))
col2.metric("🚨 Fake WiFi", fake)
col3.metric("⚠️ Suspicious", suspicious)
col4.metric("✅ Safe", safe)

st.markdown("---")

# ---------- GRAPH ----------
df = pd.DataFrame(data)

if show_graph:
    st.subheader("📊 Risk Score Visualization")
    fig, ax = plt.subplots(figsize=(8,4))

# Shorten SSID names
    short_names = [i[:6] + "..." if len(i) > 6 else i for i in df["SSID"]]

    ax.bar(short_names, df["Risk"])

    ax.set_ylabel("Risk Score")
    ax.set_xlabel("WiFi Networks")

    st.pyplot(fig)

# ---------- TABLE ----------
st.subheader("📋 Network Data")
st.dataframe(df)

# ---------- DETAILS ----------
st.subheader("🔍 Detailed Analysis")

for row in data:
    st.markdown(f"""
    ### 📶 {row['SSID']}
    - **MAC:** {row['MAC']}
    - **Security:** {row['Security']}
    - **Risk Score:** {row['Risk']}
    - **Status:** {row['Status']}
    """)

    if row["Reasons"]:
        st.warning("⚠️ " + row["Reasons"])

    st.markdown("---")