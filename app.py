import streamlit as st
import sqlite3
from datetime import datetime
from sklearn.metrics.pairwise import cosine_similarity
import joblib
import pandas as pd
import plotly.graph_objects as go

from ml_model import predict_threat

from forensic_utils import (
    parse_eml,
    extract_urls,
    extract_ips,
    get_geolocation,
    check_spf,
    check_dmarc,
    check_dkim,
    extract_domain
)


# =========================================
# PAGE
# =========================================

st.set_page_config(
    page_title="AI Email Forensic Intelligence",
    page_icon="🛡️",
    layout="wide"
)

st.title(
    "🛡️ AI-Powered Email Threat Detection & "
    "Forensic Intelligence"
)

st.caption(
    "AI-based email investigation and "
    "security analysis platform"
)


# =========================================
# DATABASE
# =========================================

conn = sqlite3.connect("threat_memory.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    score REAL,
    level TEXT,
    date TEXT
)
""")

conn.commit()


# =========================================
# EMAIL INPUT
# =========================================

st.subheader("📧 Email Input")

uploaded_file = st.file_uploader(
    "Upload .eml file",
    type=["eml"]
)

email_text = st.text_area(
    "Or paste email content",
    height=200
)


# =========================================
# ANALYSIS
# =========================================

if st.button("🔍 Analyze Email"):

    email_info = {
        "subject": "",
        "from": "",
        "to": "",
        "reply_to": "",
        "body": "",
        "received": []
    }


    # =====================================
    # EML PARSING
    # =====================================

    if uploaded_file:

        file_bytes = uploaded_file.read()

        email_info = parse_eml(file_bytes)

        analysis_text = (
            email_info["subject"]
            + " "
            + email_info["body"]
        )

    else:

        analysis_text = email_text


    if not analysis_text.strip():

        st.error(
            "Please upload an .eml file "
            "or enter email content."
        )

        st.stop()


    # =====================================
    # EMAIL DETAILS
    # =====================================

    st.subheader("📋 Email Details")

    details = pd.DataFrame({
        "Field": [
            "Subject",
            "From",
            "To",
            "Reply-To"
        ],
        "Value": [
            email_info["subject"],
            email_info["from"],
            email_info["to"],
            email_info["reply_to"]
        ]
    })

    st.dataframe(
        details,
        use_container_width=True
    )


    # =====================================
    # ML
    # =====================================

    probability, ml_level = predict_threat(
        analysis_text
    )

    ml_score = probability * 100


    # =====================================
    # KEYWORDS
    # =====================================

    suspicious_keywords = [
        "urgent",
        "verify",
        "password",
        "account",
        "click",
        "payment",
        "credential",
        "suspended",
        "login",
        "prize",
        "confirm"
    ]

    found_keywords = []

    text_lower = analysis_text.lower()

    for word in suspicious_keywords:

        if word in text_lower:
            found_keywords.append(word)


    keyword_score = min(
        len(found_keywords) * 4,
        20
    )


    # =====================================
    # URL & IP
    # =====================================

    urls = extract_urls(analysis_text)

    ips = extract_ips(analysis_text)


    # =====================================
    # FINAL SCORE
    # =====================================

    final_score = min(
        ml_score + keyword_score,
        100
    )


    # =====================================
    # RISK LEVEL
    # =====================================

    if final_score >= 75:

        risk = "HIGH"

    elif final_score >= 45:

        risk = "MEDIUM"

    else:

        risk = "LOW"


    # =====================================
    # THREAT DASHBOARD
    # =====================================

    st.subheader("📊 Threat Assessment")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "ML Probability",
        f"{ml_score:.2f}%"
    )

    col2.metric(
        "Threat Score",
        f"{final_score:.2f}%"
    )

    col3.metric(
        "Risk Level",
        risk
    )


    # =====================================
    # INDICATORS
    # =====================================

    st.subheader("🚨 Threat Indicators")

    st.write(
        "Suspicious Keywords:",
        ", ".join(found_keywords)
        if found_keywords
        else "None"
    )

    st.write(
        "Detected URLs:",
        len(urls)
    )

    st.write(
        "Detected IPs:",
        len(ips)
    )


    # =====================================
    # GEOLOCATION
    # =====================================

    st.subheader("🌍 IP GeoLocation")

    geo_results = []

    for ip in ips:

        geo_results.append(
            get_geolocation(ip)
        )

    if geo_results:

        st.dataframe(
            pd.DataFrame(geo_results),
            use_container_width=True
        )

    else:

        st.info(
            "No public IP address detected."
        )


    # =====================================
    # EMAIL AUTHENTICATION
    # =====================================

    st.subheader(
        "🔐 Email Authentication Analysis"
    )

    domain = extract_domain(
        email_info["from"]
    )

    if domain:

        spf = check_spf(domain)

        dmarc = check_dmarc(domain)

        dkim = check_dkim(domain)

        auth_table = pd.DataFrame({
            "Check": [
                "SPF",
                "DKIM",
                "DMARC"
            ],
            "Result": [
                spf,
                dkim,
                dmarc
            ]
        })

        st.dataframe(
            auth_table,
            use_container_width=True
        )

    else:

        st.info(
            "Sender domain could not be extracted."
        )


    # =====================================
    # HEADER FORENSICS
    # =====================================

    st.subheader(
        "🔎 Email Header Forensics"
    )

    received = email_info["received"]

    if received:

        for index, header in enumerate(
            received,
            start=1
        ):

            st.code(
                f"Received Hop {index}:\n{header}"
            )

    else:

        st.info(
            "No Received headers available."
        )


    # =====================================
    # ATTACK RECONSTRUCTION
    # =====================================

    st.subheader(
        "🧩 Attack Reconstruction"
    )

    attack_flow = [
        "Email"
    ]

    if found_keywords:

        attack_flow.append(
            "Suspicious Indicators"
        )

    if urls:

        attack_flow.append(
            "Suspicious URL"
        )

    if ips:

        attack_flow.append(
            "IP Address"
        )

    if geo_results:

        attack_flow.append(
            "GeoLocation"
        )

    attack_flow.append(
        "Risk Assessment"
    )

    st.info(
        " → ".join(attack_flow)
    )


    # =====================================
    # PATTERN MEMORY
    # =====================================

    st.subheader(
        "🧠 Campaign / Pattern Memory"
    )

    cursor.execute(
        "SELECT email FROM threats"
    )

    previous = cursor.fetchall()

    similar_found = False

    if previous:

        old_emails = [
            item[0]
            for item in previous
            if item[0] != analysis_text
        ]

        if old_emails:

            vectorizer = joblib.load(
                "vectorizer.pkl"
            )

            current_vector = vectorizer.transform(
                [analysis_text]
            )

            old_vectors = vectorizer.transform(
                old_emails
            )

            similarities = cosine_similarity(
                current_vector,
                old_vectors
            )

            highest = similarities.max()

            if highest >= 0.50:

                similar_found = True

                st.warning(
                    f"Similar previous pattern detected: "
                    f"{highest * 100:.2f}% similarity"
                )

            else:

                st.success(
                    "No strong previous pattern detected."
                )


    if not previous:

        st.info(
            "This is the first stored threat pattern."
        )


    # =====================================
    # SAVE CURRENT THREAT
    # =====================================

    cursor.execute(
        """
        INSERT INTO threats
        (email, score, level, date)
        VALUES (?, ?, ?, ?)
        """,
        (
            analysis_text,
            final_score,
            risk,
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )
    )

    conn.commit()


    # =====================================
    # EXPLAINABLE RISK
    # =====================================

    st.subheader(
        "💡 Explainable Risk"
    )

    reasons = []

    if ml_score >= 50:

        reasons.append(
            "ML model detected suspicious email characteristics."
        )

    if found_keywords:

        reasons.append(
            "Suspicious keywords were detected."
        )

    if urls:

        reasons.append(
            "URL indicators were found."
        )

    if ips:

        reasons.append(
            "IP indicators were found."
        )

    if similar_found:

        reasons.append(
            "Similar previous threat pattern detected."
        )

    if not reasons:

        reasons.append(
            "No major suspicious indicators detected."
        )

    for reason in reasons:

        st.write(
            "•",
            reason
        )


    # =====================================
    # RISK VISUALIZATION
    # =====================================

    # Color based on risk level

    if risk == "HIGH":

        risk_color = "red"

    elif risk == "MEDIUM":

        risk_color = "orange"

    else:

        risk_color = "green"


    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=final_score,

            title={
                "text": f"Threat Risk Score<br><b>{risk}</b>"
            },

            gauge={
                "axis": {
                    "range": [0, 100],
                    "ticksuffix": "%"
                },

                "bar": {
                    "color": risk_color
                },

                "steps": [
                    {
                        "range": [0, 45],
                        "color": "lightgreen"
                    },
                    {
                        "range": [45, 75],
                        "color": "lightyellow"
                    },
                    {
                        "range": [75, 100],
                        "color": "lightcoral"
                    }
                ]
            }
        )
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


    # =====================================
    # SAFE ATTACK REPLAY
    # =====================================

    st.subheader(
        "🧪 Safe Attack Replay"
    )

    st.warning(
        "Simulation only. No real attack is executed."
    )

    if st.button(
        "▶️ Start Safe Simulation"
    ):

        steps = [
            "Email received",
            "Threat indicator identified",
            "URL/IP analyzed",
            "GeoLocation checked",
            "Risk score calculated",
            "Investigation completed"
        ]

        for step in steps:

            st.write(
                "✅",
                step
            )

        st.success(
            "Safe attack-flow simulation completed."
        )


    # =====================================
    # FORENSIC REPORT
    # =====================================

    st.subheader(
        "📄 Forensic Investigation Report"
    )

    report = f"""
AI EMAIL FORENSIC INVESTIGATION REPORT
======================================

Generated:
{datetime.now()}

EMAIL
-----
Subject: {email_info["subject"]}
From: {email_info["from"]}
To: {email_info["to"]}
Reply-To: {email_info["reply_to"]}

THREAT ASSESSMENT
-----------------
ML Probability: {ml_score:.2f}%
Threat Score: {final_score:.2f}%
Risk Level: {risk}

SUSPICIOUS KEYWORDS
-------------------
{", ".join(found_keywords)}

URLS
----
{chr(10).join(urls)}

IP ADDRESSES
------------
{chr(10).join(ips)}

ATTACK RECONSTRUCTION
---------------------
{" -> ".join(attack_flow)}

EXPLAINABLE RISK
----------------
{chr(10).join(reasons)}

AUTHENTICATION
--------------
Domain: {domain}
SPF: {spf if domain else "Not Checked"}
DKIM: {dkim if domain else "Not Checked"}
DMARC: {dmarc if domain else "Not Checked"}

HEADER FORENSICS
----------------
{chr(10).join(received)}

NOTE
----
IP GeoLocation provides information associated
with an IP address. It should not automatically
be interpreted as the physical location of the
attacker.
"""

    st.download_button(
        "⬇️ Download Forensic Report",
        data=report,
        file_name="email_forensic_report.txt",
        mime="text/plain"
    )