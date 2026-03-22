import streamlit as st
import plotly.graph_objects as go
from utils import predict_text

st.set_page_config(page_title="Phishing Detector", layout="wide")

st.markdown("<h1 style='text-align:center;color:#4CAF50;'>🔐 Phishing Detector </h1>", unsafe_allow_html=True)

email_text = st.text_area("📩 Paste Email Content", height=250)

if st.button("🚀 Analyze Email"):

    if email_text.strip() == "":
        st.warning("Please enter email content.")
    else:

        (
            category,
            risk_score,
            ml_score,
            rule_score,
            detected_words,
            url_count,
            urgency_count,
            length_factor,
            attack_type
        ) = predict_text(email_text)

        st.markdown("## 📊 Detection Result")

        if category == "Safe":
            st.success("🟢 SAFE Email")
        elif category == "Suspicious":
            st.warning(f"🟡 SUSPICIOUS – {attack_type}")
        else:
            st.error(f"🔴 PHISHING – {attack_type}")

        # Progress animation
        st.markdown("### ⚡ Risk Level")
        progress = st.progress(0)
        for i in range(int(risk_score)):
            progress.progress(i + 1)

        st.write(f"Risk Score: {risk_score}%")

        # Gauge
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_score,
            title={'text': "Risk Score"},
            gauge={
                'axis': {'range': [0, 100]},
                'steps': [
                    {'range': [0, 30], 'color': "green"},
                    {'range': [30, 65], 'color': "yellow"},
                    {'range': [65, 100], 'color': "red"},
                ],
            }
        ))

        st.plotly_chart(fig, use_container_width=True)

        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("ML Score", f"{ml_score}%")
        col2.metric("Rule Score", f"{rule_score}%")
        col3.metric("URLs", url_count)
        col4.metric("Words", length_factor)

        st.markdown("### 🔍 Indicators")
        if detected_words:
            st.write("🔴 " + ", ".join(detected_words))
        else:
            st.success("No suspicious indicators")