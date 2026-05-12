import streamlit as st
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from script.feature_extractor import extract_features
import tempfile
import os

st.set_page_config(
    page_title="Malware Detection System",
    layout="wide"
)

@st.cache_resource
def load_models():
    rf   = joblib.load("models/random_forest.pkl")
    xgb  = joblib.load("models/xgb_model.pkl")
    cols = joblib.load("models/feature_columns.pkl")
    return rf, xgb, cols

rf_model, xgb_model, feature_columns = load_models()

def get_risk(prob):
    if prob >= 0.90: return "Critical Risk", "#ff4444"
    if prob >= 0.70: return "High Risk",     "#ff8800"
    if prob >= 0.40: return "Medium Risk",   "#ffcc00"
    return                  "Low Risk",      "#00cc44"

st.markdown("""
    <h1 style='text-align:center; color:#0D7377;'>
        ML Based Malware Detection System
    </h1>
    <p style='text-align:center; color:gray;'>
        CSE 3968 — Major Project | ITER, SOA University
    </p>
    <hr>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### Model Selection")
    model_choice = st.radio(
        "Select Model",
        ["Random Forest", "XGBoost", "Both"]
    )
    st.markdown("---")
    st.markdown("### Team")
    st.markdown("""
    - Aman Kumar
    - Harsh Kumar
    - Puja Kumari
    - Shivam Kumar Singh

    **Section:** 23412G2 | **Sem:** 6th
    """)

tab1, tab2 = st.tabs(["Scan Executable", "Model Performance"])

# ── TAB 1 — SCAN FILE ────────────────────────────────────────
with tab1:
    st.markdown("### Upload a Windows Executable (.exe)")
    uploaded = st.file_uploader(
        "Select a .exe file",
        type=["exe"],
        help="The file is analysed statically — it is never executed."
    )

    if uploaded:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name

        st.info(
            f"File received: **{uploaded.name}** "
            f"({os.path.getsize(tmp_path)/1024:.1f} KB)"
        )

        with st.spinner("Extracting PE features..."):
            try:
                features = extract_features(tmp_path)
                df_exe   = pd.DataFrame([features])

                for col in feature_columns:
                    if col not in df_exe.columns:
                        df_exe[col] = 0
                df_exe = df_exe[feature_columns]

                missing = [c for c in feature_columns if c not in features]
                st.success(
                    f"{len(feature_columns)} features extracted "
                    f"| Missing: {len(missing)}"
                )
            except Exception as e:
                st.error(f"Feature extraction failed: {e}")
                st.stop()

        st.markdown("---")
        st.markdown("### Prediction Results")

        if model_choice == "Random Forest":
            models_to_run = [("Random Forest", rf_model)]
        elif model_choice == "XGBoost":
            models_to_run = [("XGBoost", xgb_model)]
        else:
            models_to_run = [
                ("Random Forest", rf_model),
                ("XGBoost", xgb_model)
            ]

        cols_display = st.columns(len(models_to_run))

        for i, (name, model) in enumerate(models_to_run):
            pred  = model.predict(df_exe)[0]
            prob  = model.predict_proba(df_exe)[0][1]
            label = "Malware Detected" if pred == 1 else "Benign File"
            conf  = prob * 100 if pred == 1 else (1 - prob) * 100
            risk_label, risk_color = get_risk(prob)

            with cols_display[i]:
                st.markdown(f"#### {name}")
                bg     = "#ffeeee" if pred == 1 else "#eeffee"
                border = "#ff4444" if pred == 1 else "#00cc44"
                st.markdown(f"""
                <div style='background:{bg};
                            border-left:5px solid {border};
                            padding:16px; border-radius:8px;
                            margin-bottom:10px;'>
                    <h3 style='margin:0;'>{label}</h3>
                    <p style='margin:4px 0;'>
                        <b>Confidence:</b> {conf:.2f}%
                    </p>
                    <p style='margin:4px 0; color:{risk_color};'>
                        <b>{risk_label}</b>
                    </p>
                    <p style='margin:4px 0; font-size:0.85em; color:gray;'>
                        Malware probability: {prob*100:.2f}%
                    </p>
                </div>
                """, unsafe_allow_html=True)

                fig, ax = plt.subplots(figsize=(4, 0.5))
                ax.barh(0, conf, color=border, height=0.4)
                ax.barh(0, 100 - conf, left=conf, color="#e0e0e0", height=0.4)
                ax.set_xlim(0, 100)
                ax.axis("off")
                st.pyplot(fig, use_container_width=True)
                plt.close()

        os.unlink(tmp_path)

        st.markdown("---")
        st.caption(
            "Note: This system performs static analysis only. "
            "It reads the file's PE structure without executing it."
        )

# ── TAB 2 — MODEL PERFORMANCE ────────────────────────────────
with tab2:
    st.markdown("### PE Malware Dataset Results")
    st.caption("dataset_malwares.csv — 19,611 samples | 78 features")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Metrics Comparison")
        perf = pd.DataFrame({
            "Metric":        ["Accuracy", "Precision",
                              "Recall", "F1-Score", "ROC-AUC"],
            "Random Forest": ["99.08%", "98.91%",
                              "99.86%", "99.39%", "0.9980"],
            "XGBoost":       ["99.24%", "99.05%",
                              "99.93%", "99.49%", "0.9986"],
        })
        st.dataframe(perf, hide_index=True, use_container_width=True)

        st.markdown("#### Confusion Matrix — Random Forest")
        cm_data = pd.DataFrame({
            "":                  ["Actual Benign", "Actual Malware"],
            "Predicted Benign":  [971,  4],
            "Predicted Malware": [32,   2916],
        })
        st.dataframe(cm_data, hide_index=True, use_container_width=True)

    with col2:
        st.markdown("#### Visual Comparison")
        metrics  = ["Accuracy", "Precision", "Recall", "F1-Score"]
        rf_vals  = [99.08, 98.91, 99.86, 99.39]
        xgb_vals = [99.24, 99.05, 99.93, 99.49]

        x     = np.arange(len(metrics))
        width = 0.35
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.bar(x - width/2, rf_vals,  width, label="Random Forest", color="#1B2A4A")
        ax.bar(x + width/2, xgb_vals, width, label="XGBoost",       color="#0D7377")
        ax.set_ylim(98.5, 100.1)
        ax.set_xticks(x)
        ax.set_xticklabels(metrics)
        ax.set_ylabel("Score (%)")
        ax.legend()
        ax.set_title("Random Forest vs XGBoost")
        ax.grid(axis="y", alpha=0.3)
        st.pyplot(fig, use_container_width=True)
        plt.close()

    st.markdown("---")
    st.markdown("### EMBER 2018 v2 Dataset Results")
    st.caption("20,000 samples | 2,381 features | Internal + External validation")

    ember_data = pd.DataFrame({
        "Model":     ["Random Forest", "XGBoost",
                      "XGBoost — External (EMBER 2017)"],
        "Accuracy":  ["94%",    "96%",    "84%"],
        "Precision": ["95%",    "97%",    "99%"],
        "Recall":    ["92%",    "95%",    "70%"],
        "F1-Score":  ["94%",    "96%",    "0.82"],
        "ROC-AUC":   ["0.9839", "0.9923", "0.9832"],
    })
    st.dataframe(ember_data, hide_index=True, use_container_width=True)