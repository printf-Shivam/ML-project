import streamlit as st
import pandas as pd
import joblib
import tempfile

from script.feature_extractor import extract_features

# Load model
model = joblib.load("models/random_forest.pkl")

# Load feature columns
feature_columns = joblib.load("models/feature_columns.pkl")

# Title
st.title("Malware Detection System")

st.write("Upload an EXE file to detect malware.")

# Upload file
uploaded_file = st.file_uploader(
    "Upload EXE File",
    type=["exe"]
)

if uploaded_file is not None:

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:

        tmp_file.write(uploaded_file.read())

        temp_path = tmp_file.name

    try:

        # Extract features
        features = extract_features(temp_path)

        # Convert to dataframe
        df = pd.DataFrame([features])

        # Handle missing columns
        for col in feature_columns:

            if col not in df.columns:
                df[col] = 0

        # Match order
        df = df[feature_columns]

        # Predict
        prediction = model.predict(df)[0]

        probability = model.predict_proba(df)[0][1]

        st.subheader("Prediction Result")

        if prediction == 1:

            st.error("Malware Detected")

            st.write(
                f"Confidence: {probability*100:.2f}%"
            )

        else:

            st.success("Benign File")

            st.write(
                f"Confidence: {(1-probability)*100:.2f}%"
            )

    except Exception as e:

        st.error(f"Error: {e}")