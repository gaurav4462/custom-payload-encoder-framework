
import json
import streamlit as st

from encoder.transformations import (
    base64_encode,
    base64_decode,
    rot13_transform,
    xor_transform,
    xor_reverse,
)
from obfuscation.strings import (
    split_string,
    reconstruct_string,
    escape_representation,
    restore_escape_representation,
)
from detection.signatures import analyze_sample
from evaluation.metrics import calculate_metrics
from evaluation.runner import evaluate_dataset
from evaluation.charts import create_metrics_chart


st.set_page_config(
    page_title="Custom Payload Encoder & Obfuscation Framework",
    page_icon="🛡️",
    layout="wide",
)

st.title("Custom Payload Encoder & Obfuscation Framework")
st.caption(
    "A Python security research project using harmless sample text "
    "and simulated signature detection."
)

(
    tab_encode,
    tab_obfuscate,
    tab_detect,
    tab_metrics,
    tab_report,
) = st.tabs(
    [
        "Encoding",
        "String Transformations",
        "Detection Lab",
        "Metrics",
        "Evaluation Report",
    ]
)


# --------------------------------------------------
# 1. Encoding and decoding
# --------------------------------------------------

with tab_encode:
    st.subheader("Encoding and Decoding")

    text = st.text_area(
        "Enter harmless sample text",
        value="HELLO WORLD",
        key="encode_input",
    )

    method = st.selectbox(
        "Select transformation",
        ["Base64", "ROT13", "XOR (hex)"],
        key="encode_method",
    )

    key = ""
    if method == "XOR (hex)":
        key = st.text_input(
            "XOR key",
            value="demo-key",
            key="encode_key",
        )

    if st.button("Transform Text"):
        try:
            if method == "Base64":
                result = base64_encode(text)
            elif method == "ROT13":
                result = rot13_transform(text)
            else:
                result = xor_transform(text, key)

            st.session_state["transformed_result"] = result
            st.success("Transformation completed.")

        except (ValueError, UnicodeError) as exc:
            st.error(str(exc))

    if "transformed_result" in st.session_state:
        transformed = st.session_state["transformed_result"]

        st.text_area(
            "Transformed representation",
            value=transformed,
            key="transformed_output",
        )

        st.download_button(
            "Download transformed text",
            data=transformed,
            file_name="transformed_sample.txt",
            mime="text/plain",
            key="download_transformed",
        )

    st.divider()
    st.subheader("Decode or Reverse a Transformation")

    encoded = st.text_area(
        "Enter text to decode",
        key="decode_input",
    )

    decode_method = st.selectbox(
        "Representation format",
        ["Base64", "ROT13", "XOR (hex)", "Escaped string"],
        key="decode_method",
    )

    decode_key = ""
    if decode_method == "XOR (hex)":
        decode_key = st.text_input(
            "Original XOR key",
            key="decode_key",
        )

    if st.button("Decode / Reverse"):
        try:
            if decode_method == "Base64":
                result = base64_decode(encoded)
            elif decode_method == "ROT13":
                result = rot13_transform(encoded)
            elif decode_method == "XOR (hex)":
                result = xor_reverse(encoded, decode_key)
            else:
                result = restore_escape_representation(encoded)

            st.session_state["restored_result"] = result
            st.success("Text restored successfully.")

        except (ValueError, UnicodeError) as exc:
            st.error(f"Unable to restore text: {exc}")

    if "restored_result" in st.session_state:
        st.text_area(
            "Restored text",
            value=st.session_state["restored_result"],
            key="restored_output",
        )


# --------------------------------------------------
# 2. String transformations
# --------------------------------------------------

with tab_obfuscate:
    st.subheader("String Transformations")

    sample = st.text_area(
        "Enter harmless text",
        value="HELLOWORLD",
        key="obfuscation_input",
    )

    chunk_size = st.slider(
        "Chunk size",
        min_value=1,
        max_value=8,
        value=3,
    )

    parts = split_string(sample, chunk_size)
    reconstructed = reconstruct_string(parts)
    escaped = escape_representation(sample)

    col1, col2 = st.columns(2)

    with col1:
        st.write("String fragments")
        st.code(repr(parts))

        st.write("Reconstructed text")
        st.code(reconstructed)

    with col2:
        st.write("Escaped representation")
        st.code(escaped)

        st.write("Reconstruction result")
        if reconstructed == sample:
            st.success("The original text was restored.")
        else:
            st.error("The reconstructed text does not match.")

    if st.button("Restore escaped representation"):
        try:
            restored = restore_escape_representation(escaped)
            st.write("Restored escaped text")
            st.code(restored)

        except ValueError as exc:
            st.error(str(exc))


# --------------------------------------------------
# 3. Simulated detection
# --------------------------------------------------

with tab_detect:
    st.subheader("Simulated Signature Detection")

    st.info(
        "This experiment uses the harmless marker "
        "'TRAINING-DEMO-MARKER'. It is not a real malware scanner."
    )

    detection_input = st.text_area(
        "Sample to analyze",
        value="TRAINING-DEMO-MARKER",
        key="detection_input",
    )

    representation = st.selectbox(
        "Representation supplied",
        ["none", "base64", "rot13", "xor_hex"],
        key="detection_representation",
    )

    detection_key = ""
    if representation == "xor_hex":
        detection_key = st.text_input(
            "XOR key",
            key="detection_key",
        )

    if st.button("Analyze Sample"):
        result = analyze_sample(
            detection_input,
            encoding=representation,
            xor_key=detection_key,
        )

        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "Raw signature match",
                "Detected" if result["raw_detected"] else "Not detected",
            )

        with col2:
            st.metric(
                "After normalization",
                (
                    "Detected"
                    if result["normalized_detected"]
                    else "Not detected"
                ),
            )

        if result["normalization_error"]:
            st.warning(result["normalization_error"])

        st.write("Raw matches:", result["raw_matches"])
        st.write(
            "Normalized matches:",
            result["normalized_matches"],
        )


# --------------------------------------------------
# 4. Classification metrics calculator
# --------------------------------------------------

with tab_metrics:
    st.subheader("Classification Metrics")

    st.write(
        "Enter counts from a labeled evaluation dataset. "
        "These figures are separate from the automated report."
    )

    col1, col2 = st.columns(2)

    with col1:
        tp = st.number_input(
            "True positives",
            min_value=0,
            value=8,
            step=1,
        )
        fp = st.number_input(
            "False positives",
            min_value=0,
            value=1,
            step=1,
        )

    with col2:
        tn = st.number_input(
            "True negatives",
            min_value=0,
            value=9,
            step=1,
        )
        fn = st.number_input(
            "False negatives",
            min_value=0,
            value=2,
            step=1,
        )

    metrics = calculate_metrics(tp, fp, tn, fn)

    cols = st.columns(4)

    for col, (name, value) in zip(cols, metrics.items()):
        col.metric(
            name.replace("_", " ").title(),
            f"{value:.1%}",
        )


# --------------------------------------------------
# 5. Automated evaluation report
# --------------------------------------------------

with tab_report:
    st.subheader("Evaluation Report")

    st.write(
        "Run the labeled sample dataset and compare raw detection "
        "with detection after supported normalization."
    )

    if st.button("Run Full Evaluation", key="run_evaluation"):
        try:
            report = evaluate_dataset()
            st.session_state["evaluation_report"] = report
            st.success("Evaluation completed.")

        except (OSError, ValueError, KeyError, TypeError) as exc:
            st.error(f"Evaluation failed: {exc}")

    report = st.session_state.get("evaluation_report")

    if report:
        st.metric(
            "Samples evaluated",
            report["sample_count"],
        )

        st.subheader("Raw Detection Metrics")
        raw_metrics = report["raw_metrics"]

        cols = st.columns(4)
        for col, (name, value) in zip(cols, raw_metrics.items()):
            col.metric(
                name.replace("_", " ").title(),
                f"{value:.1%}",
            )

        st.subheader("Metrics After Normalization")
        normalized_metrics = report["normalized_metrics"]

        cols = st.columns(4)
        for col, (name, value) in zip(
            cols, normalized_metrics.items()
        ):
            col.metric(
                name.replace("_", " ").title(),
                f"{value:.1%}",
            )

        st.subheader("Comparison Chart")

        try:
            figure = create_metrics_chart(report)
            st.pyplot(figure)

            import matplotlib.pyplot as plt
            plt.close(figure)

        except (ValueError, KeyError, TypeError) as exc:
            st.warning(f"Unable to create chart: {exc}")

        st.subheader("Individual Sample Results")

        st.dataframe(
            report["results"],
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download JSON Report",
            data=json.dumps(report, indent=2),
            file_name="evaluation_results.json",
            mime="application/json",
            key="download_json_report",
        )

        csv_path = "reports/evaluation_results.csv"

        try:
            with open(csv_path, "r", encoding="utf-8", newline="") as file:
                csv_data = file.read()

            st.download_button(
                "Download CSV Report",
                data=csv_data,
                file_name="evaluation_results.csv",
                mime="text/csv",
                key="download_csv_report",
            )

        except OSError:
            st.warning(
                "The CSV report was not found. Run the evaluation again."
            )

    else:
        st.info(
            "Click Run Full Evaluation to generate metrics, "
            "a comparison chart, and downloadable reports."
        )


# --------------------------------------------------
# Footer
# --------------------------------------------------

st.divider()

st.caption(
    "Educational security research prototype. The results describe "
    "a simulated detector and do not establish real world antivirus "
    "or EDR performance."
)
