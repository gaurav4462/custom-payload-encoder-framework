
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
)
from detection.signatures import analyze_sample
from evaluation.metrics import calculate_metrics


st.set_page_config(
    page_title="Custom Payload Analysis Framework",
    page_icon="🛡️",
    layout="wide",
)

st.title("Custom Payload Encoder & Obfuscation Framework")
st.caption(
    "Educational analysis using harmless text and simulated signatures."
)

tab_encode, tab_obfuscate, tab_detect, tab_metrics = st.tabs(
    ["Encoding", "String Transformations", "Detection Lab", "Metrics"]
)

with tab_encode:
    st.subheader("Encoding and decoding")

    text = st.text_area(
        "Enter harmless sample text",
        value="HELLO WORLD",
        key="encode_input",
    )

    method = st.selectbox(
        "Transformation",
        ["Base64", "ROT13", "XOR (hex)"],
    )

    key = ""
    if method == "XOR (hex)":
        key = st.text_input("XOR key", value="demo-key")

    if st.button("Transform text"):
        try:
            if method == "Base64":
                result = base64_encode(text)
            elif method == "ROT13":
                result = rot13_transform(text)
            else:
                result = xor_transform(text, key)

            st.text_area("Transformed representation", result)

            st.download_button(
                "Download result",
                data=result,
                file_name="transformed_sample.txt",
                mime="text/plain",
            )
        except (ValueError, UnicodeError) as exc:
            st.error(str(exc))

    st.divider()
    st.subheader("Decode a representation")

    encoded = st.text_area(
        "Paste Base64, ROT13 text, or XOR hexadecimal",
        key="decode_input",
    )

    decode_method = st.selectbox(
        "Format to reverse",
        ["Base64", "ROT13", "XOR (hex)"],
        key="decode_method",
    )

    decode_key = ""
    if decode_method == "XOR (hex)":
        decode_key = st.text_input(
            "Matching XOR key",
            key="decode_key",
        )

    if st.button("Decode / reverse"):
        try:
            if decode_method == "Base64":
                result = base64_decode(encoded)
            elif decode_method == "ROT13":
                result = rot13_transform(encoded)
            else:
                result = xor_reverse(encoded, decode_key)

            st.text_area("Restored text", result, key="restored_text")
        except (ValueError, UnicodeError) as exc:
            st.error(f"Could not reverse the transformation: {exc}")


with tab_obfuscate:
    st.subheader("String transformations")

    sample = st.text_input(
        "Harmless text",
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

    st.write("String fragments:")
    st.code(repr(parts))

    reconstructed = reconstruct_string(parts)

    st.write("Reconstructed string:")
    st.code(reconstructed)

    st.write("Escape representation:")
    st.code(escape_representation(sample))

    st.write(
        "Reconstruction successful:",
        reconstructed == sample,
    )


with tab_detect:
    st.subheader("Simulated signature detection")

    st.info(
        "The detector uses only the harmless marker "
        "'TRAINING-DEMO-MARKER'. It does not scan for real malware."
    )

    detection_input = st.text_area(
        "Sample to analyze",
        value="TRAINING-DEMO-MARKER",
        key="detection_input",
    )

    representation = st.selectbox(
        "Representation supplied",
        ["none", "base64", "rot13", "xor_hex"],
    )

    detection_key = ""
    if representation == "xor_hex":
        detection_key = st.text_input(
            "XOR key used for this sample",
            key="detection_key",
        )

    if st.button("Analyze sample"):
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
        st.write("Normalized matches:", result["normalized_matches"])

        if result["normalized_detected"]:
            st.success("The training marker was recognized.")
        else:
            st.info(
                "The configured training marker was not recognized "
                "in the supported analysis path."
            )


with tab_metrics:
    st.subheader("Classification metric calculator")

    st.write(
        "Enter counts from a labeled evaluation dataset. "
        "These values are not automatically measured by the detector."
    )

    col1, col2 = st.columns(2)

    with col1:
        tp = st.number_input(
            "True positives", min_value=0, value=8, step=1
        )
        fp = st.number_input(
            "False positives", min_value=0, value=1, step=1
        )

    with col2:
        tn = st.number_input(
            "True negatives", min_value=0, value=9, step=1
        )
        fn = st.number_input(
            "False negatives", min_value=0, value=2, step=1
        )

    metrics = calculate_metrics(tp, fp, tn, fn)

    cols = st.columns(4)
    for col, (name, value) in zip(cols, metrics.items()):
        col.metric(
            name.replace("_", " ").title(),
            f"{value:.1%}",
        )

st.divider()
st.caption(
    "Local educational prototype. Encoding and obfuscation do not "
    "establish that a sample is malicious or safe."
)
