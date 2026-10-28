
import csv
import json
from pathlib import Path

from encoder.transformations import (
    base64_encode,
    rot13_transform,
    xor_transform,
)
from detection.signatures import analyze_sample
from evaluation.metrics import calculate_metrics


PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_DIR / "data" / "samples.json"
REPORT_DIR = PROJECT_DIR / "reports"


def create_representation(text: str, encoding: str) -> str:
    """Create the representation specified by a test case."""

    if encoding == "none":
        return text

    if encoding == "base64":
        return base64_encode(text)

    if encoding == "rot13":
        return rot13_transform(text)

    if encoding == "xor_hex":
        return xor_transform(text, "demo-key")

    raise ValueError(f"Unsupported encoding: {encoding}")


def load_samples() -> list[dict]:
    """Load the labeled test cases from JSON."""

    with DATA_FILE.open("r", encoding="utf-8") as file:
        samples = json.load(file)

    if not isinstance(samples, list):
        raise ValueError("The dataset must contain a list of samples.")

    for sample in samples:
        if sample.get("label") not in ("positive", "negative"):
            raise ValueError(
                f"Invalid label in sample {sample.get('id')}"
            )

    return samples


def evaluate_dataset() -> dict:
    """Evaluate the dataset and calculate raw and normalized metrics."""

    results = []

    for sample in load_samples():
        sample_id = sample["id"]
        original_text = sample["text"]
        label = sample["label"]
        encoding = sample.get("encoding", "none")

        representation = create_representation(
            original_text, encoding
        )

        analysis = analyze_sample(
            representation,
            encoding=encoding,
            xor_key="demo-key" if encoding == "xor_hex" else "",
        )

        expected_positive = label == "positive"

        raw_detected = analysis["raw_detected"]
        normalized_detected = analysis["normalized_detected"]

        results.append({
            "id": sample_id,
            "label": label,
            "encoding": encoding,
            "raw_detected": raw_detected,
            "normalized_detected": normalized_detected,
            "raw_correct": raw_detected == expected_positive,
            "normalized_correct": (
                normalized_detected == expected_positive
            ),
            "normalization_error": (
                analysis["normalization_error"] or ""
            ),
        })

    def confusion_counts(prediction_field: str) -> tuple[int, int, int, int]:
        tp = fp = tn = fn = 0

        for result in results:
            actual = result["label"] == "positive"
            predicted = result[prediction_field]

            if actual and predicted:
                tp += 1
            elif not actual and predicted:
                fp += 1
            elif not actual and not predicted:
                tn += 1
            else:
                fn += 1

        return tp, fp, tn, fn

    raw_counts = confusion_counts("raw_detected")
    normalized_counts = confusion_counts("normalized_detected")

    report = {
        "sample_count": len(results),
        "raw_metrics": calculate_metrics(*raw_counts),
        "normalized_metrics": calculate_metrics(*normalized_counts),
        "results": results,
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    json_path = REPORT_DIR / "evaluation_results.json"
    with json_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    csv_path = REPORT_DIR / "evaluation_results.csv"
    with csv_path.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        fieldnames = list(results[0].keys()) if results else []
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        if fieldnames:
            writer.writeheader()
            writer.writerows(results)

    return report


if __name__ == "__main__":
    report = evaluate_dataset()

    print(f"Samples evaluated: {report['sample_count']}")
    print("\nRaw detection metrics:")
    for name, value in report["raw_metrics"].items():
        print(f"{name}: {value:.2%}")

    print("\nDetection metrics after normalization:")
    for name, value in report["normalized_metrics"].items():
        print(f"{name}: {value:.2%}")

    print("\nReports saved in the reports folder.")
