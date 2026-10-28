
import matplotlib.pyplot as plt


def create_metrics_chart(report: dict):
    """Compare raw and normalized detection metrics."""

    metric_names = [
        "precision",
        "recall",
        "false_positive_rate",
        "accuracy",
    ]

    raw = report["raw_metrics"]
    normalized = report["normalized_metrics"]

    raw_values = [raw[name] * 100 for name in metric_names]
    normalized_values = [
        normalized[name] * 100 for name in metric_names
    ]

    positions = list(range(len(metric_names)))
    width = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))

    ax.bar(
        [p - width / 2 for p in positions],
        raw_values,
        width,
        label="Raw detection",
    )

    ax.bar(
        [p + width / 2 for p in positions],
        normalized_values,
        width,
        label="After normalization",
    )

    ax.set_ylabel("Percentage")
    ax.set_title("Detection Evaluation Results")
    ax.set_xticks(positions)
    ax.set_xticklabels(
        ["Precision", "Recall", "False positive rate", "Accuracy"]
    )
    ax.set_ylim(0, 110)
    ax.legend()
    ax.grid(axis="y", alpha=0.25)

    fig.tight_layout()
    return fig
