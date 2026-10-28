
def calculate_metrics(
    true_positives: int,
    false_positives: int,
    true_negatives: int,
    false_negatives: int,
) -> dict[str, float]:
    """Calculate standard binary-classification metrics."""

    values = (
        true_positives,
        false_positives,
        true_negatives,
        false_negatives,
    )

    if any(value < 0 for value in values):
        raise ValueError("Counts cannot be negative.")

    tp, fp, tn, fn = values

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    false_positive_rate = (
        fp / (fp + tn) if fp + tn else 0.0
    )

    accuracy_total = tp + fp + tn + fn
    accuracy = (
        (tp + tn) / accuracy_total
        if accuracy_total
        else 0.0
    )

    return {
        "precision": precision,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "accuracy": accuracy,
    }
