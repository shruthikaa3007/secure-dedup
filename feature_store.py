import csv
import os

FILE = "detection_results.csv"

def save_features(client_id, features, anomaly=None, label=None):
    file_exists = os.path.isfile(FILE)

    with open(FILE, "a", newline="") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(
                ["client_id"]
                + list(features.keys())
                + ["is_anomaly", "attack_label"]
            )

        writer.writerow(
            [client_id]
            + list(features.values())
            + [anomaly, label]
        )
