# secure-dedup

Secure deduplication prototype with:
- chunk-level dedup + proof-of-ownership checks,
- behavioral feature extraction,
- ensemble anomaly detection.

## Train anomaly models from dataset

This project now supports an ensemble:
- Isolation Forest,
- One-Class SVM,
- optional LSTM autoencoder (if TensorFlow is installed).

### 1) Install dependencies

```bash
pip install -r requirements.txt
```

> Optional for LSTM training/inference:
>
> ```bash
> pip install tensorflow
> ```

### 2) Train models

```bash
python train_model.py --dataset training_data.csv --model-dir .
```

Optional knobs:

```bash
python train_model.py \
  --dataset training_data.csv \
  --model-dir . \
  --estimators 300 \
  --contamination 0.03 \
  --ocsvm-nu 0.03 \
  --sequence-length 12
```

Disable LSTM explicitly:

```bash
python train_model.py --dataset training_data.csv --disable-lstm
```

### Artifacts produced

- `isolation_forest.pkl`
- `one_class_svm.pkl`
- `scaler.pkl`
- `model_metadata.json`
- `lstm_autoencoder.keras` *(optional)*
- `lstm_threshold.npy` *(optional)*

## Runtime detection behavior

At runtime, `detector.py` uses an ensemble vote:
- Isolation Forest vote,
- One-Class SVM vote,
- optional LSTM vote when enough per-client history is available.

An anomaly is raised when at least 2 models vote anomalous.
