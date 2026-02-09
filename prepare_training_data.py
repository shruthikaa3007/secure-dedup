import pandas as pd

# Load dataset
df = pd.read_csv("feature_dataset.csv")

print("Columns found:", df.columns.tolist())

# Remove non-feature columns
non_feature_cols = ["client_id"]
feature_cols = [c for c in df.columns if c not in non_feature_cols]

if not feature_cols:
    raise ValueError("❌ No feature columns found. Feature dataset is empty.")

# Drop rows with missing values
df = df.dropna(subset=feature_cols)

print("✅ Clean dataset shape:", df.shape)

# Save cleaned data
df.to_csv("training_data.csv", index=False)

print("✅ training_data.csv created")
