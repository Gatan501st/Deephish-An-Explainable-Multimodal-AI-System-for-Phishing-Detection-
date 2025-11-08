"""
NLU Phishing Detection Model Evaluation Script
This script evaluates the BERT-based phishing detection model with comprehensive metrics.
Run this script or convert to Jupyter notebook for interactive evaluation.
"""

import pandas as pd
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

# Optional visualization imports - script will work without them
try:
    import matplotlib.pyplot as plt
    import seaborn as sns

    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False
    print(
        "⚠️  matplotlib/seaborn not available. Metrics will be printed but visualizations will be skipped."
    )
    print("   Install with: pip install matplotlib seaborn")

try:
    from tqdm import tqdm
except ImportError:
    # Fallback if tqdm is not available
    def tqdm(iterable, desc=""):
        print(f"{desc}...")
        return iterable


import warnings

warnings.filterwarnings("ignore")

# ============================================================================
# 1. Load Model and Tokenizer
# ============================================================================
print("=" * 60)
print("Loading Phishing Detection Model")
print("=" * 60)

model_name = "ealvaradob/bert-finetuned-phishing"
print(f"Loading model: {model_name}")

tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

# Set device
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)
model.eval()

print(f"✅ Model loaded successfully on {device}\n")

# ============================================================================
# 2. Load and Prepare Test Dataset
# ============================================================================
print("=" * 60)
print("Loading Test Dataset")
print("=" * 60)

try:
    # Try to load actual dataset - use smaller sample for faster evaluation
    df = pd.read_csv(
        "data/phishing_email.csv", nrows=500
    )  # Reduced to 500 for faster evaluation
    print(f"Loaded dataset with {len(df)} samples")

    # Find text and label columns
    text_col = None
    label_col = None

    for col in df.columns:
        if "text" in col.lower() or "content" in col.lower() or "email" in col.lower():
            text_col = col
        if (
            "label" in col.lower()
            or "class" in col.lower()
            or "phishing" in col.lower()
        ):
            label_col = col

    if text_col and label_col:
        # Clean data
        df = df.dropna(subset=[text_col, label_col])
        df = df[df[text_col].astype(str).str.len() > 10]

        texts = df[text_col].astype(str).tolist()
        labels = df[label_col].astype(int).tolist()

        print(f"✅ Final dataset size: {len(texts)} samples")
        print(f"Label distribution:\n{df[label_col].value_counts()}\n")
    else:
        raise ValueError("Could not find text/label columns")

except Exception as e:
    print(f"⚠️  Error loading dataset: {e}")
    print("Creating synthetic test data for demonstration...\n")

    # Create synthetic test data
    phishing_texts = [
        "URGENT: Your account will be suspended. Click here to verify immediately.",
        "You have won a prize! Click the link to claim your reward.",
        "Your password needs to be updated. Click here to reset now.",
        "Security alert: Unusual activity detected. Verify your account.",
        "Limited time offer! Free gift card. Click to claim.",
        "Your account has been compromised. Verify your identity now.",
        "Congratulations! You've been selected for a special offer.",
        "Action required: Update your payment information immediately.",
        "Your subscription will expire soon. Renew now to continue.",
        "Important: Confirm your email address to avoid account suspension.",
    ] * 10  # Repeat for more samples

    legitimate_texts = [
        "Thank you for your order. Your package will arrive tomorrow.",
        "Meeting reminder: Team standup at 10 AM in conference room.",
        "Here is the report you requested regarding Q4 sales.",
        "Happy birthday! Hope you have a wonderful day.",
        "The project deadline has been extended to next Friday.",
        "Please review the attached document and provide feedback.",
        "Welcome to our newsletter. Here are this month's updates.",
        "Your order has been shipped. Tracking number: ABC123.",
        "Thank you for your interest in our product catalog.",
        "Reminder: Quarterly review meeting scheduled for next week.",
    ] * 10  # Repeat for more samples

    texts = phishing_texts + legitimate_texts
    labels = [1] * len(phishing_texts) + [0] * len(legitimate_texts)

    print(f"✅ Created {len(texts)} synthetic test samples\n")

# ============================================================================
# 3. Make Predictions
# ============================================================================
print("=" * 60)
print("Making Predictions")
print("=" * 60)


def predict_batch(texts, batch_size=64):
    """Make predictions on a batch of texts - optimized for speed"""
    predictions = []
    probabilities = []

    # Process in larger batches for speed
    for i in tqdm(range(0, len(texts), batch_size), desc="Predicting", leave=False):
        batch_texts = texts[i : i + batch_size]

        # Tokenize with shorter max_length for speed
        inputs = tokenizer(
            batch_texts,
            padding=True,
            truncation=True,
            max_length=256,  # Reduced from 512 for speed
            return_tensors="pt",
        ).to(device)

        # Predict
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probs = torch.nn.functional.softmax(logits, dim=-1)
            preds = torch.argmax(logits, dim=-1)

        predictions.extend(preds.cpu().numpy())
        probabilities.extend(probs.cpu().numpy())

    return np.array(predictions), np.array(probabilities)


y_pred, y_probs = predict_batch(texts)
y_true = np.array(labels)

print(f"\n✅ Predictions completed: {len(y_pred)} samples")
print(f"Prediction distribution: {np.bincount(y_pred)}\n")

# ============================================================================
# 4. Calculate Metrics
# ============================================================================
print("=" * 60)
print("CALCULATING METRICS")
print("=" * 60)

accuracy = accuracy_score(y_true, y_pred)
precision = precision_score(y_true, y_pred, average="binary", zero_division=0)
recall = recall_score(y_true, y_pred, average="binary", zero_division=0)
f1 = f1_score(y_true, y_pred, average="binary", zero_division=0)

# Confusion matrix
cm = confusion_matrix(y_true, y_pred)

# Print results
print(f"\n📊 Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"🎯 Precision: {precision:.4f} ({precision*100:.2f}%)")
print(f"📈 Recall:    {recall:.4f} ({recall*100:.2f}%)")
print(f"⚡ F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
print("\n" + "=" * 60)

# Detailed classification report
print("\n📋 Detailed Classification Report:")
print("=" * 60)
print(classification_report(y_true, y_pred, target_names=["HAM", "PHISHING"]))

# ============================================================================
# 5. Visualize Results (Optional)
# ============================================================================
if VISUALIZATION_AVAILABLE:
    print("\n" + "=" * 60)
    print("GENERATING VISUALIZATIONS")
    print("=" * 60)

    try:
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))

        # Confusion Matrix
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=["HAM", "PHISHING"],
            yticklabels=["HAM", "PHISHING"],
            ax=axes[0],
        )
        axes[0].set_title("Confusion Matrix", fontsize=14, fontweight="bold")
        axes[0].set_ylabel("True Label", fontsize=12)
        axes[0].set_xlabel("Predicted Label", fontsize=12)

        # Metrics Bar Chart
        metrics = ["Accuracy", "Precision", "Recall", "F1-Score"]
        values = [accuracy, precision, recall, f1]
        colors = ["#3498db", "#2ecc71", "#f39c12", "#e74c3c"]

        bars = axes[1].bar(
            metrics, values, color=colors, alpha=0.7, edgecolor="black", linewidth=1.5
        )
        axes[1].set_ylim([0, 1])
        axes[1].set_ylabel("Score", fontsize=12)
        axes[1].set_title("Model Performance Metrics", fontsize=14, fontweight="bold")
        axes[1].grid(axis="y", alpha=0.3, linestyle="--")

        # Add value labels on bars
        for bar, value in zip(bars, values):
            height = bar.get_height()
            axes[1].text(
                bar.get_x() + bar.get_width() / 2.0,
                height + 0.01,
                f"{value:.3f}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        plt.tight_layout()
        plt.savefig("nlu_evaluation_results.png", dpi=300, bbox_inches="tight")
        print("✅ Visualization saved as 'nlu_evaluation_results.png'")
        plt.show()
    except Exception as e:
        print(f"⚠️  Error generating visualizations: {e}")
        print("   Continuing without visualizations...")
else:
    print("\n" + "=" * 60)
    print("VISUALIZATIONS SKIPPED")
    print("=" * 60)
    print("   Install matplotlib and seaborn to enable visualizations:")
    print("   pip install matplotlib seaborn")

# ============================================================================
# 6. Model Efficiency Summary
# ============================================================================
print("\n" + "=" * 60)
print("MODEL EFFICIENCY SUMMARY")
print("=" * 60)

summary = pd.DataFrame(
    {
        "Metric": ["Accuracy", "Precision", "Recall", "F1-Score"],
        "Score": [f"{accuracy:.4f}", f"{precision:.4f}", f"{recall:.4f}", f"{f1:.4f}"],
        "Percentage": [
            f"{accuracy*100:.2f}%",
            f"{precision*100:.2f}%",
            f"{recall*100:.2f}%",
            f"{f1*100:.2f}%",
        ],
    }
)

print(summary.to_string(index=False))
print("\n" + "=" * 60)

# Interpretation
print("\n📝 Interpretation:")
print(f"   • The model correctly identifies {accuracy*100:.1f}% of all samples")
print(f"   • When predicting phishing, {precision*100:.1f}% are actually phishing")
print(f"   • The model detects {recall*100:.1f}% of all phishing emails")
print(f"   • Overall F1-score of {f1*100:.1f}% indicates balanced performance")

if accuracy > 0.9 and f1 > 0.85:
    print("\n✅ Model Performance: EXCELLENT")
elif accuracy > 0.8 and f1 > 0.75:
    print("\n✅ Model Performance: GOOD")
else:
    print("\n⚠️  Model Performance: NEEDS IMPROVEMENT")

print("\n" + "=" * 60)
print("Evaluation Complete!")
print("=" * 60)
