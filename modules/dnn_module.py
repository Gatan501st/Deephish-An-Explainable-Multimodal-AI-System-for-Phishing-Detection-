"""
DNN Module for URL/IP Phishing Detection
Uses Multilayer Perceptron (MLP) to classify URLs based on extracted features
"""

import pandas as pd
import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
import re
import socket
from urllib.parse import urlparse
from typing import Dict, List, Any, Tuple, Optional
import os
from pathlib import Path

# Try to import dns.resolver (optional)
try:
    import dns.resolver

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# Feature names in order (as per the model training)
FEATURE_NAMES = [
    "Have_IP",
    "Have_At",
    "URL_Length",
    "URL_Depth",
    "Redirection",
    "https_Domain",
    "TinyURL",
    "Prefix/Suffix",
    "DNS_Record",
    "Web_Traffic",
    "Domain_Age",
    "Domain_End",
    "iFrame",
    "Mouse_Over",
    "Right_Click",
    "Web_Forwards",
]

# Feature descriptions for user-friendly display
FEATURE_DESCRIPTIONS = {
    "Have_IP": "URL contains IP address instead of domain name",
    "Have_At": "URL contains @ symbol (suspicious)",
    "URL_Length": "URL length indicates suspicious pattern",
    "URL_Depth": "Number of path levels in URL",
    "Redirection": "URL uses redirection",
    "https_Domain": "Domain uses HTTPS protocol",
    "TinyURL": "URL is shortened (TinyURL, bit.ly, etc.)",
    "Prefix/Suffix": "URL has suspicious prefix or suffix",
    "DNS_Record": "Domain has valid DNS records",
    "Web_Traffic": "Domain shows web traffic patterns",
    "Domain_Age": "Domain age indicator (new domains are suspicious)",
    "Domain_End": "Domain ending type (suspicious TLDs)",
    "iFrame": "Page uses iframe (often in phishing)",
    "Mouse_Over": "Mouse over reveals suspicious content",
    "Right_Click": "Right click is disabled",
    "Web_Forwards": "URL uses forwarding mechanism",
}

# Global model and scaler
_model: Optional[MLPClassifier] = None
_scaler: Optional[StandardScaler] = None
_model_loaded = False


def extract_url_features(url: str) -> Dict[str, int]:
    """
    Extract phishing-related features from a URL
    Returns a dictionary with feature names and values
    """
    features = {}

    try:
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        full_url = url.lower()

        # 1. Have_IP: Check if domain is an IP address
        try:
            socket.inet_aton(domain.split(":")[0])  # Check if it's an IP
            features["Have_IP"] = 1
        except (socket.error, ValueError):
            features["Have_IP"] = 0

        # 2. Have_At: Check for @ symbol
        features["Have_At"] = 1 if "@" in url else 0

        # 3. URL_Length: Categorize URL length (1 if > 54 chars, 0 otherwise)
        features["URL_Length"] = 1 if len(url) > 54 else 0

        # 4. URL_Depth: Count path depth (number of /)
        path = parsed.path.strip("/")
        features["URL_Depth"] = path.count("/") if path else 0

        # 5. Redirection: Check for common redirection indicators
        redir_indicators = ["redirect", "go.php", "link", "url=", "ref="]
        features["Redirection"] = (
            1 if any(indicator in full_url for indicator in redir_indicators) else 0
        )

        # 6. https_Domain: Check if HTTPS is used
        features["https_Domain"] = 1 if parsed.scheme == "https" else 0

        # 7. TinyURL: Check if it's a shortened URL
        short_url_domains = [
            "bit.ly",
            "tinyurl.com",
            "goo.gl",
            "t.co",
            "ow.ly",
            "is.gd",
            "buff.ly",
        ]
        features["TinyURL"] = (
            1 if any(domain.endswith(short) for short in short_url_domains) else 0
        )

        # 8. Prefix/Suffix: Check for suspicious prefix or suffix
        suspicious_prefixes = ["http://", "-", "_"]
        suspicious_suffixes = [".exe", ".zip", ".scr", ".bat"]
        has_prefix = any(domain.startswith(pref) for pref in suspicious_prefixes)
        has_suffix = any(full_url.endswith(suff) for suff in suspicious_suffixes)
        features["Prefix/Suffix"] = 1 if (has_prefix or has_suffix) else 0

        # 9. DNS_Record: Try to resolve DNS (simplified check)
        # DNS_Record = 0 means suspicious (can't resolve or doesn't exist)
        # DNS_Record = 1 means legitimate (can resolve)
        try:
            if features["Have_IP"] == 0:
                # Try to resolve domain
                socket.gethostbyname(domain.split(":")[0])
                features["DNS_Record"] = 1  # Valid DNS record
            else:
                features["DNS_Record"] = 0  # IP addresses don't need DNS resolution
        except (socket.gaierror, socket.error):
            features["DNS_Record"] = 0  # Suspicious: can't resolve domain

        # 10. Web_Traffic: Assume 1 for now (would need actual traffic data)
        features["Web_Traffic"] = 1

        # 11. Domain_Age: Check for suspicious patterns (new/suspicious domains)
        # Domain_Age = 1 indicates suspicious (new/short/numeric domains)
        # Domain_Age = 0 indicates established domain
        domain_part = domain.split(":")[0].split(".")[0]
        is_numeric_domain = domain_part.isdigit()
        is_very_short = len(domain_part) < 4
        has_numbers = any(char.isdigit() for char in domain_part)
        # Also check for random-looking character strings
        is_random_looking = (
            len(domain_part) > 10 and len(set(domain_part)) / len(domain_part) > 0.7
        )
        features["Domain_Age"] = (
            1
            if (
                is_numeric_domain
                or is_very_short
                or (has_numbers and len(domain_part) < 6)
                or is_random_looking
            )
            else 0
        )

        # 12. Domain_End: Check for suspicious TLDs
        # Domain_End = 1 indicates suspicious TLD
        # Domain_End = 0 indicates common/legitimate TLD
        suspicious_tlds = [
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".gq",
            ".xyz",
            ".top",
            ".click",
            ".download",
            ".stream",
            ".review",
            ".science",
        ]
        # Also check if TLD is unusual or very long
        domain_parts = domain.split(":")[0].split(".")
        if len(domain_parts) >= 2:
            tld = "." + domain_parts[-1]
            has_suspicious_tld = any(
                domain.endswith(tld_susp) for tld_susp in suspicious_tlds
            )
            is_long_tld = len(domain_parts[-1]) > 4  # Long TLDs can be suspicious
            features["Domain_End"] = 1 if (has_suspicious_tld or is_long_tld) else 0
        else:
            features["Domain_End"] = 0

        # 13-16. iFrame, Mouse_Over, Right_Click, Web_Forwards
        # These require actual page analysis, so we'll use heuristics
        # For now, we'll set defaults based on suspicious patterns

        # iFrame: Often used in phishing
        iframe_indicators = ["iframe", "embed", "frame"]
        features["iFrame"] = (
            1 if any(ind in full_url for ind in iframe_indicators) else 0
        )

        # Mouse_Over: Suspicious if URL looks manipulated
        features["Mouse_Over"] = 1 if features["Have_At"] or features["TinyURL"] else 0

        # Right_Click: Can't detect from URL alone, use heuristic
        features["Right_Click"] = 0  # Default, would need page analysis

        # Web_Forwards: Check for forwarding indicators
        forward_indicators = ["forward", "redirect", "goto", "link"]
        features["Web_Forwards"] = (
            1 if any(ind in full_url for ind in forward_indicators) else 0
        )

    except Exception as e:
        # If extraction fails, return default values
        print(f"Error extracting features from URL {url}: {e}")
        features = {name: 0 for name in FEATURE_NAMES}

    # Ensure all features are present
    for name in FEATURE_NAMES:
        if name not in features:
            features[name] = 0

    return features


def load_or_train_model(
    data_path: Optional[str] = None,
) -> Tuple[MLPClassifier, StandardScaler]:
    """
    Load pre-trained model or train a new one from data
    """
    global _model, _scaler, _model_loaded

    model_path = Path("models/dnn_url_classifier.pkl")
    scaler_path = Path("models/dnn_scaler.pkl")

    # Try to load existing model
    if model_path.exists() and scaler_path.exists():
        try:
            import joblib

            _model = joblib.load(model_path)
            _scaler = joblib.load(scaler_path)
            _model_loaded = True
            print("✅ Loaded pre-trained DNN model")
            return _model, _scaler
        except Exception as e:
            print(f"⚠️ Could not load model: {e}. Training new model...")

    # Train new model if loading fails
    if data_path is None:
        data_path = "data\PhiUSIIL_Phishing_URL_Dataset.csv"

    if not os.path.exists(data_path):
        raise FileNotFoundError(
            f"Dataset not found at {data_path}. Cannot train model."
        )

    print("📊 Training DNN model from data...")
    data = pd.read_csv(data_path)

    # Drop Domain column and prepare features
    X = data.drop(["Domain", "Label"], axis=1)
    y = data["Label"]

    # Shuffle data
    data_shuffled = data.sample(frac=1).reset_index(drop=True)
    X = data_shuffled.drop(["Domain", "Label"], axis=1)
    y = data_shuffled["Label"]

    # Split data
    from sklearn.model_selection import train_test_split

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=12
    )

    # Scale features
    _scaler = StandardScaler()
    X_train_scaled = _scaler.fit_transform(X_train)
    X_test_scaled = _scaler.transform(X_test)

    # Train MLP
    _model = MLPClassifier(
        alpha=0.001, hidden_layer_sizes=([100, 100, 100]), random_state=12
    )
    _model.fit(X_train_scaled, y_train)

    # Evaluate
    train_score = _model.score(X_train_scaled, y_train)
    test_score = _model.score(X_test_scaled, y_test)
    print(
        f"✅ Model trained - Train Accuracy: {train_score:.3f}, Test Accuracy: {test_score:.3f}"
    )

    # Save model
    try:
        import joblib

        Path("models").mkdir(exist_ok=True)
        joblib.dump(_model, model_path)
        joblib.dump(_scaler, scaler_path)
        print(f"💾 Model saved to {model_path}")
    except Exception as e:
        print(f"⚠️ Could not save model: {e}")

    _model_loaded = True
    return _model, _scaler


def get_model():
    """Get or load the model"""
    global _model, _scaler, _model_loaded

    if not _model_loaded or _model is None or _scaler is None:
        load_or_train_model()
    return _model, _scaler


def predict_url(url: str) -> Dict[str, Any]:
    """
    Predict if URL is phishing and return feature contributions
    """
    try:
        # Extract features
        features = extract_url_features(url)

        # Get model
        model, scaler = get_model()

        # Convert to array in correct order
        feature_vector = np.array([[features[name] for name in FEATURE_NAMES]])

        # Scale features
        feature_vector_scaled = scaler.transform(feature_vector)

        # Predict
        prediction = model.predict(feature_vector_scaled)[0]
        probabilities = model.predict_proba(feature_vector_scaled)[0]

        # Get feature importance (using feature values weighted by model coefficients)
        # For MLP, we can approximate importance by looking at input layer weights
        feature_contributions = {}
        if hasattr(model, "coefs_") and len(model.coefs_) > 0:
            # Get first layer weights (input to first hidden)
            input_weights = model.coefs_[0]  # Shape: (n_features, n_hidden)
            # Average absolute weights per feature
            feature_importance = np.abs(input_weights).mean(axis=1)
            # Weight by actual feature value
            for i, name in enumerate(FEATURE_NAMES):
                contribution = feature_importance[i] * features[name]
                feature_contributions[name] = {
                    "value": int(features[name]),
                    "contribution": float(contribution),
                    "description": FEATURE_DESCRIPTIONS.get(name, ""),
                }
        else:
            # Fallback: use feature values directly as contribution
            for name in FEATURE_NAMES:
                feature_contributions[name] = {
                    "value": int(features[name]),
                    "contribution": float(features[name]),
                    "description": FEATURE_DESCRIPTIONS.get(name, ""),
                }

        # Sort features by contribution (highest first)
        sorted_features = sorted(
            feature_contributions.items(),
            key=lambda x: x[1]["contribution"],
            reverse=True,
        )

        # Get top contributing features
        phishing_features = [
            {
                "feature": name,
                "value": data["value"],
                "contribution": data["contribution"],
                "description": data["description"],
            }
            for name, data in sorted_features
            if data["value"] > 0 and data["contribution"] > 0
        ]

        return {
            "is_phishing": bool(prediction == 1),
            "prediction": "PHISHING" if prediction == 1 else "LEGITIMATE",
            "confidence": float(
                probabilities[1] if prediction == 1 else probabilities[0]
            ),
            "probabilities": {
                "legitimate": float(probabilities[0]),
                "phishing": float(probabilities[1]),
            },
            "features": features,
            "feature_contributions": feature_contributions,
            "top_phishing_indicators": phishing_features[:10],  # Top 10
            "url": url,
        }

    except Exception as e:
        return {
            "error": f"Failed to analyze URL: {str(e)}",
            "url": url,
        }


def analyze_urls(urls: List[str]) -> Dict[str, Any]:
    """
    Analyze multiple URLs and return aggregated results
    """
    results = []
    for url in urls:
        result = predict_url(url)
        results.append(result)

    # Aggregate statistics
    phishing_count = sum(1 for r in results if r.get("is_phishing", False))
    total_count = len(results)

    return {
        "total_urls": total_count,
        "phishing_count": phishing_count,
        "legitimate_count": total_count - phishing_count,
        "urls_analyzed": results,
    }


def get_feature_explanation(feature_name: str) -> str:
    """Get human-readable explanation of a feature"""
    return FEATURE_DESCRIPTIONS.get(feature_name, f"Feature: {feature_name}")
