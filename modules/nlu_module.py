import torch
import torch.nn as nn
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
)
import numpy as np
from typing import Dict, List, Any, Tuple
import os
import sys

# Try to import the original nlu library for fallback
try:
    import nlu

    NLU_AVAILABLE = True
except Exception:
    NLU_AVAILABLE = False


# =====================================
# 🚀 Model and Tokenizer Loading
# =====================================
def load_phishing_model():
    """
    Load the phishing detection model and tokenizer
    Returns: (model, tokenizer) or (None, None) if loading fails
    """
    try:
        # Use the pre-trained phishing detection model
        model_name = "ealvaradob/bert-finetuned-phishing"
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)

        # Set device
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()  # Set to evaluation mode

        return model, tokenizer, device
    except Exception as e:
        print(f"Error loading phishing model: {e}")
        return None, None, None


# Global model variables
_model, _tokenizer, _device = load_phishing_model()


# =====================================
# 🧠 Core Classification Functions
# =====================================
def detect_phishing(texts: List[str]) -> Tuple[np.ndarray, np.ndarray]:
    """
    Detect phishing messages from a list of texts
    Args:
        texts: List of text strings to analyze
    Returns:
        Tuple of (predictions, probabilities) where:
        - predictions: numpy array of 0 (ham) or 1 (phishing)
        - probabilities: numpy array of probability distributions
    """
    if _model is None or _tokenizer is None:
        raise RuntimeError(
            "Phishing model not loaded. Please check model initialization."
        )

    # Tokenize inputs
    inputs = _tokenizer(
        texts, padding=True, truncation=True, max_length=512, return_tensors="pt"
    ).to(_device)

    # Get predictions
    with torch.no_grad():
        outputs = _model(**inputs)

    # Convert to probabilities
    probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
    predictions = torch.argmax(outputs.logits, dim=-1)

    return predictions.cpu().numpy(), probabilities.cpu().numpy()


def classify_text(text: str) -> Dict[str, Any]:
    """
    Classify a single text as phishing or ham using the phishing detection model
    Args:
        text: String to classify
    Returns:
        Dictionary with classification results
    """
    try:
        # Use the phishing detection model if available
        if _model is not None and _tokenizer is not None:
            predictions, probabilities = detect_phishing([text])
            pred = int(predictions[0])
            prob = probabilities[0]
            is_phishing = pred == 1
            confidence = prob[1] if is_phishing else prob[0]

            return {
                "document": text,
                "prediction": "PHISHING" if is_phishing else "HAM",
                "is_phishing": is_phishing,
                "confidence": float(confidence),
                "probabilities": {"ham": float(prob[0]), "phishing": float(prob[1])},
                "model": "phishing_detection",
            }

        # Fallback to original nlu library if available
        elif NLU_AVAILABLE:
            try:
                spam_df = nlu.load("classify.spam.use").predict(
                    [text], output_level="document"
                )
                doc = spam_df["document"].iloc[0] if "document" in spam_df else text
                spam_score = None
                if "spam" in spam_df:
                    try:
                        spam_score = float(spam_df["spam"].iloc[0])
                    except Exception:
                        spam_score = spam_df["spam"].iloc[0]
                return {
                    "document": doc,
                    "spam": spam_score,
                    "model": "nlu_spam_classifier",
                }
            except Exception as e:
                return {"error": f"NLU fallback failed: {str(e)}"}

        else:
            return {"error": "No classification models available"}

    except Exception as e:
        return {"error": str(e)}


# =====================================
# 📧 Email Analysis Functions
# =====================================
def analyze_email_content(email_text: str) -> Dict[str, Any]:
    """
    Analyze email content for phishing detection
    Args:
        email_text: Combined email text (subject + body)
    Returns:
        Dictionary with analysis results
    """
    try:
        if not email_text.strip():
            return {
                "is_phishing": False,
                "confidence": 0.0,
                "prediction": "HAM",
                "probabilities": {"ham": 1.0, "phishing": 0.0},
                "error": "Empty email content",
            }

        predictions, probabilities = detect_phishing([email_text])
        pred = int(predictions[0])
        prob = probabilities[0]
        is_phishing = pred == 1
        confidence = prob[1] if is_phishing else prob[0]

        return {
            "is_phishing": is_phishing,
            "confidence": float(confidence),
            "prediction": "PHISHING" if is_phishing else "HAM",
            "probabilities": {"ham": float(prob[0]), "phishing": float(prob[1])},
            "content_preview": email_text[:500]
            + ("..." if len(email_text) > 500 else ""),
        }

    except Exception as e:
        return {"error": f"Failed to analyze email content: {str(e)}"}


def analyze_comment(
    comment_text: str, comment_name: str = "user_comment"
) -> Dict[str, Any]:
    """
    Analyze user comment for phishing detection
    Args:
        comment_text: Comment text to analyze
        comment_name: Name/identifier for the comment
    Returns:
        Dictionary with analysis results
    """
    try:
        if not comment_text.strip():
            return {
                "is_phishing": False,
                "confidence": 0.0,
                "prediction": "HAM",
                "probabilities": {"ham": 1.0, "phishing": 0.0},
                "error": "Empty comment",
            }

        predictions, probabilities = detect_phishing([comment_text])
        pred = int(predictions[0])
        prob = probabilities[0]
        is_phishing = pred == 1
        confidence = prob[1] if is_phishing else prob[0]

        return {
            "is_phishing": is_phishing,
            "confidence": float(confidence),
            "prediction": "PHISHING" if is_phishing else "HAM",
            "probabilities": {"ham": float(prob[0]), "phishing": float(prob[1])},
            "comment_name": comment_name,
            "content_preview": comment_text[:200]
            + ("..." if len(comment_text) > 200 else ""),
        }

    except Exception as e:
        return {"error": f"Failed to analyze comment: {str(e)}"}


# =====================================
# 🔍 Risk Assessment Functions
# =====================================
def assess_risk_level(confidence: float, is_phishing: bool) -> str:
    """
    Assess risk level based on confidence and prediction
    Args:
        confidence: Confidence score (0-1)
        is_phishing: Boolean indicating if content is phishing
    Returns:
        Risk level: "LOW", "MEDIUM", or "HIGH"
    """
    if is_phishing:
        if confidence >= 0.8:
            return "HIGH"
        elif confidence >= 0.6:
            return "MEDIUM"
        else:
            return "LOW"
    else:
        if confidence >= 0.8:
            return "LOW"
        elif confidence >= 0.6:
            return "MEDIUM"
        else:
            return "MEDIUM"  # Low confidence in ham prediction is concerning


def get_recommendation(risk_level: str, is_phishing: bool) -> str:
    """
    Get recommendation based on risk assessment
    Args:
        risk_level: Risk level ("LOW", "MEDIUM", "HIGH")
        is_phishing: Boolean indicating if content is phishing
    Returns:
        Recommendation string
    """
    if risk_level == "HIGH":
        return "Do not interact with this content. Report to security team immediately."
    elif risk_level == "MEDIUM":
        return "Use caution. Verify sender and links before taking any action."
    else:
        if is_phishing:
            return (
                "Content appears suspicious but with low confidence. Review carefully."
            )
        else:
            return "Content appears safe. No immediate threats detected."


# =====================================
# 🧩 Comprehensive Analysis Function
# =====================================
def comprehensive_analysis(
    email_text: str = None, comment_text: str = None
) -> Dict[str, Any]:
    """
    Perform comprehensive analysis combining email and comment analysis
    Args:
        email_text: Email content to analyze
        comment_text: Comment content to analyze
    Returns:
        Dictionary with comprehensive analysis results
    """
    results = {
        "analysis_timestamp": None,  # Will be set by caller if needed
        "email_analysis": None,
        "comment_analysis": None,
        "combined_risk_assessment": None,
    }

    # Analyze email if provided
    if email_text and email_text.strip():
        results["email_analysis"] = analyze_email_content(email_text)

    # Analyze comment if provided
    if comment_text and comment_text.strip():
        results["comment_analysis"] = analyze_comment(comment_text)

    # Combined risk assessment
    risk_factors = []
    overall_risk = "LOW"

    if results["email_analysis"] and not results["email_analysis"].get("error"):
        email_risk = results["email_analysis"]["is_phishing"]
        email_confidence = results["email_analysis"]["confidence"]
        if email_risk:
            risk_factors.append(
                f"Email content detected as phishing (confidence: {email_confidence:.3f})"
            )
            overall_risk = assess_risk_level(email_confidence, email_risk)

    if results["comment_analysis"] and not results["comment_analysis"].get("error"):
        comment_risk = results["comment_analysis"]["is_phishing"]
        comment_confidence = results["comment_analysis"]["confidence"]
        if comment_risk:
            risk_factors.append(
                f"User comment detected as phishing (confidence: {comment_confidence:.3f})"
            )
            comment_risk_level = assess_risk_level(comment_confidence, comment_risk)
            if overall_risk == "LOW":
                overall_risk = comment_risk_level
            elif overall_risk == "MEDIUM" and comment_risk_level == "HIGH":
                overall_risk = "HIGH"

    results["combined_risk_assessment"] = {
        "overall_risk": overall_risk,
        "risk_factors": risk_factors,
        "recommendation": get_recommendation(overall_risk, len(risk_factors) > 0),
    }

    return results


# =====================================
# 🔧 Utility Functions
# =====================================
def is_model_loaded() -> bool:
    """
    Check if the phishing detection model is loaded
    Returns:
        Boolean indicating if model is available
    """
    return _model is not None and _tokenizer is not None


def get_model_info() -> Dict[str, Any]:
    """
    Get information about the loaded model
    Returns:
        Dictionary with model information
    """
    if _model is None:
        return {"error": "No model loaded"}

    return {
        "model_name": "ealvaradob/bert-finetuned-phishing",
        "device": str(_device) if _device else "unknown",
        "model_loaded": True,
        "tokenizer_loaded": _tokenizer is not None,
        "nlu_fallback_available": NLU_AVAILABLE,
    }
