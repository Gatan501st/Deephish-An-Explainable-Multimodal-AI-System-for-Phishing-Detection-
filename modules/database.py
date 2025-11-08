"""
Database Module for DeepPhish
Handles all database operations using Supabase
"""
import os
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from modules.auth import get_supabase
from dotenv import load_dotenv

load_dotenv()


def save_analysis_history(
    user_id: str,
    analysis_type: str,
    result_data: Dict[str, Any],
    input_data: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    Save analysis result to database
    Returns analysis_id if successful, None otherwise
    """
    supabase = get_supabase()
    if not supabase:
        return None

    try:
        # Extract key metrics from result
        nlu_analysis = result_data.get("nlu_analysis", {})
        dnn_analysis = result_data.get("dnn_analysis", {})
        
        is_phishing = False
        confidence = 0.0
        risk_level = "LOW"
        risk_score = 0.0

        # Determine if phishing from NLU or DNN
        if nlu_analysis and not nlu_analysis.get("error"):
            is_phishing = nlu_analysis.get("is_phishing", False)
            confidence = nlu_analysis.get("confidence", 0.0)
        elif dnn_analysis and not dnn_analysis.get("error"):
            if isinstance(dnn_analysis, list) and len(dnn_analysis) > 0:
                dnn = dnn_analysis[0]
            else:
                dnn = dnn_analysis
            is_phishing = dnn.get("is_phishing", False)
            confidence = dnn.get("confidence", 0.0)

        # Calculate risk level
        if is_phishing:
            if confidence >= 0.8:
                risk_level = "HIGH"
                risk_score = confidence
            elif confidence >= 0.6:
                risk_level = "MEDIUM"
                risk_score = confidence
            else:
                risk_level = "LOW"
                risk_score = confidence
        else:
            risk_score = 1 - confidence

        # Insert into database
        response = supabase.table("analysis_history").insert({
            "user_id": user_id,
            "analysis_type": analysis_type,
            "input_data": input_data or {},
            "result_data": result_data,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "is_phishing": is_phishing,
            "confidence": confidence,
        }).execute()

        if response.data and len(response.data) > 0:
            return response.data[0]["id"]
        return None

    except Exception as e:
        print(f"Error saving analysis history: {e}")
        return None


def get_analysis_history(
    user_id: str,
    limit: int = 50,
    offset: int = 0,
    analysis_type: Optional[str] = None,
    is_phishing: Optional[bool] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Get analysis history for a user with filters
    """
    supabase = get_supabase()
    if not supabase:
        return []

    try:
        query = supabase.table("analysis_history").select("*").eq("user_id", user_id)

        if analysis_type:
            query = query.eq("analysis_type", analysis_type)
        if is_phishing is not None:
            query = query.eq("is_phishing", is_phishing)
        if start_date:
            query = query.gte("created_at", start_date.isoformat())
        if end_date:
            query = query.lte("created_at", end_date.isoformat())

        query = query.order("created_at", desc=True).limit(limit).offset(offset)

        response = query.execute()
        return response.data if response.data else []

    except Exception as e:
        print(f"Error getting analysis history: {e}")
        return []


def get_analysis_by_id(analysis_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a specific analysis by ID
    """
    supabase = get_supabase()
    if not supabase:
        return None

    try:
        response = supabase.table("analysis_history").select("*").eq("id", analysis_id).eq("user_id", user_id).execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]
        return None

    except Exception as e:
        print(f"Error getting analysis by ID: {e}")
        return None


def get_user_statistics(user_id: str, days: int = 30) -> Dict[str, Any]:
    """
    Get statistics for a user
    """
    supabase = get_supabase()
    if not supabase:
        return {}

    try:
        start_date = datetime.now() - timedelta(days=days)
        
        # Get all analyses in date range
        response = supabase.table("analysis_history").select("*").eq("user_id", user_id).gte("created_at", start_date.isoformat()).execute()
        
        analyses = response.data if response.data else []
        
        total = len(analyses)
        phishing_count = sum(1 for a in analyses if a.get("is_phishing", False))
        safe_count = total - phishing_count
        
        # Group by type
        by_type = {}
        for analysis in analyses:
            a_type = analysis.get("analysis_type", "unknown")
            by_type[a_type] = by_type.get(a_type, 0) + 1
        
        # Group by risk level
        by_risk = {}
        for analysis in analyses:
            risk = analysis.get("risk_level", "LOW")
            by_risk[risk] = by_risk.get(risk, 0) + 1
        
        # Daily counts
        daily_counts = {}
        for analysis in analyses:
            date = analysis.get("created_at", "")[:10]  # Get date part
            daily_counts[date] = daily_counts.get(date, 0) + 1

        return {
            "total_analyses": total,
            "phishing_detected": phishing_count,
            "safe_detected": safe_count,
            "phishing_rate": (phishing_count / total * 100) if total > 0 else 0,
            "by_type": by_type,
            "by_risk_level": by_risk,
            "daily_counts": daily_counts,
            "period_days": days,
        }

    except Exception as e:
        print(f"Error getting user statistics: {e}")
        return {}


def create_feedback_report(
    analysis_id: str,
    user_id: str,
    feedback_type: str,
    original_prediction: str,
    user_correction: Optional[str] = None,
    comments: Optional[str] = None,
) -> Optional[str]:
    """
    Create a false positive/negative feedback report
    """
    supabase = get_supabase()
    if not supabase:
        return None

    try:
        response = supabase.table("feedback_reports").insert({
            "analysis_id": analysis_id,
            "user_id": user_id,
            "feedback_type": feedback_type,
            "original_prediction": original_prediction,
            "user_correction": user_correction,
            "comments": comments,
        }).execute()

        if response.data and len(response.data) > 0:
            return response.data[0]["id"]
        return None

    except Exception as e:
        print(f"Error creating feedback report: {e}")
        return None


def get_or_create_user_profile(user_id: str, email: str) -> Dict[str, Any]:
    """
    Get or create user profile
    """
    supabase = get_supabase()
    if not supabase:
        return {}

    try:
        # Try to get existing profile
        response = supabase.table("user_profiles").select("*").eq("id", user_id).execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]
        
        # Create new profile
        response = supabase.table("user_profiles").insert({
            "id": user_id,
            "email": email,
            "role": "user",
            "preferences": {},
        }).execute()

        if response.data and len(response.data) > 0:
            return response.data[0]
        return {}

    except Exception as e:
        print(f"Error getting/creating user profile: {e}")
        return {}


def update_user_preferences(user_id: str, preferences: Dict[str, Any]) -> bool:
    """
    Update user preferences
    """
    supabase = get_supabase()
    if not supabase:
        return False

    try:
        supabase.table("user_profiles").update({
            "preferences": preferences,
            "updated_at": datetime.now().isoformat(),
        }).eq("id", user_id).execute()
        return True

    except Exception as e:
        print(f"Error updating user preferences: {e}")
        return False


def get_threat_rules(user_id: str, organization_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Get threat rules (whitelist/blacklist) for a user or organization
    """
    supabase = get_supabase()
    if not supabase:
        return []

    try:
        query = supabase.table("threat_rules").select("*")
        
        if organization_id:
            query = query.eq("organization_id", organization_id)
        else:
            query = query.eq("user_id", user_id).is_("organization_id", "null")

        response = query.execute()
        return response.data if response.data else []

    except Exception as e:
        print(f"Error getting threat rules: {e}")
        return []


def create_threat_rule(
    user_id: str,
    rule_type: str,
    rule_category: str,
    rule_value: str,
    description: Optional[str] = None,
    organization_id: Optional[str] = None,
) -> Optional[str]:
    """
    Create a threat rule (whitelist/blacklist entry)
    """
    supabase = get_supabase()
    if not supabase:
        return None

    try:
        response = supabase.table("threat_rules").insert({
            "user_id": user_id,
            "organization_id": organization_id,
            "rule_type": rule_type,
            "rule_category": rule_category,
            "rule_value": rule_value,
            "description": description,
            "created_by": user_id,
        }).execute()

        if response.data and len(response.data) > 0:
            return response.data[0]["id"]
        return None

    except Exception as e:
        print(f"Error creating threat rule: {e}")
        return None


def delete_threat_rule(rule_id: str, user_id: str) -> bool:
    """
    Delete a threat rule
    """
    supabase = get_supabase()
    if not supabase:
        return False

    try:
        supabase.table("threat_rules").delete().eq("id", rule_id).eq("user_id", user_id).execute()
        return True

    except Exception as e:
        print(f"Error deleting threat rule: {e}")
        return False

