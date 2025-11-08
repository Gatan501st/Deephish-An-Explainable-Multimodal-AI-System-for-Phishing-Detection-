"""
Supabase Authentication Module
Handles user authentication and session management
"""
import os
from typing import Optional, Dict, Any
from functools import wraps
from flask import request, jsonify, session
from supabase import create_client, Client
from dotenv import load_dotenv
import requests

load_dotenv()

# Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY", "")
supabase: Optional[Client] = None

if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        print(f"Warning: Failed to initialize Supabase client: {e}")
        supabase = None


def get_supabase() -> Optional[Client]:
    """Get Supabase client instance"""
    return supabase


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify JWT token from Supabase
    Returns user data if token is valid, None otherwise
    """
    if not supabase or not SUPABASE_URL:
        return None
    
    try:
        # Verify token by making a request to Supabase auth API
        headers = {
            "Authorization": f"Bearer {token}",
            "apikey": SUPABASE_KEY
        }
        response = requests.get(
            f"{SUPABASE_URL}/auth/v1/user",
            headers=headers,
            timeout=5
        )
        
        if response.status_code == 200:
            user_data = response.json()
            return {
                "id": user_data.get("id"),
                "email": user_data.get("email"),
                "email_verified": user_data.get("email_confirmed_at") is not None,
            }
        else:
            print(f"Token verification failed: HTTP {response.status_code}")
            return None
    except Exception as e:
        print(f"Token verification failed: {e}")
        return None


def require_auth(f):
    """
    Decorator to require authentication for API endpoints
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for token in Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required", "code": "UNAUTHORIZED"}), 401
        
        token = auth_header.replace("Bearer ", "")
        user = verify_token(token)
        
        if not user:
            return jsonify({"error": "Invalid or expired token", "code": "INVALID_TOKEN"}), 401
        
        # Attach user to request
        request.current_user = user
        return f(*args, **kwargs)
    
    return decorated_function


def optional_auth(f):
    """
    Decorator for endpoints that work with or without authentication
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")
            user = verify_token(token)
            request.current_user = user if user else None
        else:
            request.current_user = None
        return f(*args, **kwargs)
    
    return decorated_function

