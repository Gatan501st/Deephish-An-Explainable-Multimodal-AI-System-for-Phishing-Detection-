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
    Verify JWT token from Supabase and get user role
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
            user_id = user_data.get("id")
            user_email = user_data.get("email")
            
            # Get user role from database
            role = "user"  # default role
            try:
                if supabase:
                    profile_response = supabase.table("user_profiles").select("role").eq("id", user_id).execute()
                    if profile_response.data and len(profile_response.data) > 0:
                        role = profile_response.data[0].get("role", "user")
            except Exception as e:
                print(f"Error fetching user role: {e}")
                # If profile doesn't exist, create it with default role
                try:
                    if supabase:
                        supabase.table("user_profiles").insert({
                            "id": user_id,
                            "email": user_email,
                            "role": "user"
                        }).execute()
                except Exception as e2:
                    print(f"Error creating user profile: {e2}")
            
            return {
                "id": user_id,
                "email": user_email,
                "email_verified": user_data.get("email_confirmed_at") is not None,
                "role": role,
            }
        else:
            print(f"Token verification failed: HTTP {response.status_code}")
            return None
    except Exception as e:
        print(f"Token verification failed: {e}")
        return None


def require_auth(f):
    """
    Decorator to require authentication for API endpoints and web pages
    Supports both API (Authorization header) and web (session/localStorage via redirect)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import redirect, url_for
        
        # Check for token in Authorization header (API request)
        auth_header = request.headers.get("Authorization", "")
        is_api_request = auth_header.startswith("Bearer ")
        
        if is_api_request:
            # API request - check Authorization header
            token = auth_header.replace("Bearer ", "")
            user = verify_token(token)
            
            if not user:
                return jsonify({"error": "Invalid or expired token", "code": "INVALID_TOKEN"}), 401
            
            # Attach user to request
            request.current_user = user
            return f(*args, **kwargs)
        else:
            # Web page request - check for token in session or query params
            # For now, we'll check if it's a JSON request vs HTML request
            wants_json = request.headers.get("Accept", "").startswith("application/json")
            
            # Try to get token from session (if we add session support) or require client-side redirect
            # For now, return 401 and let client handle redirect
            if wants_json:
                return jsonify({"error": "Authentication required", "code": "UNAUTHORIZED", "redirect": "/login"}), 401
            else:
                # For HTML requests, check if user has token in localStorage (client-side)
                # We can't access localStorage server-side, so we'll return the page
                # and let JavaScript handle auth check
                # Alternatively, we could use cookies/sessions
                # For now, allow the page to load and let client-side JS handle auth
                request.current_user = None  # Will be set by client-side JS if authenticated
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


def require_admin(f):
    """
    Decorator to require admin role for API endpoints
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
        
        # Check if user is admin
        if user.get("role") != "admin":
            return jsonify({"error": "Admin access required", "code": "FORBIDDEN"}), 403
        
        # Attach user to request
        request.current_user = user
        return f(*args, **kwargs)
    
    return decorated_function


def is_admin(user: Dict[str, Any]) -> bool:
    """
    Check if user is an admin
    """
    return user.get("role") == "admin" if user else False


def can_access_resource(user: Dict[str, Any], resource_user_id: str) -> bool:
    """
    Check if user can access a resource (either owner or admin)
    """
    if not user:
        return False
    if is_admin(user):
        return True
    return user.get("id") == resource_user_id

