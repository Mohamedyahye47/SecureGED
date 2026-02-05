"""
documents.oauth

Google OAuth 2.0 + OpenID Connect
- PKCE enforced
- CSRF protection via state
- Stateless helper (no business logic here)
"""

import base64
import hashlib
import secrets
import requests
from django.conf import settings


class GoogleOAuthManager:
    GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
    GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

    # ----------------------------
    # STEP 1 — Redirect to Google
    # ----------------------------
    @staticmethod
    def get_authorization_url(request) -> str:
        # PKCE: code_verifier
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode("utf-8").rstrip("=")

        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode("utf-8").rstrip("=")

        # CSRF protection
        state = secrets.token_urlsafe(32)

        # Store in session
        request.session["oauth_code_verifier"] = code_verifier
        request.session["oauth_state"] = state

        params = {
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "redirect_uri": settings.GOOGLE_OAUTH_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "consent",
        }

        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{GoogleOAuthManager.GOOGLE_AUTH_URL}?{query}"

    # ----------------------------
    # STEP 2 — Exchange code
    # ----------------------------
    @staticmethod
    def exchange_code_for_token(request, code: str) -> dict:
        code_verifier = request.session.get("oauth_code_verifier")
        state_sent = request.session.get("oauth_state")
        state_returned = request.GET.get("state")

        # CSRF check
        if not state_sent or state_sent != state_returned:
            return {"error": "OAuth state invalide (CSRF détecté)."}

        if not code_verifier:
            return {"error": "PKCE verifier manquant (session expirée)."}

        data = {
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": settings.GOOGLE_OAUTH_REDIRECT_URI,
            "code_verifier": code_verifier,
        }

        try:
            response = requests.post(
                GoogleOAuthManager.GOOGLE_TOKEN_URL,
                data=data,
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": f"Token exchange failed: {e}"}

    # ----------------------------
    # STEP 3 — Get user info
    # ----------------------------
    @staticmethod
    def get_user_info(access_token: str) -> dict:
        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        try:
            response = requests.get(
                GoogleOAuthManager.GOOGLE_USERINFO_URL,
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": f"Userinfo fetch failed: {e}"}
