import jwt
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth.models import User
import logging

logger = logging.getLogger(__name__)


class JWTService:
    """
    Simple JWT service with sliding expiration.
    - Stateless (no DB storage)
    - One access token
    - Expiration extended on each valid request
    """

    ALGORITHM = "HS256"
    EXPIRATION_MINUTES = 2  # ⏱️ recommandé (1 min = debug seulement)
    LEEWAY_SECONDS = 10      # tolérance horloge

    @staticmethod
    def generate_token(user):
        """Generate a new JWT access token"""
        payload = {
            "type": "access",
            "user_id": user.id,
            "username": user.username,
            "is_staff": user.is_staff,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=JWTService.EXPIRATION_MINUTES),
        }

        token = jwt.encode(
            payload,
            settings.SECRET_KEY,
            algorithm=JWTService.ALGORITHM
        )

        logger.debug(f"JWT generated for user {user.id}")
        return token

    @staticmethod
    def verify_token(token):
        """Verify token and return payload or error"""
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[JWTService.ALGORITHM],
                leeway=JWTService.LEEWAY_SECONDS,
            )

            if payload.get("type") != "access":
                return None, "Invalid token type"

            return payload, None

        except jwt.ExpiredSignatureError:
            return None, "Token expired"
        except jwt.InvalidTokenError:
            return None, "Invalid token"

    @staticmethod
    def get_user_from_token(token):
        """Return user from valid token"""
        payload, error = JWTService.verify_token(token)

        if error:
            return None

        try:
            return User.objects.get(id=payload["user_id"])
        except User.DoesNotExist:
            return None

    @staticmethod
    def verify_and_refresh(token):
        """
        Sliding expiration:
        - If token is valid → issue a new token
        - Return (user, new_token)
        """
        payload, error = JWTService.verify_token(token)

        if error:
            return None, None

        try:
            user = User.objects.get(id=payload["user_id"])
            new_token = JWTService.generate_token(user)
            return user, new_token
        except User.DoesNotExist:
            return None, None
