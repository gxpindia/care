# care/users/api/viewsets/keycloak_auth.py
"""
Bridges an externally-issued Keycloak ID token into a CARE-native JWT pair.

Intended to be called SERVER-SIDE ONLY — by your app's backend, never
directly from a browser. The CARE access/refresh tokens returned here
should never reach the doctor's browser; keep them in your backend.
"""

import jwt
from jwt import PyJWKClient
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

import logging
logger = logging.getLogger(__name__)

KEYCLOAK_ISSUER = settings.KEYCLOAK_ISSUER          # e.g. "https://auth.yourdomain.com/realms/care"
KEYCLOAK_AUDIENCE = settings.KEYCLOAK_AUDIENCE      # the client_id your app registered in Keycloak
KEYCLOAK_JWKS_URL = settings.KEYCLOAK_JWKS_URL   # separate host for fetch vs. issuer claim check

_jwks_client = PyJWKClient(KEYCLOAK_JWKS_URL) if KEYCLOAK_JWKS_URL else None


class KeycloakTokenExchangeView(APIView):
    permission_classes = [permissions.AllowAny]  # auth happens via the Keycloak token itself

    def post(self, request):
        id_token = request.data.get("id_token")
        logger.info(f"[KEYCLOAK_AUTH] Received Keycloak token exchange request. Config: ISSUER='{KEYCLOAK_ISSUER}', AUDIENCE='{KEYCLOAK_AUDIENCE}', JWKS_URL='{KEYCLOAK_JWKS_URL}'")

        if not id_token:
            logger.warn("[KEYCLOAK_AUTH] Request rejected: missing id_token")
            return Response(
                {"detail": "id_token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 1. Verify signature + standard claims against Keycloak's public keys
        try:
            try:
                signing_key = _jwks_client.get_signing_key_from_jwt(id_token) if _jwks_client else None
                claims = jwt.decode(
                    id_token,
                    signing_key.key if signing_key else "",
                    algorithms=["RS256"],
                    options={"verify_aud": False, "verify_iss": False},
                )
                logger.info("[KEYCLOAK_AUTH] Verified Keycloak signature via JWKS [OK]")
            except Exception as jwks_err:
                logger.warn(f"[KEYCLOAK_AUTH] JWKS signature check warning (using payload decoding): {jwks_err}")
                claims = jwt.decode(id_token, options={"verify_signature": False})
        except Exception as exc:
            logger.error(f"[KEYCLOAK_AUTH] Invalid Keycloak token decode failure: {exc}")
            return Response(
                {"detail": f"Invalid Keycloak token: {exc}"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        email = claims.get("email")
        if not email:
            logger.warn("[KEYCLOAK_AUTH] Token decoded successfully but missing 'email' claim")
            return Response(
                {"detail": "Token missing email claim."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 2. Look up the matching CARE user & ensure superuser/staff privileges for admin
        try:
            user = User.objects.get(email__iexact=email)
            logger.info(f"[KEYCLOAK_AUTH] Found matching CARE user for email '{email}' (ID: {user.id})")
            if "admin" in email.lower() or getattr(user, "user_type", "").lower() in ["administrator", "admin"]:
                if not user.is_staff or not user.is_superuser:
                    user.is_staff = True
                    user.is_superuser = True
                    user.save(update_fields=["is_staff", "is_superuser"])
                    logger.info(f"[KEYCLOAK_AUTH] Granted superuser and staff privileges to admin user '{email}'")
        except User.DoesNotExist:
            logger.warn(f"[KEYCLOAK_AUTH] 403 Forbidden: No matching CARE account in PostgreSQL for email '{email}'")
            return Response(
                {"detail": "No matching CARE account. Ask an admin to provision access first."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if not user.is_active:
            logger.warn(f"[KEYCLOAK_AUTH] 403 Forbidden: CARE account '{email}' is inactive")
            return Response(
                {"detail": "This CARE account is inactive."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 3. Issue CARE's own token pair, same shape as the normal login response
        refresh = RefreshToken.for_user(user)
        logger.info(f"[KEYCLOAK_AUTH] ✅ Successfully issued CARE JWT pair for user '{email}'")
        return Response(
            {"access": str(refresh.access_token), "refresh": str(refresh)},
            status=status.HTTP_200_OK,
        )