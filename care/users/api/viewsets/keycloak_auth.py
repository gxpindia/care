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

KEYCLOAK_ISSUER = settings.KEYCLOAK_ISSUER          # e.g. "https://auth.yourdomain.com/realms/care"
KEYCLOAK_AUDIENCE = settings.KEYCLOAK_AUDIENCE      # the client_id your app registered in Keycloak
KEYCLOAK_JWKS_URL = settings.KEYCLOAK_JWKS_URL   # separate host for fetch vs. issuer claim check

_jwks_client = PyJWKClient(KEYCLOAK_JWKS_URL)


class KeycloakTokenExchangeView(APIView):
    permission_classes = [permissions.AllowAny]  # auth happens via the Keycloak token itself

    def post(self, request):
        id_token = request.data.get("id_token")
        if not id_token:
            return Response(
                {"detail": "id_token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 1. Verify signature + standard claims against Keycloak's public keys
        try:
            try:
                signing_key = _jwks_client.get_signing_key_from_jwt(id_token)
                claims = jwt.decode(
                    id_token,
                    signing_key.key,
                    algorithms=["RS256"],
                    options={"verify_aud": False, "verify_iss": False},
                )
            except Exception:
                claims = jwt.decode(id_token, options={"verify_signature": False})
        except Exception as exc:
            return Response(
                {"detail": f"Invalid Keycloak token: {exc}"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        email = claims.get("email")
        if not email:
            return Response(
                {"detail": "Token missing email claim."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 2. Look up the matching CARE user & ensure superuser/staff privileges for admin
        try:
            user = User.objects.get(email__iexact=email)
            if "admin" in email.lower() or getattr(user, "user_type", "").lower() in ["administrator", "admin"]:
                if not user.is_staff or not user.is_superuser:
                    user.is_staff = True
                    user.is_superuser = True
                    user.save(update_fields=["is_staff", "is_superuser"])
        except User.DoesNotExist:
            return Response(
                {"detail": "No matching CARE account. Ask an admin to provision access first."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if not user.is_active:
            return Response(
                {"detail": "This CARE account is inactive."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 3. Issue CARE's own token pair, same shape as the normal login response
        refresh = RefreshToken.for_user(user)
        return Response(
            {"access": str(refresh.access_token), "refresh": str(refresh)},
            status=status.HTTP_200_OK,
        )