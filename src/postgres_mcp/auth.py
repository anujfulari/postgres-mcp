"""OAuth2/JWT authentication for PostgreSQL MCP Server.

This module validates OAuth2 Bearer tokens (JWT) using either a JWKS URL
for asymmetric algorithms (e.g., RS256) or a configured HS256 secret for
testing and simple setups.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set

import requests
from jose import jwk
from jose import jwt

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Raised when authentication configuration or validation fails."""

    pass


class AuthConfig:
    """Configuration for OAuth2 authentication."""

    def __init__(
        self,
        oauth_issuer: Optional[str] = None,
        oauth_audience: Optional[str] = None,
        oauth_jwks_url: Optional[str] = None,
        oauth_algorithms: Optional[List[str]] = None,
        oauth_required_scopes: Optional[Set[str]] = None,
        oauth_hs256_secret: Optional[str] = None,
        disable_auth: bool = False,
    ) -> None:
        self.oauth_issuer = oauth_issuer
        self.oauth_audience = oauth_audience
        self.oauth_jwks_url = oauth_jwks_url
        self.oauth_algorithms = oauth_algorithms or ["RS256", "HS256"]
        self.oauth_required_scopes = oauth_required_scopes or set()
        self.oauth_hs256_secret = oauth_hs256_secret
        self.disable_auth = disable_auth

    @classmethod
    def from_env_and_args(
        cls,
        oauth_issuer_arg: Optional[str] = None,
        oauth_audience_arg: Optional[str] = None,
        oauth_jwks_url_arg: Optional[str] = None,
        oauth_algorithms_arg: Optional[str] = None,
        oauth_required_scopes_arg: Optional[str] = None,
        oauth_hs256_secret_arg: Optional[str] = None,
        disable_auth_arg: bool = False,
    ) -> "AuthConfig":
        """Create AuthConfig from environment variables and command line arguments.

        Required when auth is enabled: issuer, audience, and either JWKS URL or HS256 secret.
        """
        disable_auth = disable_auth_arg

        issuer = oauth_issuer_arg or os.environ.get("OAUTH_ISSUER")
        audience = oauth_audience_arg or os.environ.get("OAUTH_AUDIENCE")
        jwks_url = oauth_jwks_url_arg or os.environ.get("OAUTH_JWKS_URL")
        algorithms_csv = oauth_algorithms_arg or os.environ.get("OAUTH_ALGORITHMS")
        scopes_csv = oauth_required_scopes_arg or os.environ.get("OAUTH_REQUIRED_SCOPES")
        hs256_secret = oauth_hs256_secret_arg or os.environ.get("OAUTH_HS256_SECRET")

        algorithms = [a.strip() for a in algorithms_csv.split(",")] if isinstance(algorithms_csv, str) else None
        required_scopes = (
            set(s.strip() for s in scopes_csv.split(",") if s.strip()) if isinstance(scopes_csv, str) else None
        )

        # Validate required fields when auth is enabled
        if not disable_auth:
            missing: list[str] = []
            if not (jwks_url or hs256_secret):
                missing.append("OAUTH_JWKS_URL or OAUTH_HS256_SECRET")
            # For JWKS (asymmetric), require both issuer and audience
            if jwks_url:
                if not issuer:
                    missing.append("OAUTH_ISSUER")
                if not audience:
                    missing.append("OAUTH_AUDIENCE")
            # For HS256 (symmetric), issuer is optional but audience recommended
            if hs256_secret and not audience:
                missing.append("OAUTH_AUDIENCE")
            if missing:
                raise AuthError(
                    "Authentication is required. Please configure OAuth via environment vars or CLI options. Missing: "
                    + ", ".join(missing)
                )

        config = cls(
            oauth_issuer=issuer,
            oauth_audience=audience,
            oauth_jwks_url=jwks_url,
            oauth_algorithms=algorithms,
            oauth_required_scopes=required_scopes,
            oauth_hs256_secret=hs256_secret,
            disable_auth=disable_auth,
        )

        if disable_auth:
            logger.warning("Authentication is DISABLED. This is not recommended for production use.")

        return config


class Authenticator:
    """Validates OAuth2 Bearer tokens (JWT)."""

    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self._jwks_cache: Dict[str, Any] = {"keys": None, "fetched_at": 0.0}
        self._jwks_ttl_seconds: int = 300

    def validate_authorization_header(self, auth_header: Optional[str]) -> bool:
        """Validate Authorization header for HTTP requests.

        Returns True if authentication is successful or disabled, False otherwise.
        """
        if self.config.disable_auth:
            return True

        if not auth_header:
            logger.warning("Authentication failed: No Authorization header")
            return False

        if not auth_header.startswith("Bearer "):
            logger.warning("Authentication failed: Invalid Authorization header format")
            return False

        token = auth_header[7:]
        return self._validate_token(token)

    def _validate_token(self, token: str) -> bool:
        try:
            claims = self._decode_jwt(token)
            # Enforce scopes if configured
            if self.config.oauth_required_scopes:
                token_scopes: Set[str] = set()
                scope_claim = claims.get("scope")
                if isinstance(scope_claim, str):
                    token_scopes.update(s for s in scope_claim.split(" ") if s)
                scp_claim = claims.get("scp")
                if isinstance(scp_claim, list):
                    token_scopes.update(str(s) for s in scp_claim)
                missing = self.config.oauth_required_scopes - token_scopes
                if missing:
                    logger.warning(f"Authentication failed: Missing required scopes: {', '.join(sorted(missing))}")
                    return False
            return True
        except Exception as exc:  # noqa: BLE001 - log and treat as auth failure
            logger.warning(f"Authentication failed: {exc}")
            return False

    def _decode_jwt(self, token: str) -> Dict[str, Any]:
        issuer = self.config.oauth_issuer
        audience = self.config.oauth_audience
        algorithms = self.config.oauth_algorithms

        if self.config.oauth_hs256_secret:
            # Symmetric validation path (useful for testing)
            decode_kwargs: Dict[str, Any] = {
                "algorithms": algorithms or ["HS256"],
                "options": {
                    "verify_at_hash": False,
                    "verify_iss": bool(issuer),
                    "verify_aud": bool(audience),
                },
            }
            if audience:
                decode_kwargs["audience"] = audience
            if issuer:
                decode_kwargs["issuer"] = issuer
            return jwt.decode(
                token,
                self.config.oauth_hs256_secret,
                **decode_kwargs,
            )

        # JWKS-based validation
        keys = self._get_jwks_keys()
        if not keys:
            raise AuthError("No JWKS keys available for token validation")

        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        key_data: Optional[Dict[str, Any]] = None
        if kid:
            key_data = next((k for k in keys if k.get("kid") == kid), None)
        if key_data is None and len(keys) == 1:
            key_data = keys[0]
        if key_data is None:
            raise AuthError("Unable to find matching JWK for token")

        constructed = jwk.construct(key_data)
        # Convert constructed key to PEM for jose.jwt.decode
        try:
            key_pem = constructed.to_pem().decode("utf-8")
        except Exception:
            # Fallback: pass raw JWK; python-jose can handle some JWK dicts directly
            key_pem = key_data  # type: ignore[assignment]

        decode_kwargs_jwks: Dict[str, Any] = {
            "algorithms": algorithms or ["RS256"],
            "options": {
                "verify_at_hash": False,
                "verify_iss": bool(issuer),
                "verify_aud": bool(audience),
            },
        }
        if audience:
            decode_kwargs_jwks["audience"] = audience
        if issuer:
            decode_kwargs_jwks["issuer"] = issuer

        return jwt.decode(
            token,
            key_pem,  # type: ignore[arg-type]
            **decode_kwargs_jwks,
        )

    def _get_jwks_keys(self) -> List[Dict[str, Any]]:
        if not self.config.oauth_jwks_url:
            return []
        now = time.time()
        if self._jwks_cache["keys"] and (now - float(self._jwks_cache["fetched_at"])) < self._jwks_ttl_seconds:
            return self._jwks_cache["keys"]  # type: ignore[return-value]

        resp = requests.get(self.config.oauth_jwks_url, timeout=5)
        resp.raise_for_status()
        jwks = resp.json()
        keys = jwks.get("keys") or []
        if not isinstance(keys, list):
            raise AuthError("Invalid JWKS payload: 'keys' must be a list")
        self._jwks_cache = {"keys": keys, "fetched_at": now}
        return keys

    def get_auth_required_message(self) -> str:
        return (
            "Authentication required. Provide a valid OAuth2 Bearer token in the Authorization header.\n"
            "  - Header: 'Authorization: Bearer <access-token>'\n"
            "  - Configure with OAUTH_ISSUER, OAUTH_AUDIENCE, and OAUTH_JWKS_URL (or OAUTH_HS256_SECRET)"
        )
