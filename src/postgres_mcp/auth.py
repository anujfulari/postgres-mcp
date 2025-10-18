"""Authorization module for PostgreSQL MCP Server.

This module provides authentication for the MCP server.
It supports:
- API key-based authentication (default)
- Optional Google OAuth (OIDC) ID token verification when configured

API key validation is synchronous and timing-attack resistant.
OIDC token validation uses Google's JWKS and requires network access.
"""

import hashlib
import hmac
import logging
import os
import secrets
import time
from typing import Optional, Any

import jwt  # pyjwt  # type: ignore[import-not-found]
import httpx

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Raised when authentication fails."""

    pass


class AuthConfig:
    """Configuration for authentication."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        disable_auth: bool = False,
        google_client_id: Optional[str] = None,
        google_oidc_config_url: str = "https://accounts.google.com/.well-known/openid-configuration",
        workspace_domain: Optional[str] = None,
    ):
        """Initialize authentication configuration.

        Args:
            api_key: The API key to use for authentication
            disable_auth: Whether to disable authentication (for testing/development)
            google_client_id: Google OAuth Client ID to enable OIDC verification
            google_oidc_config_url: OIDC discovery URL for the identity provider
            workspace_domain: Optional Google Workspace domain restriction (claims.hd)
        """
        self.api_key = api_key
        self.disable_auth = disable_auth
        self.google_client_id = google_client_id
        self.google_oidc_config_url = google_oidc_config_url
        self.workspace_domain = workspace_domain

    @classmethod
    def from_env_and_args(
        cls,
        api_key_arg: Optional[str] = None,
        disable_auth_arg: bool = False,
    ) -> "AuthConfig":
        """Create AuthConfig from environment variables and command line arguments.

        Args:
            api_key_arg: API key from command line argument
            disable_auth_arg: Disable auth flag from command line

        Returns:
            AuthConfig instance

        Raises:
            AuthError: If no API key is provided and auth is not disabled
        """
        # Priority: command line > environment variable
        api_key = api_key_arg or os.environ.get("MCP_API_KEY")
        disable_auth = disable_auth_arg

        # OAuth-related env vars
        google_client_id = os.environ.get("GOOGLE_CLIENT_ID")
        google_oidc_config_url = os.environ.get(
            "GOOGLE_OIDC",
            "https://accounts.google.com/.well-known/openid-configuration",
        )
        workspace_domain = os.environ.get("WORKSPACE_DOMAIN")

        if not api_key and not disable_auth and not google_client_id:
            raise AuthError(
                "Authentication is required. Please provide either: \n"
                "  - API key via --api-key or MCP_API_KEY env var, or\n"
                "  - Google OAuth by setting GOOGLE_CLIENT_ID (and optional GOOGLE_OIDC, WORKSPACE_DOMAIN), or\n"
                "  - Disable auth with --disable-auth (NOT recommended)."
            )

        if disable_auth:
            logger.warning("Authentication is DISABLED. This is not recommended for production use.")

        if google_client_id:
            logger.info("Google OAuth (OIDC) verification enabled via GOOGLE_CLIENT_ID")

        return cls(
            api_key=api_key,
            disable_auth=disable_auth,
            google_client_id=google_client_id,
            google_oidc_config_url=google_oidc_config_url,
            workspace_domain=workspace_domain,
        )


def generate_api_key(length: int = 32) -> str:
    """Generate a secure random API key.

    Args:
        length: Length of the API key in bytes (default: 32)

    Returns:
        Base64-encoded API key
    """
    return secrets.token_urlsafe(length)


def secure_compare(a: str, b: str) -> bool:
    """Securely compare two strings to prevent timing attacks.

    Args:
        a: First string to compare
        b: Second string to compare

    Returns:
        True if strings are equal, False otherwise
    """
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


class Authenticator:
    """Handles API key authentication."""

    def __init__(self, config: AuthConfig):
        """Initialize the authenticator.

        Args:
            config: Authentication configuration
        """
        self.config = config
        self._jwks_cache: dict[str, object] = {}
        self._jwks_fetched_at: float = 0.0
        self._jwks_cache_ttl_seconds: int = 3600

    def is_authenticated(self, provided_key: Optional[str]) -> bool:
        """Check if the provided API key is valid.

        Args:
            provided_key: The API key provided by the client

        Returns:
            True if authentication is successful or disabled, False otherwise
        """
        if self.config.disable_auth:
            return True

        if not provided_key:
            logger.warning("Authentication failed: No API key provided")
            return False

        if not self.config.api_key:
            logger.error("Authentication failed: No API key configured")
            return False

        is_valid = secure_compare(provided_key, self.config.api_key)
        if not is_valid:
            logger.warning("Authentication failed: Invalid API key provided")

        return is_valid

    async def _get_google_jwks(self) -> dict[str, Any]:
        """Fetch and cache JWKS from the configured OIDC discovery document."""
        now = time.time()
        if self._jwks_cache and (now - self._jwks_fetched_at) < self._jwks_cache_ttl_seconds:
            return self._jwks_cache["jwks"]  # type: ignore[index]

        oidc_url = self.config.google_oidc_config_url
        async with httpx.AsyncClient() as client:
            oidc = (await client.get(oidc_url)).json()
            jwks_uri = oidc["jwks_uri"]
            jwks = (await client.get(jwks_uri)).json()

        self._jwks_cache = {"jwks_uri": jwks_uri, "jwks": jwks}
        self._jwks_fetched_at = now
        return jwks

    def _verify_google_id_token(self, id_token: str, jwks: dict[str, Any]) -> bool:
        """Verify a Google ID token using JWKS and configured client ID/domain."""
        try:
            header = jwt.get_unverified_header(id_token)
            key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])  # type: ignore[index]
            claims = jwt.decode(
                id_token,
                jwt.algorithms.RSAAlgorithm.from_jwk(key),
                algorithms=["RS256"],
                audience=self.config.google_client_id,
                issuer=["https://accounts.google.com", "accounts.google.com"],
            )
            workspace_domain = self.config.workspace_domain
            if workspace_domain and claims.get("hd") != workspace_domain:  # type: ignore[union-attr]
                logger.warning("OIDC token rejected: hd claim does not match WORKSPACE_DOMAIN")
                return False
            return True
        except Exception as exc:
            logger.warning(f"OIDC token verification failed: {exc}")
            return False

    def validate_authorization_header(self, auth_header: Optional[str]) -> bool:
        """Validate Authorization header for HTTP requests.

        Args:
            auth_header: The Authorization header value

        Returns:
            True if authentication is successful, False otherwise
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

        # If Google OAuth is configured, accept a valid Google ID token
        if self.config.google_client_id:
            # Best-effort synchronous heuristic: quickly accept JWT-looking tokens and let async path do network
            if token.count(".") == 2:
                # We cannot verify JWKS synchronously here; fall back to False so async path can run
                return False

        # Fallback to API key validation
        return self.is_authenticated(token)

    def get_auth_required_message(self) -> str:
        """Get the message to display when authentication is required.

        Returns:
            Error message for missing authentication
        """
        return (
            "Authentication required. Please provide a valid API key via:\n"
            "  - Authorization header: 'Bearer <api-key>'\n"
            "  - Or set MCP_API_KEY environment variable\n"
            "Alternatively, configure Google OAuth by setting GOOGLE_CLIENT_ID and send a Google ID token."
        )

    async def validate_authorization_header_async(self, auth_header: Optional[str]) -> bool:
        """Async validation supporting both API key and Google OIDC ID tokens."""
        if self.config.disable_auth:
            return True

        if not auth_header or not auth_header.startswith("Bearer "):
            return False

        token = auth_header[7:]

        # Try Google OIDC first when configured
        if self.config.google_client_id and token.count(".") == 2:
            try:
                jwks = await self._get_google_jwks()
                if self._verify_google_id_token(token, jwks):
                    return True
            except Exception as exc:
                logger.warning(f"Error during OIDC verification: {exc}")

        # Fallback to API key validation
        return self.is_authenticated(token)
