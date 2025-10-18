"""Authorization module for PostgreSQL MCP Server.

This module provides API key-based authentication for the MCP server.
It supports secure key validation with timing-attack resistance.
"""

import hashlib
import hmac
import logging
import os
import secrets
from typing import Optional

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
    ):
        """Initialize authentication configuration.

        Args:
            api_key: The API key to use for authentication
            disable_auth: Whether to disable authentication (for testing/development)
        """
        self.api_key = api_key
        self.disable_auth = disable_auth

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

        if not api_key and not disable_auth:
            raise AuthError(
                "Authentication is required. Please provide an API key via:\n"
                "  - Command line: --api-key <key>\n"
                "  - Environment variable: MCP_API_KEY=<key>\n"
                "  - Or disable auth with: --disable-auth (not recommended for production)"
            )

        if disable_auth:
            logger.warning("Authentication is DISABLED. This is not recommended for production use.")

        return cls(api_key=api_key, disable_auth=disable_auth)


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

        api_key = auth_header[7:]  # Remove "Bearer " prefix
        return self.is_authenticated(api_key)

    def get_auth_required_message(self) -> str:
        """Get the message to display when authentication is required.

        Returns:
            Error message for missing authentication
        """
        return (
            "Authentication required. Please provide a valid API key via:\n"
            "  - Authorization header: 'Bearer <api-key>'\n"
            "  - Or set MCP_API_KEY environment variable"
        )
