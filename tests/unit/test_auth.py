"""Tests for the OAuth-based authorization module."""

import os
from unittest.mock import patch

import pytest
from jose import jwt

from postgres_mcp.auth import AuthConfig
from postgres_mcp.auth import AuthError
from postgres_mcp.auth import Authenticator


class TestAuthConfig:
    def test_init_disable_auth(self):
        config = AuthConfig(disable_auth=True)
        assert config.disable_auth is True

    def test_from_env_and_args_disable_auth(self):
        config = AuthConfig.from_env_and_args(
            oauth_issuer_arg=None,
            oauth_audience_arg=None,
            oauth_jwks_url_arg=None,
            disable_auth_arg=True,
        )
        assert config.disable_auth is True

    def test_from_env_and_args_env_vars(self):
        with patch.dict(
            os.environ,
            {
                "OAUTH_ISSUER": "https://issuer.example.com",
                "OAUTH_AUDIENCE": "my-audience",
                "OAUTH_HS256_SECRET": "secret",
            },
            clear=True,
        ):
            config = AuthConfig.from_env_and_args()
            assert config.oauth_issuer == "https://issuer.example.com"
            assert config.oauth_audience == "my-audience"
            assert config.oauth_hs256_secret == "secret"

    def test_from_env_and_args_missing_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(AuthError):
                AuthConfig.from_env_and_args(disable_auth_arg=False)


class TestAuthenticatorHS256:
    def test_validate_authorization_header_when_disabled(self):
        config = AuthConfig(disable_auth=True)
        auth = Authenticator(config)
        assert auth.validate_authorization_header("Bearer anything") is True
        assert auth.validate_authorization_header(None) is True

    def test_hs256_success(self):
        secret = "super-secret"
        config = AuthConfig(
            oauth_issuer="iss",
            oauth_audience="aud",
            oauth_hs256_secret=secret,
            oauth_algorithms=["HS256"],
        )
        auth = Authenticator(config)
        token = jwt.encode({"iss": "iss", "aud": "aud"}, secret, algorithm="HS256")
        assert auth.validate_authorization_header(f"Bearer {token}") is True

    def test_hs256_wrong_audience(self):
        secret = "super-secret"
        config = AuthConfig(
            oauth_issuer="iss",
            oauth_audience="aud",
            oauth_hs256_secret=secret,
            oauth_algorithms=["HS256"],
        )
        auth = Authenticator(config)
        token = jwt.encode({"iss": "iss", "aud": "other"}, secret, algorithm="HS256")
        assert auth.validate_authorization_header(f"Bearer {token}") is False

    def test_hs256_without_issuer_config(self):
        secret = "super-secret"
        # No issuer configured; should not verify iss claim
        config = AuthConfig(
            oauth_issuer=None,
            oauth_audience="aud",
            oauth_hs256_secret=secret,
            oauth_algorithms=["HS256"],
        )
        auth = Authenticator(config)
        # Token missing iss should still validate if audience matches
        token = jwt.encode({"aud": "aud"}, secret, algorithm="HS256")
        assert auth.validate_authorization_header(f"Bearer {token}") is True
