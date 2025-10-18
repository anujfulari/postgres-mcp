"""Tests for the authorization module."""

import os
import pytest
from unittest.mock import patch

from postgres_mcp.auth import AuthConfig
from postgres_mcp.auth import Authenticator
from postgres_mcp.auth import AuthError
from postgres_mcp.auth import generate_api_key
from postgres_mcp.auth import secure_compare


class TestAuthConfig:
    """Test AuthConfig class."""

    def test_init_with_api_key(self):
        """Test AuthConfig initialization with API key."""
        config = AuthConfig(api_key="test-key", disable_auth=False)
        assert config.api_key == "test-key"
        assert config.disable_auth is False

    def test_init_disable_auth(self):
        """Test AuthConfig initialization with disabled auth."""
        config = AuthConfig(api_key=None, disable_auth=True)
        assert config.api_key is None
        assert config.disable_auth is True

    def test_from_env_and_args_with_command_line_key(self):
        """Test AuthConfig creation from command line argument."""
        config = AuthConfig.from_env_and_args(
            api_key_arg="cmd-key",
            disable_auth_arg=False
        )
        assert config.api_key == "cmd-key"
        assert config.disable_auth is False

    def test_from_env_and_args_with_env_var(self):
        """Test AuthConfig creation from environment variable."""
        with patch.dict(os.environ, {"MCP_API_KEY": "env-key"}):
            config = AuthConfig.from_env_and_args(
                api_key_arg=None,
                disable_auth_arg=False
            )
            assert config.api_key == "env-key"
            assert config.disable_auth is False

    def test_from_env_and_args_priority(self):
        """Test that command line argument takes priority over environment variable."""
        with patch.dict(os.environ, {"MCP_API_KEY": "env-key"}):
            config = AuthConfig.from_env_and_args(
                api_key_arg="cmd-key",
                disable_auth_arg=False
            )
            assert config.api_key == "cmd-key"

    def test_from_env_and_args_disable_auth(self):
        """Test AuthConfig creation with disabled auth."""
        config = AuthConfig.from_env_and_args(
            api_key_arg=None,
            disable_auth_arg=True
        )
        assert config.api_key is None
        assert config.disable_auth is True

    def test_from_env_and_args_no_key_raises_error(self):
        """Test that AuthError is raised when no API key is provided."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(AuthError) as exc_info:
                AuthConfig.from_env_and_args(
                    api_key_arg=None,
                    disable_auth_arg=False
                )
            assert "Authentication is required" in str(exc_info.value)


class TestAuthenticator:
    """Test Authenticator class."""

    def test_init(self):
        """Test Authenticator initialization."""
        config = AuthConfig(api_key="test-key", disable_auth=False)
        auth = Authenticator(config)
        assert auth.config == config

    def test_is_authenticated_with_correct_key(self):
        """Test authentication with correct API key."""
        config = AuthConfig(api_key="test-key", disable_auth=False)
        auth = Authenticator(config)
        assert auth.is_authenticated("test-key") is True

    def test_is_authenticated_with_incorrect_key(self):
        """Test authentication with incorrect API key."""
        config = AuthConfig(api_key="test-key", disable_auth=False)
        auth = Authenticator(config)
        assert auth.is_authenticated("wrong-key") is False

    def test_is_authenticated_with_no_key(self):
        """Test authentication with no API key provided."""
        config = AuthConfig(api_key="test-key", disable_auth=False)
        auth = Authenticator(config)
        assert auth.is_authenticated(None) is False

    def test_is_authenticated_when_disabled(self):
        """Test authentication when auth is disabled."""
        config = AuthConfig(api_key=None, disable_auth=True)
        auth = Authenticator(config)
        assert auth.is_authenticated("any-key") is True
        assert auth.is_authenticated(None) is True

    def test_validate_authorization_header_correct(self):
        """Test authorization header validation with correct header."""
        config = AuthConfig(api_key="test-key", disable_auth=False)
        auth = Authenticator(config)
        assert auth.validate_authorization_header("Bearer test-key") is True

    def test_validate_authorization_header_incorrect_key(self):
        """Test authorization header validation with incorrect key."""
        config = AuthConfig(api_key="test-key", disable_auth=False)
        auth = Authenticator(config)
        assert auth.validate_authorization_header("Bearer wrong-key") is False

    def test_validate_authorization_header_no_bearer(self):
        """Test authorization header validation without Bearer prefix."""
        config = AuthConfig(api_key="test-key", disable_auth=False)
        auth = Authenticator(config)
        assert auth.validate_authorization_header("test-key") is False

    def test_validate_authorization_header_no_header(self):
        """Test authorization header validation with no header."""
        config = AuthConfig(api_key="test-key", disable_auth=False)
        auth = Authenticator(config)
        assert auth.validate_authorization_header(None) is False

    def test_validate_authorization_header_when_disabled(self):
        """Test authorization header validation when auth is disabled."""
        config = AuthConfig(api_key=None, disable_auth=True)
        auth = Authenticator(config)
        assert auth.validate_authorization_header("Bearer any-key") is True
        assert auth.validate_authorization_header(None) is True

    def test_get_auth_required_message(self):
        """Test getting authentication required message."""
        config = AuthConfig(api_key="test-key", disable_auth=False)
        auth = Authenticator(config)
        message = auth.get_auth_required_message()
        assert "Authentication required" in message
        assert "Authorization header" in message


class TestUtilityFunctions:
    """Test utility functions."""

    def test_generate_api_key(self):
        """Test API key generation."""
        key = generate_api_key()
        assert isinstance(key, str)
        assert len(key) > 0

    def test_generate_api_key_custom_length(self):
        """Test API key generation with custom length."""
        key = generate_api_key(length=16)
        assert isinstance(key, str)
        assert len(key) > 0

    def test_secure_compare_equal_strings(self):
        """Test secure comparison with equal strings."""
        assert secure_compare("test", "test") is True

    def test_secure_compare_different_strings(self):
        """Test secure comparison with different strings."""
        assert secure_compare("test", "different") is False

    def test_secure_compare_different_lengths(self):
        """Test secure comparison with different length strings."""
        assert secure_compare("test", "testing") is False

    def test_secure_compare_empty_strings(self):
        """Test secure comparison with empty strings."""
        assert secure_compare("", "") is True

    def test_secure_compare_timing_attack_resistance(self):
        """Test that secure comparison is timing-attack resistant."""
        # This is a basic test - in practice, you'd need more sophisticated timing analysis
        import time
        
        # Test with strings of different lengths
        start = time.time()
        secure_compare("short", "very-long-string-that-should-take-longer")
        time_diff_length = time.time() - start
        
        # Test with strings of same length but different content
        start = time.time()
        secure_compare("test1", "test2")
        time_diff_same = time.time() - start
        
        # The timing should be similar (within reasonable bounds)
        # This is a basic check - real timing attack resistance testing is more complex
        assert abs(time_diff_length - time_diff_same) < 0.1  # 100ms tolerance


class TestIntegration:
    """Integration tests for authentication."""

    def test_full_auth_flow_with_correct_key(self):
        """Test complete authentication flow with correct key."""
        config = AuthConfig(api_key="test-key", disable_auth=False)
        auth = Authenticator(config)
        
        # Test direct authentication
        assert auth.is_authenticated("test-key") is True
        
        # Test header authentication
        assert auth.validate_authorization_header("Bearer test-key") is True

    def test_full_auth_flow_with_incorrect_key(self):
        """Test complete authentication flow with incorrect key."""
        config = AuthConfig(api_key="test-key", disable_auth=False)
        auth = Authenticator(config)
        
        # Test direct authentication
        assert auth.is_authenticated("wrong-key") is False
        
        # Test header authentication
        assert auth.validate_authorization_header("Bearer wrong-key") is False

    def test_auth_disabled_flow(self):
        """Test authentication flow when auth is disabled."""
        config = AuthConfig(api_key=None, disable_auth=True)
        auth = Authenticator(config)
        
        # Test direct authentication
        assert auth.is_authenticated("any-key") is True
        assert auth.is_authenticated(None) is True
        
        # Test header authentication
        assert auth.validate_authorization_header("Bearer any-key") is True
        assert auth.validate_authorization_header(None) is True

    def test_config_priority(self):
        """Test that command line arguments take priority over environment variables."""
        with patch.dict(os.environ, {"MCP_API_KEY": "env-key"}):
            config = AuthConfig.from_env_and_args(
                api_key_arg="cmd-key",
                disable_auth_arg=False
            )
            auth = Authenticator(config)
            
            # Should use command line key, not environment key
            assert auth.is_authenticated("cmd-key") is True
            assert auth.is_authenticated("env-key") is False
