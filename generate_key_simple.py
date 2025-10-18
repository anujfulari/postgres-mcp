#!/usr/bin/env python3
"""Simple API key generator for PostgreSQL MCP Server (no dependencies)."""

import secrets

def generate_api_key(length=32):
    """Generate a secure random API key."""
    return secrets.token_urlsafe(length)

if __name__ == "__main__":
    print("🔐 PostgreSQL MCP Server - Simple API Key Generator")
    print("=" * 55)
    
    # Generate a secure API key
    api_key = generate_api_key()
    
    print(f"✅ Generated API Key: {api_key}")
    print()
    print("📋 Usage Instructions:")
    print("1. Set as environment variable:")
    print(f"   export MCP_API_KEY=\"{api_key}\"")
    print()
    print("2. Or use as command line argument:")
    print(f"   postgres-mcp --api-key \"{api_key}\"")
    print()
    print("3. For SSE transport, use in Authorization header:")
    print(f"   Authorization: Bearer {api_key}")
    print()
    print("⚠️  Security Notes:")
    print("- Keep this key secure and don't share it")
    print("- Don't commit it to version control")
    print("- Store it in environment variables for production")
    print("- Generate a new key if compromised")
    print()
    print("🔧 Alternative lengths:")
    print(f"   Short key (16 bytes): {secrets.token_urlsafe(16)}")
    print(f"   Long key (48 bytes):  {secrets.token_urlsafe(48)}")
