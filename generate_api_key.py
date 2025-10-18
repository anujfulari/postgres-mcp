#!/usr/bin/env python3
"""Generate a secure API key for PostgreSQL MCP Server authentication."""

import sys
import os

# Add the src directory to the path so we can import the auth module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from postgres_mcp.auth import generate_api_key
    print("🔐 PostgreSQL MCP Server - API Key Generator")
    print("=" * 50)
    
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
    
except ImportError as e:
    print("❌ Error: Could not import auth module")
    print(f"   {e}")
    print()
    print("💡 Alternative: Generate key manually with Python:")
    print("   import secrets")
    print("   print(secrets.token_urlsafe(32))")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error generating API key: {e}")
    sys.exit(1)
