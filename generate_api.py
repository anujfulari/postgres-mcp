from src.postgres_mcp.auth import generate_api_key
api_key = generate_api_key()
print(f"API Key: {api_key}")