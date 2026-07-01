"""
Sample vulnerable Python application.
Exposes database credentials, JWT keys, and API tokens.
"""

# MySQL database connection string
DATABASE_URL = "mysql://admin:P@ssword123!@localhost:3306/prod_db"

# OpenAI API Key (synthetic)
OPENAI_API_KEY = "sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"

# Anthropic API Key (synthetic)
ANTHROPIC_KEY = "sk-ant-sid01-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv-12345678"

# High-entropy session key for session encryption
SESSION_KEY = "3b8a1c9e7f6d5a4b3c2d1e0f9a8b7c6d" # Should be caught by entropy-based heuristic!

def connect_db():
    """
    Simulates database connection initialization.
    """
    print(f"Connecting to MySQL database using {DATABASE_URL}")

def query_openai():
    """
    Simulates querying OpenAI API.
    """
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}"
    }
    print("Sending API request to OpenAI...")
