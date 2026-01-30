#!/usr/bin/env python3
"""
Clean code fixture - should NOT trigger secret detection.
Uses environment variables and safe patterns.
"""

import os

# Safe: Environment variables
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL")

# Safe: Placeholder patterns
API_KEY = "${API_KEY}"
PASSWORD = "${PASSWORD}"
TOKEN = "YOUR_TOKEN_HERE"

# Safe: Configuration file references
config_path = "/etc/myapp/config.yaml"
secrets_file = "~/.config/secrets.json"

# Safe: Variable references
def get_credentials():
    """Get credentials from environment."""
    return {
        "key": os.getenv("API_KEY"),
        "secret": os.getenv("API_SECRET"),
    }

# Safe: Command examples in comments
# Example: export AWS_ACCESS_KEY_ID=your_key_here
# Run: python script.py --password $PASSWORD

class DatabaseConnection:
    """Database connection using environment config."""

    def __init__(self):
        self.host = os.environ.get("DB_HOST", "localhost")
        self.port = os.environ.get("DB_PORT", "5432")
        self.password = os.environ.get("DB_PASSWORD")

if __name__ == "__main__":
    print("This is a clean code fixture")
