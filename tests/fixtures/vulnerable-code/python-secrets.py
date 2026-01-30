#!/usr/bin/env python3
"""
Test fixture with intentional secrets for scanner verification.
All secrets use TEST patterns to avoid GitHub push protection.
"""

# AWS credentials (test patterns)
AWSAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
AWSSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# API keys
api_key = "sk1234567890abcdef1234567890abcdef"

# Database connection strings
dbConnectionString = "postgres://admin:MyPassword123@localhost:5432/mydb?sslmode=disable"
mongo_uri = "mongodb://root:password123@mongo.example.com:27017/mydb"

# Generic password
password = "hardcoded_password_123"

# Generic token (not triggering specific provider patterns)
MESSAGING_TOKEN = "token_abcdef1234567890abcdef1234567890"

def get_connection():
    """Function returning connection string - should be detected."""
    password = "secretpass123"
    return f"mysql://user:{password}@localhost/db"

if __name__ == "__main__":
    print("This is a test fixture with intentional secrets")
