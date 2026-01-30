#!/usr/bin/env python3
"""
Test Fixture: Python file with intentional secrets for scanner detection.
This file is used by integration tests to verify secret detection.
DO NOT use these credentials - they are fake test data.
"""

import os
import boto3

# Hardcoded AWS credentials (should be detected)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# API keys (should be detected - using obvious test patterns)
STRIPE_API_KEY = "sk_test_TESTKEY1234567890abcdefghij"
GITHUB_TOKEN = "ghp_TESTTOKEN00000000000000000000000000"
# Note: Slack token pattern removed to avoid GitHub push protection
# Using generic token pattern instead
MESSAGING_TOKEN = "token_abcdef1234567890abcdef1234567890"

# Database connection with embedded password (should be detected)
DATABASE_URL = "postgresql://admin:SuperSecret123!@db.example.com:5432/production"
MONGODB_URI = "mongodb://root:password123@mongo.example.com:27017/mydb"

# Private key (should be detected)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MaXZVz...
-----END RSA PRIVATE KEY-----"""

# JWT secret (should be detected)
JWT_SECRET = "my-super-secret-jwt-key-that-should-not-be-hardcoded"

def connect_to_database():
    # Inline password (should be detected)
    password = "hardcoded_password_123"
    return f"mysql://user:{password}@localhost/db"

def get_api_client():
    # Another API key pattern
    api_key = "api_key_1234567890abcdef1234567890abcdef"
    return {"Authorization": f"Bearer {api_key}"}
