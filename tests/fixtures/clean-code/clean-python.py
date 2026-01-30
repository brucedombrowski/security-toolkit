#!/usr/bin/env python3
"""
Test Fixture: Clean Python file with no secrets or PII.
This file is used by integration tests to verify no false positives.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class User:
    """User data model with no sensitive data."""

    id: int
    username: str
    email_verified: bool = False

    def __post_init__(self):
        if not self.username:
            raise ValueError("Username cannot be empty")


def get_database_url() -> str:
    """Get database URL from environment variable (safe pattern)."""
    return os.environ.get("DATABASE_URL", "sqlite:///default.db")


def get_api_key() -> Optional[str]:
    """Get API key from environment (safe pattern)."""
    return os.getenv("API_KEY")


def calculate_checksum(data: bytes) -> str:
    """Calculate SHA256 checksum of data."""
    import hashlib
    return hashlib.sha256(data).hexdigest()


def format_phone_display(country_code: str, number: str) -> str:
    """Format phone number for display (no real numbers)."""
    return f"+{country_code} {number[:3]}-{number[3:6]}-{number[6:]}"


def validate_email_format(email: str) -> bool:
    """Validate email format (pattern only, not real emails)."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


class ConfigManager:
    """Configuration manager using environment variables."""

    def __init__(self):
        self.debug = os.getenv("DEBUG", "false").lower() == "true"
        self.log_level = os.getenv("LOG_LEVEL", "INFO")

    def get_secret(self, name: str) -> Optional[str]:
        """Retrieve secret from environment (safe pattern)."""
        return os.environ.get(name)


if __name__ == "__main__":
    user = User(id=1, username="testuser")
    print(f"Created user: {user.username}")
