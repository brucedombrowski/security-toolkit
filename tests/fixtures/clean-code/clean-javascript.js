/**
 * Test Fixture: Clean JavaScript file with no secrets or PII.
 * This file is used by integration tests to verify no false positives.
 */

// Safe: Environment variable usage
const API_KEY = process.env.API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;

// Safe: Configuration from external source
const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  logLevel: process.env.LOG_LEVEL || 'info',
};

/**
 * User class with no sensitive data
 */
class User {
  constructor(id, username) {
    this.id = id;
    this.username = username;
    this.createdAt = new Date();
  }

  toJSON() {
    return {
      id: this.id,
      username: this.username,
      createdAt: this.createdAt.toISOString(),
    };
  }
}

/**
 * Safe: Get secret from environment
 */
function getSecret(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

/**
 * Safe: Validate email format (pattern only)
 */
function isValidEmail(email) {
  const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return pattern.test(email);
}

/**
 * Safe: Format currency without real amounts
 */
function formatCurrency(amount, currency = 'USD') {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency,
  }).format(amount);
}

/**
 * Safe: Calculate hash (no secrets involved)
 */
async function calculateHash(data) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

module.exports = {
  User,
  config,
  getSecret,
  isValidEmail,
  formatCurrency,
  calculateHash,
};
