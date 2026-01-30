/**
 * Test fixture with intentional secrets for scanner verification.
 * All secrets use TEST patterns to avoid GitHub push protection.
 */

// Firebase-style config (with test values)
const firebaseConfig = {
  apiKey: "TEST_firebase_api_key_1234567890abcdef",
  authDomain: "test-app.firebaseapp.com",
  databaseURL: "https://test-app.firebaseio.com"
};

// Stripe-style test key
const STRIPE_KEY = "sk_test_TESTKEY1234567890abcdefghij";

// SendGrid-style test key
const SENDGRID_KEY = "SG.TESTtestTEST1234567890abcdefghij.testkey1234";

// Twilio-style test values
const twilioConfig = {
  accountSid: "ACTEST1234567890abcdef1234567890",
  authToken: "test_auth_token_1234567890abcdef"
};

// Hardcoded password
const password = "admin123!@#";

// Database URL with credentials
const dbUrl = "postgresql://admin:password123@db.example.com:5432/myapp";

module.exports = { firebaseConfig, STRIPE_KEY, SENDGRID_KEY, twilioConfig };
