/**
 * Test Fixture: JavaScript file with intentional secrets for scanner detection.
 * This file is used by integration tests to verify secret detection.
 * DO NOT use these credentials - they are fake test data.
 */

// Firebase config with API key (should be detected - test pattern)
const firebaseConfig = {
  apiKey: "AIzaTESTKEY0000000000000000000000000",
  authDomain: "myapp.firebaseapp.com",
  projectId: "myapp-12345",
  storageBucket: "myapp.appspot.com",
};

// Stripe publishable key (should be detected - test pattern)
const STRIPE_KEY = "pk_test_TESTKEY000000000000000000";

// SendGrid API key (should be detected - test pattern)
const SENDGRID_API_KEY = "SG.TESTKEY00000000000000.TEST00000000000000000000000000000000000000";

// Twilio credentials (should be detected - using test patterns)
const TWILIO_ACCOUNT_SID = "ACTEST00000000000000000000000000";
const TWILIO_AUTH_TOKEN = "auth_token_TEST0000000000000000";

// Database connection string (should be detected)
const mongoConnection = "mongodb+srv://user:MyP@ssw0rd!@cluster.mongodb.net/test";

// OAuth client secret (should be detected - test pattern)
const GOOGLE_CLIENT_SECRET = "GOCSPX-TESTSECRET0000000000000";

// Hardcoded password in code (should be detected)
function authenticate(username) {
  const password = "admin123!@#";
  return login(username, password);
}

// API endpoint with embedded token (should be detected)
const apiEndpoint = "https://api.example.com/v1/data?token=secret_token_12345";

// Private key in JS (should be detected)
const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...
-----END PRIVATE KEY-----`;

module.exports = { firebaseConfig, STRIPE_KEY };
