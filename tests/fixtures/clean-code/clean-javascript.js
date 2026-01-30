/**
 * Clean code fixture - should NOT trigger secret detection.
 * Uses environment variables and safe patterns.
 */

// Safe: Environment variables
const API_KEY = process.env.API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;
const SECRET_KEY = process.env.SECRET_KEY;

// Safe: Placeholder patterns
const config = {
  apiKey: "${API_KEY}",
  secret: "YOUR_SECRET_HERE",
  password: "<password>",
  token: "{{TOKEN}}"
};

// Safe: Environment-based configuration
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID
};

// Safe: Configuration loader
function loadConfig() {
  return {
    stripeKey: process.env.STRIPE_SECRET_KEY,
    sendgridKey: process.env.SENDGRID_API_KEY,
    twilioSid: process.env.TWILIO_ACCOUNT_SID
  };
}

// Safe: Empty/null values
const emptyCredentials = {
  password: "",
  token: null,
  key: undefined
};

// Safe: Documentation examples
/**
 * Usage:
 *   API_KEY=your_key_here node app.js
 *   export DATABASE_URL=postgres://user:pass@host/db
 */

module.exports = { config, loadConfig };
