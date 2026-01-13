/**
 * VULNERABLE: Environment Configuration
 *
 * Security Issues:
 * - A02: Cryptographic Failures (Sensitive Data Exposure)
 *
 * This file demonstrates INSECURE patterns of storing sensitive data
 * in Angular environment files. These values are bundled into the
 * client-side JavaScript and are accessible to anyone.
 *
 * DO NOT USE REAL CREDENTIALS IN ENVIRONMENT FILES
 */

export const environment = {
  production: false,

  // VULN: API keys bundled into client-side code
  apiKey: 'sk_live_51ABC123DEF456_SUPER_SECRET_DO_NOT_EXPOSE',

  // VULN: Secret keys should NEVER be in frontend code
  secretKey: 'secret_key_abcdef123456_VERY_SENSITIVE',

  // VULN: Database credentials in frontend code (!!)
  databaseUrl: 'mongodb://admin:SuperSecretPassword123@db.production.example.com:27017/myapp',

  // VULN: Third-party service credentials
  stripeSecretKey: 'sk_live_STRIPE_SECRET_NEVER_EXPOSE_THIS',
  twilioAuthToken: 'twilio_auth_token_secret_12345',
  awsSecretKey: 'aws_secret_access_key/ABCDEFGHIJKLMNOP',

  // VULN: Internal service URLs (information disclosure)
  internalApiUrl: 'https://internal-api.company-network.local:8443',
  adminPanelUrl: 'https://admin.company.com/secret-admin',

  // API URL (this one is okay to have)
  apiUrl: 'http://localhost:3001/api',
};

/**
 * WHY THIS IS DANGEROUS:
 *
 * 1. All values in this file are bundled into main.js
 * 2. Anyone can view them in browser DevTools
 * 3. They're indexed by search engines if source maps are exposed
 * 4. Attackers can extract them from the minified bundle
 *
 * WHAT SHOULD GO HERE:
 * - Public API URLs
 * - Feature flags (non-sensitive)
 * - Public keys (for encryption, NOT decryption)
 *
 * WHAT SHOULD NEVER GO HERE:
 * - API secret keys
 * - Database credentials
 * - Private keys
 * - Internal URLs
 * - Anything you wouldn't post publicly
 */
