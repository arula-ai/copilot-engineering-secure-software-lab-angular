/**
 * Production Environment Configuration
 *
 * NOTE: Even in production builds, any values here are exposed
 * in the client-side bundle. Only include PUBLIC configuration.
 */

export const environment = {
  production: true,

  // ONLY public, non-sensitive values should go here
  apiUrl: '/api', // Relative URL for production

  // Public keys are okay (used for encryption, not secrets)
  // stripePublicKey: 'pk_live_...',

  // Feature flags (non-sensitive)
  enableAnalytics: true,
  enableErrorReporting: true,
};

/**
 * SECURE PATTERN:
 *
 * Sensitive configuration should be:
 * 1. Stored on the backend
 * 2. Fetched at runtime (after authentication)
 * 3. Never bundled into the frontend
 *
 * Example:
 *   // After login, fetch config from authenticated endpoint
 *   this.http.get('/api/config').subscribe(config => {
 *     this.apiKey = config.apiKey; // Only accessible to logged-in users
 *   });
 */
