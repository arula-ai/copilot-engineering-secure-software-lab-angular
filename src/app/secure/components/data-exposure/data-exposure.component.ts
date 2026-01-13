/**
 * SECURE: Sensitive Data Protection
 *
 * Security Controls:
 * - A02: Cryptographic Best Practices
 * - A05: Security Configuration
 *
 * This component demonstrates SECURE patterns for handling sensitive
 * data in Angular applications.
 *
 * SAFE FOR PRODUCTION (with proper server-side implementation)
 */

import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-secure-data-exposure',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="security-demo">
      <div class="header">
        <h2>SECURE: Data Protection</h2>
        <span class="badge success">A02: Data Protection</span>
      </div>

      <div class="description">
        <p>
          This component demonstrates secure patterns for handling sensitive
          data, avoiding exposure through environment files, logging, and storage.
        </p>
      </div>

      <div class="demo-section">
        <h3>Environment Configuration</h3>
        <p class="context">Only public, non-sensitive values in environment files...</p>

        <div class="config-display">
          <h4>Safe Environment Values:</h4>
          <div class="data-item">
            <strong>API URL:</strong>
            <code>{{ safeConfig.apiUrl }}</code>
            <span class="safe-tag">Public</span>
          </div>
          <div class="data-item">
            <strong>Feature Flags:</strong>
            <code>{{ safeConfig.enableAnalytics }}</code>
            <span class="safe-tag">Public</span>
          </div>
        </div>

        <div class="security-note">
          <strong>Note:</strong> API keys and secrets are:
          <ul>
            <li>Stored on the server, never in frontend code</li>
            <li>Fetched at runtime via authenticated API calls</li>
            <li>Never bundled into the JavaScript</li>
          </ul>
        </div>
      </div>

      <div class="demo-section">
        <h3>Safe Payment Processing</h3>
        <p class="context">Sensitive data is masked and never logged...</p>

        <div class="input-group">
          <label for="creditCard">Credit Card:</label>
          <input
            id="creditCard"
            type="text"
            [(ngModel)]="creditCard"
            placeholder="4111-1111-1111-1111"
            maxlength="19"
            (input)="onCardInput()"
          >
        </div>

        @if (maskedCard) {
          <div class="masked-display">
            <strong>Masked value:</strong> <code>{{ maskedCard }}</code>
            <p class="note">Only the last 4 digits are ever displayed or logged.</p>
          </div>
        }

        <button (click)="processPaymentSecurely()">Process Payment</button>

        @if (paymentResult) {
          <div class="result success">{{ paymentResult }}</div>
        }
      </div>

      <div class="demo-section">
        <h3>Secure Session Storage</h3>
        <p class="context">Only non-sensitive identifiers stored client-side...</p>

        <button (click)="demonstrateSecureStorage()">Show Storage Strategy</button>

        @if (storageDemo) {
          <div class="storage-comparison">
            <div class="storage-section bad">
              <h4>Vulnerable (Don't Do This)</h4>
              <pre>{{ storageDemo.vulnerable }}</pre>
            </div>
            <div class="storage-section good">
              <h4>Secure (Best Practice)</h4>
              <pre>{{ storageDemo.secure }}</pre>
            </div>
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>Logging Best Practices</h3>
        <p class="context">Sensitive data is never logged...</p>

        <div class="logging-demo">
          <div class="log-example bad">
            <h4>Vulnerable Logging</h4>
            <code>console.log('User:', &#123; email, password, ssn &#125;)</code>
            <span class="status-bad">Exposes sensitive data!</span>
          </div>
          <div class="log-example good">
            <h4>Secure Logging</h4>
            <code>console.log('User login:', &#123; userId: user.id &#125;)</code>
            <span class="status-good">Only non-sensitive identifiers</span>
          </div>
        </div>

        <button (click)="demonstrateSecureLogging()">Test Secure Logging</button>

        @if (loggingResult) {
          <div class="result success">
            <pre>{{ loggingResult }}</pre>
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>Data Comparison</h3>
        <div class="comparison-table">
          <div class="comparison-row header">
            <div>Data Type</div>
            <div>Vulnerable</div>
            <div>Secure</div>
          </div>
          <div class="comparison-row">
            <div>API Keys</div>
            <div class="bad">In environment.ts</div>
            <div class="good">Server-side only</div>
          </div>
          <div class="comparison-row">
            <div>User Passwords</div>
            <div class="bad">Logged to console</div>
            <div class="good">Never logged</div>
          </div>
          <div class="comparison-row">
            <div>Credit Cards</div>
            <div class="bad">Full number stored</div>
            <div class="good">Masked, last 4 only</div>
          </div>
          <div class="comparison-row">
            <div>Session Tokens</div>
            <div class="bad">In localStorage</div>
            <div class="good">HttpOnly cookies</div>
          </div>
          <div class="comparison-row">
            <div>User Data</div>
            <div class="bad">Full SSN stored</div>
            <div class="good">IDs only, fetch on demand</div>
          </div>
        </div>
      </div>

      <div class="code-section">
        <h3>Secure Implementation</h3>
        <pre><code>{{ secureCode }}</code></pre>
      </div>

      <div class="explanation">
        <h3>Security Controls Applied</h3>
        <ul>
          <li><strong>No secrets in code:</strong> API keys stored server-side, fetched via authenticated endpoints</li>
          <li><strong>Data masking:</strong> Sensitive data masked in UI (e.g., ****1234)</li>
          <li><strong>Safe logging:</strong> Only non-sensitive identifiers logged</li>
          <li><strong>Minimal storage:</strong> Only necessary data stored client-side</li>
          <li><strong>Server-side secrets:</strong> Sensitive operations handled by backend</li>
          <li><strong>HTTPS only:</strong> All data transmitted over encrypted connections</li>
        </ul>
      </div>
    </div>
  `,
  styles: [`
    .security-demo { max-width: 800px; }
    .header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
    .header h2 { margin: 0; color: #28a745; }
    .badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .badge.success { background: #28a745; color: white; }
    .description { background: #d4edda; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; border-left: 4px solid #28a745; }
    .demo-section { background: #f8f9fa; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; }
    .demo-section h3 { margin-top: 0; }
    .context { color: #666; font-style: italic; }
    .config-display { background: white; padding: 1rem; border-radius: 4px; border: 1px solid #ddd; margin-bottom: 1rem; }
    .config-display h4 { margin-top: 0; }
    .data-item { margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
    .data-item strong { min-width: 120px; }
    .data-item code { background: #d4edda; padding: 0.25rem 0.5rem; border-radius: 4px; }
    .safe-tag { background: #28a745; color: white; padding: 0.125rem 0.5rem; border-radius: 4px; font-size: 0.75rem; }
    .security-note { background: #d4edda; padding: 1rem; border-radius: 4px; }
    .security-note ul { margin: 0.5rem 0 0 1.5rem; }
    .input-group { margin-bottom: 1rem; }
    .input-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
    .input-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
    button { padding: 0.75rem 1.5rem; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; margin-bottom: 0.5rem; }
    .masked-display { padding: 1rem; background: white; border-radius: 4px; border: 1px solid #ddd; margin-bottom: 1rem; }
    .masked-display code { background: #d4edda; padding: 0.25rem 0.5rem; border-radius: 4px; }
    .masked-display .note { margin: 0.5rem 0 0 0; font-size: 0.875rem; color: #666; }
    .result { padding: 1rem; border-radius: 4px; margin-top: 1rem; }
    .result.success { background: #d4edda; color: #155724; }
    .result pre { margin: 0; white-space: pre-wrap; }
    .storage-comparison { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem; }
    .storage-section { padding: 1rem; border-radius: 4px; }
    .storage-section.bad { background: #f8d7da; }
    .storage-section.good { background: #d4edda; }
    .storage-section h4 { margin-top: 0; }
    .storage-section pre { background: rgba(0,0,0,0.1); padding: 0.75rem; border-radius: 4px; font-size: 0.8rem; overflow-x: auto; }
    .logging-demo { margin-bottom: 1rem; }
    .log-example { padding: 1rem; border-radius: 4px; margin-bottom: 0.5rem; }
    .log-example.bad { background: #f8d7da; }
    .log-example.good { background: #d4edda; }
    .log-example h4 { margin: 0 0 0.5rem 0; font-size: 0.9rem; }
    .log-example code { display: block; background: rgba(0,0,0,0.1); padding: 0.5rem; border-radius: 4px; font-size: 0.85rem; }
    .status-bad { color: #721c24; font-size: 0.8rem; display: block; margin-top: 0.5rem; }
    .status-good { color: #155724; font-size: 0.8rem; display: block; margin-top: 0.5rem; }
    .comparison-table { border: 1px solid #ddd; border-radius: 4px; overflow: hidden; }
    .comparison-row { display: grid; grid-template-columns: 1fr 1fr 1fr; }
    .comparison-row.header { background: #343a40; color: white; font-weight: 600; }
    .comparison-row > div { padding: 0.75rem; border-bottom: 1px solid #ddd; }
    .comparison-row:last-child > div { border-bottom: none; }
    .comparison-row .bad { background: #f8d7da; color: #721c24; }
    .comparison-row .good { background: #d4edda; color: #155724; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #d4edda; padding: 1rem; border-radius: 8px; border-left: 4px solid #28a745; }
    .explanation h3 { margin-top: 0; }
  `]
})
export class SecureDataExposureComponent implements OnInit {
  creditCard = '';
  maskedCard = '';
  paymentResult = '';
  storageDemo: { vulnerable: string; secure: string } | null = null;
  loggingResult = '';

  safeConfig = {
    apiUrl: '/api',
    enableAnalytics: true
  };

  secureCode = `
// SECURE: Data protection patterns

// 1. Environment files - ONLY public values
// src/environments/environment.ts
export const environment = {
  production: false,
  apiUrl: '/api',           // Public - OK
  enableAnalytics: true     // Public - OK
  // NO API keys, secrets, or credentials!
};

// 2. Fetch sensitive config from authenticated endpoint
async getSecureConfig(): Promise<Config> {
  // Only available to authenticated users
  return this.http.get<Config>('/api/secure-config', {
    withCredentials: true
  }).toPromise();
}

// 3. Mask sensitive data in UI
maskCreditCard(card: string): string {
  const last4 = card.replace(/\\D/g, '').slice(-4);
  return '****-****-****-' + last4;
}

// 4. Safe logging - never log sensitive data
logUserAction(user: User, action: string) {
  console.log('User action:', {
    userId: user.id,      // OK - identifier only
    action: action        // OK - action name
    // NEVER log: password, ssn, credit card, tokens
  });
}

// 5. Minimal client-side storage
storeUserSession(user: User) {
  // Only store non-sensitive identifiers
  sessionStorage.setItem('userId', user.id);
  // Sensitive data stays on server
  // Session token in HttpOnly cookie
}
  `.trim();

  ngOnInit(): void {
    // Safe initialization - no sensitive data logging
    console.log('Component initialized');
  }

  onCardInput(): void {
    if (this.creditCard) {
      this.maskedCard = this.maskCreditCard(this.creditCard);
    } else {
      this.maskedCard = '';
    }
  }

  private maskCreditCard(card: string): string {
    // Remove non-digits
    const digits = card.replace(/\D/g, '');
    if (digits.length < 4) return '****';

    // Only show last 4 digits
    const last4 = digits.slice(-4);
    return `****-****-****-${last4}`;
  }

  processPaymentSecurely(): void {
    if (!this.creditCard) {
      this.paymentResult = 'Please enter a credit card number';
      return;
    }

    // SECURE: Never log full credit card number
    const masked = this.maskCreditCard(this.creditCard);

    // Safe logging - only masked value
    console.log('Processing payment for card:', masked);

    this.paymentResult = `SECURE: Payment processing initiated.

Card (masked): ${masked}

Security measures applied:
✓ Full card number never logged
✓ Sent to server over HTTPS
✓ Server handles actual payment processing
✓ Card data not stored client-side`;

    // Clear sensitive data from memory
    this.creditCard = '';
    this.maskedCard = '';
  }

  demonstrateSecureStorage(): void {
    this.storageDemo = {
      vulnerable: `// VULNERABLE - Don't do this!
localStorage.setItem('user', JSON.stringify({
  id: '12345',
  email: 'user@example.com',
  ssn: '123-45-6789',        // Sensitive!
  creditCard: '4111...',     // Sensitive!
  apiToken: 'secret_abc123'  // Sensitive!
}));`,
      secure: `// SECURE - Best practice
// Session identifier only (for re-authentication check)
sessionStorage.setItem('sessionId', 'sess_abc123');

// User preferences (non-sensitive)
localStorage.setItem('theme', 'dark');
localStorage.setItem('language', 'en');

// Sensitive data:
// - Stored on server
// - Fetched via authenticated API calls
// - Session token in HttpOnly cookie`
    };
  }

  demonstrateSecureLogging(): void {
    // Simulate a user action with safe logging
    const user = {
      id: 'usr_12345',
      email: 'user@example.com',
      name: 'John Doe'
    };

    // SECURE: Only log non-sensitive identifiers
    console.log('Secure log example:', {
      userId: user.id,
      action: 'demonstrateSecureLogging',
      timestamp: new Date().toISOString()
    });

    this.loggingResult = `Console output (check DevTools):

{
  userId: '${user.id}',
  action: 'demonstrateSecureLogging',
  timestamp: '${new Date().toISOString()}'
}

✓ No email, password, or sensitive data logged
✓ Only non-sensitive identifiers included
✓ Timestamps for audit trails`;
  }
}
