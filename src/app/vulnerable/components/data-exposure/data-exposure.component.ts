/**
 * VULNERABLE: Sensitive Data Exposure
 *
 * Security Issues:
 * - A02: Cryptographic Failures (Sensitive Data Exposure)
 * - A05: Security Misconfiguration
 *
 * This component demonstrates how sensitive data can be exposed
 * in Angular applications through various misconfigurations.
 *
 * DO NOT USE IN PRODUCTION
 */

import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { environment } from '../../../../environments/environment';

// VULN: Hardcoded credentials in source
const API_KEY = 'sk_live_51ABC123DEF456_SUPER_SECRET_KEY';
const DATABASE_PASSWORD = 'admin123!@#';

@Component({
  selector: 'app-vulnerable-data-exposure',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="vulnerability-demo">
      <div class="header">
        <h2>VULNERABLE: Sensitive Data Exposure</h2>
        <span class="badge danger">A02: Cryptographic Failures</span>
      </div>

      <div class="description">
        <p>
          This component demonstrates multiple ways sensitive data can be exposed
          in Angular applications, including API keys in environment files,
          hardcoded secrets, and console logging.
        </p>
      </div>

      <div class="demo-section">
        <h3>Environment Configuration</h3>
        <p class="context">API keys and secrets bundled into the client...</p>

        <div class="exposed-data">
          <h4>Data from environment.ts:</h4>
          <div class="data-item">
            <strong>API Key:</strong>
            <code>{{ exposedApiKey }}</code>
          </div>
          <div class="data-item">
            <strong>Secret Key:</strong>
            <code>{{ exposedSecret }}</code>
          </div>
          <div class="data-item">
            <strong>Database URL:</strong>
            <code>{{ exposedDbUrl }}</code>
          </div>
        </div>

        <div class="warning-box">
          <strong>These values are visible in:</strong>
          <ul>
            <li>Browser DevTools (Sources tab)</li>
            <li>Network tab (bundled JavaScript)</li>
            <li>Anyone who downloads your app</li>
          </ul>
        </div>
      </div>

      <div class="demo-section">
        <h3>Console Logging Sensitive Data</h3>
        <p class="context">Debug logs that expose user data...</p>

        <div class="input-group">
          <label for="creditCard">Credit Card:</label>
          <input
            id="creditCard"
            type="text"
            [(ngModel)]="creditCard"
            placeholder="4111-1111-1111-1111"
            maxlength="19"
          >
        </div>

        <div class="input-group">
          <label for="ssn">SSN:</label>
          <input
            id="ssn"
            type="text"
            [(ngModel)]="ssn"
            placeholder="123-45-6789"
            maxlength="11"
          >
        </div>

        <button (click)="processPayment()">Process Payment (Check Console)</button>

        @if (paymentResult) {
          <div class="result warning">{{ paymentResult }}</div>
        }
      </div>

      <div class="demo-section">
        <h3>Local Storage Data</h3>
        <p class="context">Sensitive data stored insecurely in localStorage...</p>

        <button (click)="storeUserData()">Store User Data</button>
        <button (click)="viewLocalStorage()">View localStorage</button>

        @if (localStorageContents) {
          <div class="storage-viewer">
            <h4>localStorage Contents (accessible via XSS):</h4>
            <pre>{{ localStorageContents }}</pre>
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>Network Request Exposure</h3>
        <p class="context">Sensitive data in URLs and request bodies...</p>

        <div class="exposed-data">
          <h4>Vulnerable Request Patterns:</h4>
          <div class="data-item">
            <strong>Password in URL:</strong>
            <code>/api/login?user=admin&password=secret123</code>
          </div>
          <div class="data-item">
            <strong>Token in URL:</strong>
            <code>/api/data?token={{ exposedApiKey }}</code>
          </div>
          <div class="data-item">
            <strong>Full credit card in response:</strong>
            <code>{{ '{ "card": "4111111111111111" }' }}</code>
          </div>
        </div>

        <p class="warning-text">
          All of these are visible in browser history, server logs, and proxy logs!
        </p>
      </div>

      <div class="demo-section">
        <h3>Source Code Exposure</h3>
        <p class="context">Hardcoded secrets in TypeScript files...</p>

        <button (click)="revealHardcodedSecrets()">Reveal Hardcoded Secrets</button>

        @if (hardcodedSecrets) {
          <div class="result error">
            <pre>{{ hardcodedSecrets }}</pre>
          </div>
        }

        <p class="context">
          These values are in the bundled JavaScript - anyone can extract them!
        </p>
      </div>

      <div class="code-section">
        <h3>Vulnerable Patterns</h3>
        <pre><code>{{ vulnerableCode }}</code></pre>
      </div>

      <div class="explanation">
        <h3>Why This Is Dangerous</h3>
        <ul>
          <li><strong>Environment files:</strong> Bundled into client JS, visible to anyone</li>
          <li><strong>Console logging:</strong> Exposes data to anyone with DevTools open</li>
          <li><strong>localStorage:</strong> Accessible via XSS attacks</li>
          <li><strong>URL parameters:</strong> Logged in browser history, server logs, referer headers</li>
          <li><strong>Hardcoded secrets:</strong> Extracted from minified bundle easily</li>
        </ul>
      </div>
    </div>
  `,
  styles: [`
    .vulnerability-demo { max-width: 800px; }
    .header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
    .header h2 { margin: 0; color: #dc3545; }
    .badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .badge.danger { background: #dc3545; color: white; }
    .description { background: #fff5f5; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; border-left: 4px solid #dc3545; }
    .demo-section { background: #f8f9fa; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; }
    .demo-section h3 { margin-top: 0; }
    .context { color: #666; font-style: italic; }
    .input-group { margin-bottom: 1rem; }
    .input-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
    .input-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
    button { padding: 0.75rem 1.5rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; margin-right: 0.5rem; margin-bottom: 0.5rem; }
    button:hover { background: #0056b3; }
    .exposed-data { background: white; padding: 1rem; border-radius: 4px; border: 2px solid #dc3545; margin-bottom: 1rem; }
    .data-item { margin-bottom: 0.75rem; }
    .data-item strong { display: inline-block; min-width: 120px; }
    .data-item code { background: #f8d7da; padding: 0.25rem 0.5rem; border-radius: 4px; word-break: break-all; }
    .warning-box { background: #fff3cd; padding: 1rem; border-radius: 4px; border-left: 4px solid #ffc107; }
    .warning-box ul { margin: 0.5rem 0 0 0; padding-left: 1.5rem; }
    .warning-text { color: #dc3545; font-weight: 500; }
    .result { padding: 1rem; border-radius: 4px; margin-top: 1rem; }
    .result.warning { background: #fff3cd; color: #856404; }
    .result.error { background: #f8d7da; color: #721c24; }
    .storage-viewer { margin-top: 1rem; }
    .storage-viewer pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 4px; overflow-x: auto; max-height: 200px; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #fff3cd; padding: 1rem; border-radius: 8px; border-left: 4px solid #ffc107; }
    .explanation h3 { margin-top: 0; }
  `]
})
export class VulnerableDataExposureComponent implements OnInit {
  // VULN: Exposing environment values in template
  exposedApiKey = '';
  exposedSecret = '';
  exposedDbUrl = '';

  creditCard = '';
  ssn = '';
  paymentResult = '';

  localStorageContents = '';
  hardcodedSecrets = '';

  vulnerableCode = `
// VULNERABLE: Multiple data exposure patterns

// 1. Environment file with secrets (bundled into client!)
// src/environments/environment.ts
export const environment = {
  production: false,
  apiKey: 'sk_live_51ABC123DEF456_SECRET', // EXPOSED!
  stripeKey: 'pk_live_STRIPE_PUBLIC_KEY',  // EXPOSED!
  databaseUrl: 'mongodb://admin:password@db.example.com' // EXPOSED!
};

// 2. Console logging sensitive data
processPayment(card: string, ssn: string) {
  console.log('Processing payment:', { card, ssn }); // EXPOSED!
  console.debug('Full card details:', card);          // EXPOSED!
}

// 3. Storing sensitive data in localStorage
storeUserSession(user: User) {
  localStorage.setItem('user', JSON.stringify({
    id: user.id,
    email: user.email,
    ssn: user.ssn,           // EXPOSED via XSS!
    creditCard: user.card    // EXPOSED via XSS!
  }));
}

// 4. Hardcoded secrets in source code
const API_KEY = 'sk_live_51ABC123DEF456';  // EXPOSED in bundle!
const DB_PASSWORD = 'admin123!@#';          // EXPOSED in bundle!

// 5. Sensitive data in URLs
this.http.get(\`/api/user?ssn=\${ssn}&token=\${apiKey}\`);
// Logged in: browser history, server logs, referer headers
  `.trim();

  ngOnInit(): void {
    // VULN: Exposing environment config to template
    this.exposedApiKey = (environment as any).apiKey || 'sk_live_DEMO_KEY_12345';
    this.exposedSecret = (environment as any).secretKey || 'secret_DEMO_abcdef';
    this.exposedDbUrl = (environment as any).databaseUrl || 'mongodb://admin:password123@localhost:27017';

    // VULN: Logging sensitive config on init
    console.log('Environment loaded:', environment);
  }

  processPayment(): void {
    if (!this.creditCard || !this.ssn) {
      this.paymentResult = 'Please enter card and SSN';
      return;
    }

    // VULN: Logging sensitive financial data!
    console.log('=== SENSITIVE DATA LOGGED ===');
    console.log('Credit Card:', this.creditCard);
    console.log('SSN:', this.ssn);
    console.log('Processing with API key:', this.exposedApiKey);
    console.log('=============================');

    this.paymentResult = `VULNERABLE: Check your browser console (F12) - your credit card "${this.creditCard}" and SSN "${this.ssn}" were just logged!`;
  }

  storeUserData(): void {
    // VULN: Storing sensitive data in localStorage
    const userData = {
      id: 'user_123',
      email: 'user@example.com',
      creditCard: '4111-1111-1111-1111',
      ssn: '123-45-6789',
      bankAccount: '****4567',
      apiToken: 'secret_token_abc123',
      sessionId: 'sess_vulnerable_xyz'
    };

    localStorage.setItem('vulnerable_user_data', JSON.stringify(userData));
    localStorage.setItem('vulnerable_api_key', this.exposedApiKey);
    localStorage.setItem('vulnerable_session', 'active_session_token_123');

    console.log('Stored sensitive data in localStorage:', userData);

    alert('Sensitive data stored in localStorage! Click "View localStorage" to see it.');
  }

  viewLocalStorage(): void {
    const allStorage: Record<string, string> = {};

    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key) {
        allStorage[key] = localStorage.getItem(key) || '';
      }
    }

    this.localStorageContents = JSON.stringify(allStorage, null, 2);

    // VULN: Also logging it
    console.log('localStorage contents:', allStorage);
  }

  revealHardcodedSecrets(): void {
    // VULN: These constants are in the compiled bundle
    this.hardcodedSecrets = `
Hardcoded secrets found in source:

API_KEY: ${API_KEY}
DATABASE_PASSWORD: ${DATABASE_PASSWORD}

These values are embedded in the compiled JavaScript
bundle and can be extracted by anyone who downloads
your application!

To find them:
1. Open DevTools > Sources
2. Find main.js (or similar bundle)
3. Search for the secret values

Or use: curl https://yoursite.com/main.js | strings | grep "sk_live"
    `.trim();

    console.warn('Revealed hardcoded secrets:', { API_KEY, DATABASE_PASSWORD });
  }
}
