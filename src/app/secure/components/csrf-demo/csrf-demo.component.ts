/**
 * SECURE: CSRF/XSRF Protection Demonstration
 *
 * Security Controls:
 * - A01: Access Control with CSRF Protection
 * - A05: Security Configuration
 *
 * This component demonstrates proper CSRF protection patterns
 * in Angular applications.
 *
 * SAFE FOR PRODUCTION (with server-side implementation)
 */

import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpHeaders } from '@angular/common/http';

@Component({
  selector: 'app-secure-csrf-demo',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="security-demo">
      <div class="header">
        <h2>SECURE: CSRF Protection Enabled</h2>
        <span class="badge success">A01: Access Control</span>
      </div>

      <div class="description">
        <p>
          This component demonstrates proper CSRF token handling in Angular
          HttpClient requests, preventing cross-site request forgery attacks.
        </p>
      </div>

      <div class="demo-section">
        <h3>Money Transfer (With CSRF Protection)</h3>
        <p class="context">Secure banking feature with CSRF tokens and proper HTTP methods...</p>

        <div class="transfer-form">
          <div class="input-group">
            <label for="recipient">Recipient:</label>
            <input
              id="recipient"
              type="text"
              [(ngModel)]="recipient"
              placeholder="recipient@example.com"
            >
          </div>

          <div class="input-group">
            <label for="amount">Amount ($):</label>
            <input
              id="amount"
              type="number"
              [(ngModel)]="amount"
              placeholder="100"
            >
          </div>

          <button (click)="transferMoney()">Transfer Money (Secure)</button>
        </div>

        @if (transferResult) {
          <div class="result success">
            {{ transferResult }}
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>API Configuration</h3>
        <p class="context">HttpClient setup with XSRF module...</p>

        <div class="config-display">
          <p><strong>Security Configuration:</strong></p>
          <ul>
            <li>XSRF Module: <span class="status good">Configured</span></li>
            <li>Cookie Name: <span class="status good">XSRF-TOKEN</span></li>
            <li>Header Name: <span class="status good">X-XSRF-TOKEN</span></li>
            <li>SameSite Cookie: <span class="status good">Strict</span></li>
            <li>HTTP Methods: <span class="status good">POST/PUT/DELETE only</span></li>
          </ul>
        </div>

        <button (click)="checkCsrfConfig()">Verify CSRF Protection</button>

        @if (csrfCheckResult) {
          <div class="result success">
            <pre>{{ csrfCheckResult }}</pre>
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>Attack Simulation</h3>
        <p class="context">See how CSRF attacks are blocked...</p>

        <div class="attack-simulation">
          <p>When an attacker tries to make requests from their site:</p>
          <ol>
            <li>Browser doesn't send XSRF-TOKEN cookie (SameSite=Strict)</li>
            <li>Request has no X-XSRF-TOKEN header</li>
            <li>Server rejects request: "Invalid CSRF token"</li>
          </ol>

          <button (click)="simulateAttack()" class="test-btn">Simulate CSRF Attack</button>
        </div>

        @if (attackResult) {
          <div class="result success">
            <strong>Attack Result:</strong><br>
            <pre>{{ attackResult }}</pre>
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>Protection Comparison</h3>
        <div class="comparison-table">
          <div class="comparison-row header">
            <div>Protection</div>
            <div>Vulnerable</div>
            <div>Secure</div>
          </div>
          <div class="comparison-row">
            <div>XSRF Token</div>
            <div class="bad">Not included</div>
            <div class="good">Auto-included</div>
          </div>
          <div class="comparison-row">
            <div>SameSite Cookie</div>
            <div class="bad">None/Lax</div>
            <div class="good">Strict</div>
          </div>
          <div class="comparison-row">
            <div>State-Change Methods</div>
            <div class="bad">GET allowed</div>
            <div class="good">POST/PUT/DELETE</div>
          </div>
          <div class="comparison-row">
            <div>Origin Validation</div>
            <div class="bad">None</div>
            <div class="good">Server-side check</div>
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
          <li><strong>XSRF Module:</strong> Angular automatically reads XSRF-TOKEN cookie and adds X-XSRF-TOKEN header</li>
          <li><strong>SameSite Cookies:</strong> Browser doesn't send cookies with cross-origin requests</li>
          <li><strong>POST for mutations:</strong> State-changing operations use POST/PUT/DELETE, not GET</li>
          <li><strong>Server validation:</strong> Server verifies token matches for all state-changing requests</li>
          <li><strong>Origin checking:</strong> Server validates Origin/Referer headers</li>
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
    .input-group { margin-bottom: 1rem; }
    .input-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
    .input-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
    button { padding: 0.75rem 1.5rem; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; margin-top: 0.5rem; }
    button:hover { background: #1e7e34; }
    .test-btn { background: #6c757d; }
    .result { padding: 1rem; border-radius: 4px; margin-top: 1rem; }
    .result.success { background: #d4edda; color: #155724; }
    .result pre { margin: 0.5rem 0 0 0; white-space: pre-wrap; }
    .config-display { background: white; padding: 1rem; border-radius: 4px; border: 1px solid #ddd; }
    .config-display ul { margin: 0.5rem 0 0 0; padding-left: 1.5rem; }
    .status { font-weight: 600; }
    .status.bad { color: #dc3545; }
    .status.good { color: #28a745; }
    .attack-simulation { background: white; padding: 1rem; border-radius: 4px; border: 2px solid #28a745; }
    .attack-simulation ol { margin: 1rem 0; padding-left: 1.5rem; }
    .comparison-table { border: 1px solid #ddd; border-radius: 4px; overflow: hidden; margin-top: 1rem; }
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
export class SecureCsrfDemoComponent implements OnInit {
  recipient = '';
  amount = 100;
  transferResult = '';
  csrfCheckResult = '';
  attackResult = '';

  secureCode = `
// SECURE: Angular CSRF/XSRF Configuration

// app.config.ts - Configure XSRF handling
import { provideHttpClient, withXsrfConfiguration } from '@angular/common/http';

export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(
      withXsrfConfiguration({
        cookieName: 'XSRF-TOKEN',   // Cookie name set by server
        headerName: 'X-XSRF-TOKEN'  // Header Angular will send
      })
    )
  ]
};

// api.service.ts - Requests automatically include CSRF token
@Injectable()
export class SecureApiService {

  transferMoney(recipient: string, amount: number) {
    // Angular automatically:
    // 1. Reads XSRF-TOKEN cookie
    // 2. Adds X-XSRF-TOKEN header
    return this.http.post('/api/transfer', {
      recipient,
      amount
    }, { withCredentials: true });
  }

  // NEVER use GET for state-changing operations
  updateEmail(email: string) {
    return this.http.post('/api/update-email', { email });
    // POST, not GET!
  }
}

// Server must:
// 1. Set XSRF-TOKEN cookie on initial page load
// 2. Validate X-XSRF-TOKEN header matches cookie
// 3. Set SameSite=Strict on session cookies
// 4. Check Origin/Referer headers
  `.trim();

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    // In a real app, the server would set the XSRF-TOKEN cookie
    // on the initial page load
  }

  transferMoney(): void {
    if (!this.recipient || !this.amount) {
      this.transferResult = 'Please fill in all fields';
      return;
    }

    // Show what a secure request would include
    this.transferResult = `SECURE: Transfer request would include:

• HTTP Method: POST (not GET)
• Headers:
  - Content-Type: application/json
  - X-XSRF-TOKEN: <token from cookie>
• Cookies:
  - XSRF-TOKEN (read by Angular)
  - session (HttpOnly, not readable)

Server validates:
✓ X-XSRF-TOKEN header matches XSRF-TOKEN cookie
✓ Origin header matches expected domain
✓ Session is valid

Transfer of $${this.amount} to ${this.recipient} is protected!`;
  }

  checkCsrfConfig(): void {
    const checks = [
      '✓ XSRF Configuration: Enabled via withXsrfConfiguration()',
      '✓ Cookie Name: XSRF-TOKEN',
      '✓ Header Name: X-XSRF-TOKEN',
      '✓ Auto-inclusion: Angular adds header to mutating requests',
      '✓ SameSite: Configured on server (Strict recommended)',
      '✓ Origin Validation: Checked server-side'
    ];

    this.csrfCheckResult = `CSRF Protection Status:\n\n${checks.join('\n')}\n\n✓ Your application is protected against CSRF attacks!`;
  }

  simulateAttack(): void {
    this.attackResult = `CSRF Attack Attempt:

1. Attacker creates page at evil.com with hidden form
2. Victim visits evil.com while logged into yourbank.com
3. Form tries to POST to yourbank.com/api/transfer

Attack BLOCKED because:

❌ SameSite=Strict cookie policy:
   Browser refuses to send cookies to cross-origin requests

❌ Missing XSRF token:
   Attacker can't read XSRF-TOKEN cookie from their domain
   Request has no X-XSRF-TOKEN header

❌ Server validation fails:
   - No valid XSRF token
   - Origin header is evil.com, not yourbank.com

Response: 403 Forbidden - Invalid CSRF token

✓ Attack prevented! User's money is safe.`;
  }
}
