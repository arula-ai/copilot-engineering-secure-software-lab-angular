/**
 * VULNERABLE: CSRF/XSRF Demonstration
 *
 * Security Issues:
 * - A01: Broken Access Control (CSRF)
 * - A05: Security Misconfiguration
 *
 * This component demonstrates missing CSRF protection patterns
 * in Angular applications.
 *
 * DO NOT USE IN PRODUCTION
 */

import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpHeaders } from '@angular/common/http';

@Component({
  selector: 'app-vulnerable-csrf-demo',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="vulnerability-demo">
      <div class="header">
        <h2>VULNERABLE: CSRF Protection Missing</h2>
        <span class="badge danger">A01: Access Control</span>
      </div>

      <div class="description">
        <p>
          This component demonstrates how missing CSRF token handling in Angular
          HttpClient requests can lead to cross-site request forgery attacks.
        </p>
      </div>

      <div class="demo-section">
        <h3>Money Transfer (No CSRF Protection)</h3>
        <p class="context">A banking feature that transfers money without CSRF tokens...</p>

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

          <button (click)="transferMoney()">Transfer Money</button>
        </div>

        @if (transferResult) {
          <div class="result" [class.success]="transferSuccess" [class.error]="!transferSuccess">
            {{ transferResult }}
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>Profile Update (GET for State Change)</h3>
        <p class="context">Using GET requests for sensitive operations...</p>

        <div class="input-group">
          <label for="newEmail">New Email:</label>
          <input
            id="newEmail"
            type="email"
            [(ngModel)]="newEmail"
            placeholder="newemail@example.com"
          >
        </div>

        <button (click)="updateEmailViaGet()">Update Email (via GET)</button>

        @if (emailUpdateResult) {
          <div class="result warning">{{ emailUpdateResult }}</div>
        }

        <div class="attack-preview">
          <h4>Attack Vector:</h4>
          <p>An attacker can change your email with an image tag:</p>
          <code>&lt;img src="https://yourbank.com/api/update-email?email=attacker&#64;evil.com"&gt;</code>
        </div>
      </div>

      <div class="demo-section">
        <h3>API Configuration</h3>
        <p class="context">HttpClient setup without XSRF interceptor...</p>

        <div class="config-display">
          <p><strong>Current Configuration:</strong></p>
          <ul>
            <li>XSRF Module: <span class="status bad">Not configured</span></li>
            <li>withCredentials: <span class="status bad">false (cookies not sent)</span></li>
            <li>CSRF Header: <span class="status bad">Not included</span></li>
          </ul>
        </div>

        <button (click)="checkCsrfConfig()">Check CSRF Protection</button>

        @if (csrfCheckResult) {
          <div class="result warning">
            <pre>{{ csrfCheckResult }}</pre>
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>Simulated CSRF Attack</h3>
        <p class="context">See how an attacker's page could make requests on your behalf...</p>

        <div class="attack-simulation">
          <p>If you were logged in and visited an attacker's page containing:</p>
          <pre><code>{{ attackCode }}</code></pre>
          <button (click)="simulateAttack()" class="attack-btn">Simulate Attack</button>
        </div>

        @if (attackResult) {
          <div class="result error">
            <strong>Attack Result:</strong><br>
            {{ attackResult }}
          </div>
        }
      </div>

      <div class="code-section">
        <h3>Vulnerable Code</h3>
        <pre><code>{{ vulnerableCode }}</code></pre>
      </div>

      <div class="explanation">
        <h3>Why This Is Dangerous</h3>
        <ul>
          <li><strong>No CSRF tokens:</strong> Server can't verify request originated from your app</li>
          <li><strong>GET for mutations:</strong> State-changing GET requests can be triggered via images/links</li>
          <li><strong>Missing SameSite cookies:</strong> Cookies sent with cross-origin requests</li>
          <li><strong>No origin validation:</strong> Server doesn't check Origin/Referer headers</li>
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
    button { padding: 0.75rem 1.5rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; margin-top: 0.5rem; }
    button:hover { background: #0056b3; }
    .attack-btn { background: #dc3545; }
    .attack-btn:hover { background: #c82333; }
    .result { padding: 1rem; border-radius: 4px; margin-top: 1rem; }
    .result.success { background: #d4edda; color: #155724; }
    .result.error { background: #f8d7da; color: #721c24; }
    .result.warning { background: #fff3cd; color: #856404; }
    .config-display { background: white; padding: 1rem; border-radius: 4px; border: 1px solid #ddd; }
    .config-display ul { margin: 0.5rem 0 0 0; padding-left: 1.5rem; }
    .status { font-weight: 600; }
    .status.bad { color: #dc3545; }
    .status.good { color: #28a745; }
    .attack-preview { margin-top: 1rem; padding: 1rem; background: #f8d7da; border-radius: 4px; }
    .attack-preview code { display: block; background: #721c24; color: white; padding: 0.5rem; border-radius: 4px; margin-top: 0.5rem; word-break: break-all; }
    .attack-simulation { background: white; padding: 1rem; border-radius: 4px; border: 2px dashed #dc3545; }
    .attack-simulation pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 4px; overflow-x: auto; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #fff3cd; padding: 1rem; border-radius: 8px; border-left: 4px solid #ffc107; }
    .explanation h3 { margin-top: 0; }
  `]
})
export class VulnerableCsrfDemoComponent {
  recipient = '';
  amount = 100;
  transferResult = '';
  transferSuccess = false;

  newEmail = '';
  emailUpdateResult = '';

  csrfCheckResult = '';
  attackResult = '';

  attackCode = `
<!-- Attacker's page: evil.com/harmless-looking-page.html -->
<html>
  <body>
    <h1>You won a prize!</h1>
    <!-- Hidden form auto-submits to victim's bank -->
    <form id="csrf-form" action="https://yourbank.com/api/transfer" method="POST">
      <input type="hidden" name="recipient" value="attacker@evil.com">
      <input type="hidden" name="amount" value="10000">
    </form>
    <script>
      document.getElementById('csrf-form').submit();
    </script>
  </body>
</html>
  `.trim();

  vulnerableCode = `
// VULNERABLE: API service without CSRF protection

// app.config.ts - Missing XSRF configuration
export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(), // VULN: No withXsrfConfiguration()!
  ]
};

// api.service.ts - Requests without CSRF tokens
@Injectable()
export class VulnerableApiService {

  transferMoney(recipient: string, amount: number) {
    // VULN: No CSRF token in request!
    return this.http.post('/api/transfer', {
      recipient,
      amount
    });
    // Missing: X-XSRF-TOKEN header
  }

  // VULN: Using GET for state-changing operations
  updateEmail(email: string) {
    return this.http.get('/api/update-email?email=' + email);
    // GET requests are especially vulnerable - can be triggered
    // by img tags, link prefetching, etc.
  }
}

// SECURE version would include:
// provideHttpClient(withXsrfConfiguration({
//   cookieName: 'XSRF-TOKEN',
//   headerName: 'X-XSRF-TOKEN'
// }))
  `.trim();

  constructor(private http: HttpClient) {}

  transferMoney(): void {
    if (!this.recipient || !this.amount) {
      this.transferResult = 'Please fill in all fields';
      this.transferSuccess = false;
      return;
    }

    // VULN: Making request without CSRF token
    const payload = {
      recipient: this.recipient,
      amount: this.amount
    };

    console.log('Transfer request (NO CSRF protection):', payload);

    // Simulated request - in real app this would hit the server
    // The vulnerability is that there's no CSRF token being sent
    this.transferResult = `VULNERABLE: Transfer of $${this.amount} to ${this.recipient} would be sent WITHOUT CSRF protection. An attacker could forge this request!`;
    this.transferSuccess = false;

    // Show what a real request would look like
    console.warn('Request headers (missing CSRF):', {
      'Content-Type': 'application/json',
      // Missing: 'X-XSRF-TOKEN': '<token>'
    });
  }

  updateEmailViaGet(): void {
    if (!this.newEmail) {
      this.emailUpdateResult = 'Please enter an email';
      return;
    }

    // VULN: Using GET for a state-changing operation!
    const url = `/api/update-email?email=${encodeURIComponent(this.newEmail)}`;

    console.log('GET request for email update (VULNERABLE):', url);

    this.emailUpdateResult = `VULNERABLE: Email update via GET request to ${url}. This can be exploited via image tags or link prefetching!`;
  }

  checkCsrfConfig(): void {
    // Check current CSRF configuration
    const checks = [
      'XSRF Cookie: Not being read from document.cookie',
      'XSRF Header: Not being added to requests',
      'HttpClient Config: withXsrfConfiguration() not called',
      'Server Validation: Unknown (requires server check)',
    ];

    this.csrfCheckResult = `CSRF Protection Status:\n\n${checks.map(c => '❌ ' + c).join('\n')}\n\nYour application is vulnerable to CSRF attacks!`;
  }

  simulateAttack(): void {
    // Simulate what happens when a victim visits an attacker's page
    const attackDetails = {
      attackerSite: 'https://evil.com/prize.html',
      targetEndpoint: '/api/transfer',
      payload: { recipient: 'attacker@evil.com', amount: 10000 },
      result: 'SUCCESS - Request would be sent with victim\'s cookies!'
    };

    console.warn('CSRF Attack Simulation:', attackDetails);

    this.attackResult = `Attack Simulation Complete!

Attacker's page at: ${attackDetails.attackerSite}
Would POST to: ${attackDetails.targetEndpoint}
With payload: ${JSON.stringify(attackDetails.payload)}

Result: The victim's browser would send this request WITH their authentication cookies, allowing the attacker to transfer money on their behalf!`;
  }
}
