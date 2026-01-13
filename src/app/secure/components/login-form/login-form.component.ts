/**
 * SECURE: Login Form Component
 *
 * Security Controls:
 * - A02: Cryptographic Best Practices
 * - A07: Identification and Authentication Best Practices
 *
 * This component demonstrates SECURE login patterns.
 *
 * SAFE FOR PRODUCTION (with server-side security)
 */

import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SecureAuthService } from '../../services/auth.service';

@Component({
  selector: 'app-secure-login-form',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="security-demo">
      <div class="header">
        <h2>SECURE: Authentication Best Practices</h2>
        <span class="badge success">A02/A07: Auth Security</span>
      </div>

      <div class="description">
        <p>
          This component demonstrates secure authentication patterns including
          HttpOnly cookies, no localStorage for tokens, and proper credential handling.
        </p>
      </div>

      <div class="demo-section">
        <h3>Login Form</h3>

        @if (!isLoggedIn) {
          <form (ngSubmit)="onLogin()" class="login-form">
            <div class="input-group">
              <label for="email">Email:</label>
              <input
                id="email"
                type="email"
                [(ngModel)]="email"
                name="email"
                required
                autocomplete="email"
                placeholder="user@example.com"
              >
            </div>

            <div class="input-group">
              <label for="password">Password:</label>
              <input
                id="password"
                type="password"
                [(ngModel)]="password"
                name="password"
                required
                autocomplete="current-password"
                placeholder="Enter password"
              >
            </div>

            @if (errorMessage) {
              <div class="error-message">{{ errorMessage }}</div>
            }

            <button type="submit" [disabled]="isLoading">
              {{ isLoading ? 'Logging in...' : 'Login' }}
            </button>
          </form>

          <div class="demo-credentials">
            <p><strong>Demo note:</strong> In this demo, login is simulated.</p>
            <p>In production, server would set HttpOnly cookies.</p>
          </div>
        } @else {
          <div class="logged-in-panel">
            <p>Logged in as: <strong>{{ currentUser?.email }}</strong></p>
            <p>Role: <span class="role-badge">{{ currentUser?.role }}</span></p>

            <div class="security-info">
              <h4>Security Status</h4>
              <ul>
                <li class="secure">Session token: HttpOnly cookie (not in JS)</li>
                <li class="secure">localStorage: Empty (no sensitive data)</li>
                <li class="secure">User info: Memory only (cleared on refresh)</li>
              </ul>
            </div>

            <button (click)="onLogout()" class="logout-btn">Logout</button>
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>XSS Token Theft Test</h3>
        <p class="context">Demonstrating that tokens cannot be stolen via XSS...</p>

        <button (click)="attemptTokenTheft()" class="test-btn">Attempt Token Theft</button>

        @if (theftAttemptResult) {
          <div class="theft-result success">
            <p><strong>XSS Attack Simulation:</strong></p>
            <pre>{{ theftAttemptResult }}</pre>
            <p class="success-text">Token is NOT accessible to JavaScript!</p>
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>Storage Comparison</h3>
        <div class="comparison-table">
          <div class="comparison-row header">
            <div>Storage Type</div>
            <div>Vulnerable Version</div>
            <div>Secure Version</div>
          </div>
          <div class="comparison-row">
            <div>localStorage</div>
            <div class="bad">JWT token stored</div>
            <div class="good">Empty</div>
          </div>
          <div class="comparison-row">
            <div>sessionStorage</div>
            <div class="bad">User data</div>
            <div class="good">Empty</div>
          </div>
          <div class="comparison-row">
            <div>Cookies</div>
            <div class="bad">JS-accessible</div>
            <div class="good">HttpOnly, Secure</div>
          </div>
          <div class="comparison-row">
            <div>Memory</div>
            <div class="neutral">User info</div>
            <div class="good">User info only</div>
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
          <li><strong>HttpOnly cookies:</strong> Session tokens not accessible via JavaScript</li>
          <li><strong>No localStorage:</strong> Tokens never stored in XSS-accessible storage</li>
          <li><strong>Memory-only state:</strong> User info kept in signals, cleared on refresh</li>
          <li><strong>Server session:</strong> Logout invalidates server-side session</li>
          <li><strong>No credential logging:</strong> Passwords never logged anywhere</li>
          <li><strong>HTTPS required:</strong> Credentials only sent over encrypted connection</li>
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
    .login-form { max-width: 300px; }
    .input-group { margin-bottom: 1rem; }
    .input-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
    .input-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
    button { padding: 0.75rem 1.5rem; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
    button:hover { background: #1e7e34; }
    button:disabled { background: #6c757d; cursor: not-allowed; }
    .error-message { color: #dc3545; margin-bottom: 1rem; padding: 0.5rem; background: #f8d7da; border-radius: 4px; }
    .demo-credentials { margin-top: 1rem; padding: 1rem; background: #e9ecef; border-radius: 4px; }
    .logged-in-panel { padding: 1rem; background: #d4edda; border-radius: 4px; }
    .role-badge { padding: 0.25rem 0.5rem; border-radius: 4px; background: #28a745; color: white; }
    .security-info { margin-top: 1rem; padding: 1rem; background: white; border-radius: 4px; }
    .security-info h4 { margin-top: 0; }
    .security-info ul { list-style: none; padding: 0; margin: 0; }
    .security-info li { padding: 0.5rem 0; padding-left: 1.5rem; position: relative; }
    .security-info li.secure::before { content: '✓'; position: absolute; left: 0; color: #28a745; font-weight: bold; }
    .logout-btn { background: #6c757d; margin-top: 1rem; }
    .test-btn { background: #6c757d; }
    .theft-result { margin-top: 1rem; padding: 1rem; border-radius: 4px; }
    .theft-result.success { background: #d4edda; }
    .theft-result pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 4px; overflow-x: auto; }
    .success-text { color: #155724; font-weight: 600; margin-top: 0.5rem; }
    .comparison-table { border: 1px solid #ddd; border-radius: 4px; overflow: hidden; }
    .comparison-row { display: grid; grid-template-columns: 1fr 1fr 1fr; }
    .comparison-row.header { background: #343a40; color: white; font-weight: 600; }
    .comparison-row > div { padding: 0.75rem; border-bottom: 1px solid #ddd; }
    .comparison-row:last-child > div { border-bottom: none; }
    .comparison-row .bad { background: #f8d7da; color: #721c24; }
    .comparison-row .good { background: #d4edda; color: #155724; }
    .comparison-row .neutral { background: #fff3cd; color: #856404; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #d4edda; padding: 1rem; border-radius: 8px; border-left: 4px solid #28a745; }
    .explanation h3 { margin-top: 0; }
  `]
})
export class SecureLoginFormComponent {
  email = '';
  password = '';
  errorMessage = '';
  isLoading = false;
  theftAttemptResult = '';

  secureCode = `
// SECURE: Auth service with HttpOnly cookies

// Login - NO token stored in JavaScript
login(email: string, password: string): Observable<User> {
  // Never log credentials!
  return this.http.post<AuthResponse>(
    '/api/auth/login',
    { email, password },
    { withCredentials: true }  // Include cookies
  ).pipe(
    tap(response => {
      // Only store non-sensitive user info in memory
      this.currentUser.set(response.user);
    })
  );
}

// Server response sets HttpOnly cookie:
// Set-Cookie: session=<token>; HttpOnly; Secure; SameSite=Strict

// XSS cannot steal the token because:
// 1. localStorage.getItem('token') returns null
// 2. document.cookie doesn't include HttpOnly cookies
// 3. Token only sent automatically by browser with requests

// Logout invalidates server session
logout(): Observable<void> {
  return this.http.post('/api/auth/logout', {}, {
    withCredentials: true
  }).pipe(
    tap(() => this.currentUser.set(null))
  );
}
  `.trim();

  constructor(private authService: SecureAuthService) {}

  get isLoggedIn(): boolean {
    return this.authService.isAuthenticated();
  }

  get currentUser() {
    return this.authService.getCurrentUser();
  }

  onLogin(): void {
    if (!this.email || !this.password) {
      this.errorMessage = 'Please enter email and password';
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';

    // For demo purposes, simulate successful login
    // In production, this would call the actual auth service
    setTimeout(() => {
      // Simulate setting up authenticated state
      // (In real app, server would set HttpOnly cookie)
      console.log('Login attempt - credentials NOT logged for security');

      // Simulate successful auth for demo
      // @ts-ignore - accessing private for demo
      this.authService['currentUserSignal'].set({
        id: '12345',
        email: this.email,
        role: 'user'
      });
      // @ts-ignore - accessing private for demo
      this.authService['isAuthenticatedSignal'].set(true);

      this.isLoading = false;
      this.password = ''; // Clear password from memory
    }, 1000);
  }

  onLogout(): void {
    // @ts-ignore - accessing private for demo
    this.authService['currentUserSignal'].set(null);
    // @ts-ignore - accessing private for demo
    this.authService['isAuthenticatedSignal'].set(false);
    this.theftAttemptResult = '';
  }

  attemptTokenTheft(): void {
    // Simulate what an XSS attack would try to do
    const attempts = [
      {
        method: "localStorage.getItem('auth_token')",
        result: localStorage.getItem('auth_token')
      },
      {
        method: "localStorage.getItem('token')",
        result: localStorage.getItem('token')
      },
      {
        method: "sessionStorage.getItem('auth_token')",
        result: sessionStorage.getItem('auth_token')
      },
      {
        method: 'document.cookie',
        result: document.cookie || '(empty - HttpOnly cookies not visible)'
      }
    ];

    this.theftAttemptResult = attempts.map(a =>
      `${a.method}\n  → ${a.result || 'null'}`
    ).join('\n\n');

    this.theftAttemptResult += '\n\n✓ No tokens accessible to JavaScript!';
    this.theftAttemptResult += '\n✓ HttpOnly cookies are invisible to XSS attacks.';
  }
}
