/**
 * SECURE: Authentication Service
 *
 * Security Controls:
 * - A02: Cryptographic Best Practices
 * - A07: Identification and Authentication Best Practices
 *
 * This service demonstrates SECURE authentication patterns in Angular.
 * Note: Full security requires server-side implementation as well.
 *
 * SAFE FOR PRODUCTION (with server-side security)
 */

import { Injectable, signal, PLATFORM_ID, inject } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, of, throwError } from 'rxjs';
import { catchError, map, tap } from 'rxjs/operators';

interface User {
  id: string;
  email: string;
  role: string;
}

interface AuthResponse {
  user: User;
  // Note: No token returned - using HttpOnly cookies instead
}

@Injectable({
  providedIn: 'root'
})
export class SecureAuthService {
  // SECURE: User state stored in memory only (not localStorage)
  private currentUserSignal = signal<User | null>(null);
  private isAuthenticatedSignal = signal<boolean>(false);

  private platformId = inject(PLATFORM_ID);

  // SECURE: Session validation endpoint
  private readonly AUTH_ENDPOINT = '/api/auth';

  constructor(private http: HttpClient) {
    // SECURE: Validate session on service initialization
    if (isPlatformBrowser(this.platformId)) {
      this.validateSession();
    }
  }

  /**
   * SECURE: Login via server with HttpOnly cookie
   * - Credentials sent over HTTPS
   * - Server sets HttpOnly, Secure, SameSite cookie
   * - No token stored in JavaScript-accessible storage
   */
  login(email: string, password: string): Observable<User> {
    // SECURE: Never log credentials
    // console.log is intentionally NOT used here

    return this.http.post<AuthResponse>(
      `${this.AUTH_ENDPOINT}/login`,
      { email, password },
      {
        // SECURE: Include credentials for cookie handling
        withCredentials: true,
        headers: new HttpHeaders({
          'Content-Type': 'application/json'
        })
      }
    ).pipe(
      tap(response => {
        // SECURE: Only store non-sensitive user info in memory
        this.currentUserSignal.set(response.user);
        this.isAuthenticatedSignal.set(true);
      }),
      map(response => response.user),
      catchError(error => {
        // SECURE: Don't expose detailed error information
        console.error('Login failed'); // Generic message only
        return throwError(() => new Error('Invalid credentials'));
      })
    );
  }

  /**
   * SECURE: Logout invalidates session on server
   */
  logout(): Observable<void> {
    return this.http.post<void>(
      `${this.AUTH_ENDPOINT}/logout`,
      {},
      { withCredentials: true }
    ).pipe(
      tap(() => {
        // SECURE: Clear client-side state
        this.currentUserSignal.set(null);
        this.isAuthenticatedSignal.set(false);
      }),
      catchError(() => {
        // Clear state even if server call fails
        this.currentUserSignal.set(null);
        this.isAuthenticatedSignal.set(false);
        return of(undefined);
      })
    );
  }

  /**
   * SECURE: Validate session with server
   * Called on page load to check if HttpOnly cookie is still valid
   */
  validateSession(): void {
    this.http.get<AuthResponse>(
      `${this.AUTH_ENDPOINT}/session`,
      { withCredentials: true }
    ).pipe(
      catchError(() => of(null))
    ).subscribe(response => {
      if (response?.user) {
        this.currentUserSignal.set(response.user);
        this.isAuthenticatedSignal.set(true);
      } else {
        this.currentUserSignal.set(null);
        this.isAuthenticatedSignal.set(false);
      }
    });
  }

  /**
   * SECURE: Check authentication status
   * Note: This is client-side state - always verify on server for sensitive operations
   */
  isAuthenticated(): boolean {
    return this.isAuthenticatedSignal();
  }

  /**
   * SECURE: Get current user (from memory, not storage)
   */
  getCurrentUser(): User | null {
    return this.currentUserSignal();
  }

  /**
   * SECURE: Role check should be verified server-side
   * This is for UI purposes only - never trust for authorization
   */
  hasRole(role: string): boolean {
    const user = this.currentUserSignal();
    return user?.role === role;
  }

  /**
   * SECURE: Token handling for API calls
   * Note: With HttpOnly cookies, tokens are automatically included
   * No need to manually attach tokens to requests
   */
  // getAuthHeaders(): HttpHeaders {
  //   // Not needed when using HttpOnly cookies!
  //   // The browser automatically sends cookies with withCredentials: true
  // }
}

/**
 * SECURE PATTERNS DEMONSTRATED:
 *
 * 1. HttpOnly Cookies (Server-side requirement):
 *    - Token stored in HttpOnly cookie (not accessible via JavaScript)
 *    - Cookie has Secure flag (HTTPS only)
 *    - Cookie has SameSite=Strict (CSRF protection)
 *
 * 2. No localStorage for Tokens:
 *    - Tokens never stored in localStorage or sessionStorage
 *    - User info kept in memory (signal) only
 *    - Memory cleared on page refresh (re-validated with server)
 *
 * 3. Server-side Session Validation:
 *    - Session validated with server on app load
 *    - Role/permissions verified server-side for sensitive operations
 *    - Client-side role check is UI-only
 *
 * 4. Credential Handling:
 *    - Never logged to console
 *    - Sent over HTTPS only
 *    - Not stored anywhere on client
 *
 * 5. Logout:
 *    - Server-side session invalidation
 *    - Client state cleared
 *    - HttpOnly cookie cleared by server
 *
 * SERVER REQUIREMENTS:
 *
 * The server must:
 * - Set HttpOnly, Secure, SameSite cookies
 * - Validate session on each request
 * - Implement proper session expiration
 * - Invalidate sessions on logout
 * - Implement rate limiting for login attempts
 * - Use secure password hashing (bcrypt, argon2)
 */

/**
 * Example server cookie settings (Express.js):
 *
 * res.cookie('session', sessionToken, {
 *   httpOnly: true,      // Not accessible via JavaScript
 *   secure: true,        // HTTPS only
 *   sameSite: 'strict',  // CSRF protection
 *   maxAge: 3600000,     // 1 hour
 *   path: '/'
 * });
 */
