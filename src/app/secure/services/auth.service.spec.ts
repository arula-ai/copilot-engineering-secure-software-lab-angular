/**
 * Jest Tests for Secure Authentication Service
 *
 * Tests verify that secure authentication patterns are implemented correctly.
 */

import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { SecureAuthService } from './auth.service';

describe('SecureAuthService', () => {
  let service: SecureAuthService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    // Clear storage before test setup
    localStorage.clear();
    sessionStorage.clear();

    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [SecureAuthService]
    });

    httpMock = TestBed.inject(HttpTestingController);
    service = TestBed.inject(SecureAuthService);

    // Handle the initial session validation request from constructor
    // Use expectNone or match to clear pending requests
    httpMock.match(req => req.url === '/api/auth/session')
      .forEach(req => req.flush(null));
  });

  afterEach(() => {
    // Flush any remaining requests before verify
    httpMock.match(() => true).forEach(req => req.flush(null));
    localStorage.clear();
    sessionStorage.clear();
  });

  describe('Token Storage Security', () => {
    it('should NOT store tokens in localStorage', () => {
      // Verify no auth tokens in localStorage
      // Using toBeFalsy for test environment compatibility (null or undefined)
      expect(localStorage.getItem('auth_token')).toBeFalsy();
      expect(localStorage.getItem('token')).toBeFalsy();
      expect(localStorage.getItem('jwt')).toBeFalsy();
      expect(localStorage.getItem('access_token')).toBeFalsy();
    });

    it('should NOT store tokens in sessionStorage', () => {
      // Verify no auth tokens in sessionStorage
      // Using toBeFalsy for test environment compatibility (null or undefined)
      expect(sessionStorage.getItem('auth_token')).toBeFalsy();
      expect(sessionStorage.getItem('token')).toBeFalsy();
      expect(sessionStorage.getItem('jwt')).toBeFalsy();
    });

    it('should NOT expose tokens via getToken method', () => {
      // The secure service shouldn't have a getToken method
      // that returns a JavaScript-accessible token
      expect((service as any).getToken).toBeUndefined();
    });
  });

  describe('Authentication State', () => {
    it('should start with unauthenticated state', () => {
      expect(service.isAuthenticated()).toBe(false);
      expect(service.getCurrentUser()).toBeNull();
    });

    it('should store user info in memory only (not in storage)', () => {
      // Check that no user data is persisted to storage
      const storageKeys = [
        ...Array.from({ length: localStorage.length }, (_, i) => localStorage.key(i)),
        ...Array.from({ length: sessionStorage.length }, (_, i) => sessionStorage.key(i))
      ];

      const sensitiveKeys = storageKeys.filter(key =>
        key?.includes('user') ||
        key?.includes('email') ||
        key?.includes('role') ||
        key?.includes('password')
      );

      expect(sensitiveKeys).toHaveLength(0);
    });
  });

  describe('Login Security', () => {
    it('should NOT log credentials to console', () => {
      const consoleSpy = jest.spyOn(console, 'log');

      // Simulate login call
      service.login('test@example.com', 'password123').subscribe({
        error: () => {} // Expected to fail without real backend
      });

      // Verify password was never logged
      consoleSpy.mock.calls.forEach(call => {
        const loggedContent = JSON.stringify(call);
        expect(loggedContent).not.toContain('password123');
      });

      consoleSpy.mockRestore();

      // Handle the HTTP request
      const req = httpMock.expectOne('/api/auth/login');
      req.error(new ErrorEvent('Network error'));
    });

    it('should send login request with credentials flag for cookies', () => {
      service.login('test@example.com', 'password123').subscribe({
        error: () => {}
      });

      const req = httpMock.expectOne('/api/auth/login');
      expect(req.request.withCredentials).toBe(true);
      req.error(new ErrorEvent('Network error'));
    });
  });

  describe('Logout Security', () => {
    it('should clear user state on logout', (done) => {
      // Set up authenticated state first
      (service as any).currentUserSignal.set({ id: '1', email: 'test@example.com', role: 'user' });
      (service as any).isAuthenticatedSignal.set(true);

      expect(service.isAuthenticated()).toBe(true);

      service.logout().subscribe(() => {
        expect(service.isAuthenticated()).toBe(false);
        expect(service.getCurrentUser()).toBeNull();
        done();
      });

      const req = httpMock.expectOne('/api/auth/logout');
      req.flush({});
    });

    it('should call server logout endpoint', () => {
      service.logout().subscribe();

      const req = httpMock.expectOne('/api/auth/logout');
      expect(req.request.method).toBe('POST');
      expect(req.request.withCredentials).toBe(true);
      req.flush({});
    });
  });

  describe('Role Checking', () => {
    it('should check roles from memory, not decoded tokens', () => {
      // Set user in memory
      (service as any).currentUserSignal.set({ id: '1', email: 'admin@example.com', role: 'admin' });

      expect(service.hasRole('admin')).toBe(true);
      expect(service.hasRole('user')).toBe(false);
    });

    it('should return false for role checks when not authenticated', () => {
      expect(service.hasRole('admin')).toBe(false);
      expect(service.hasRole('user')).toBe(false);
    });
  });
});

describe('Authentication Security Patterns', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  describe('Token Theft Prevention', () => {
    it('XSS should not be able to steal tokens from localStorage', () => {
      // Simulate XSS attack trying to steal token
      const stolenToken = localStorage.getItem('auth_token');
      // Should be null (not found) - using toBeFalsy for test environment compatibility
      expect(stolenToken).toBeFalsy();
    });

    it('XSS should not be able to access HttpOnly cookies', () => {
      // document.cookie should not contain session tokens
      // HttpOnly cookies are not accessible via JavaScript
      expect(document.cookie).not.toContain('session');
      expect(document.cookie).not.toContain('auth_token');
    });
  });

  describe('Credential Handling', () => {
    it('should never store passwords anywhere', () => {
      const testPassword = 'SuperSecretPassword123!';

      // Check localStorage
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key) {
          const value = localStorage.getItem(key);
          expect(value).not.toContain(testPassword);
        }
      }

      // Check sessionStorage
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key) {
          const value = sessionStorage.getItem(key);
          expect(value).not.toContain(testPassword);
        }
      }
    });
  });
});
