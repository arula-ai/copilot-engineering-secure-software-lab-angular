/**
 * Jest Tests for URL Validation Security
 *
 * Tests verify that URL validation correctly blocks malicious URLs
 * and prevents open redirect vulnerabilities.
 */

// URL validation functions (extracted for testing)
const SAFE_PROTOCOLS = ['http:', 'https:', 'mailto:', 'tel:'];
const ALLOWED_PATHS = ['/', '/dashboard', '/profile', '/settings', '/account', '/orders'];
const TRUSTED_DOMAINS = ['example.com', 'github.com', 'angular.io', 'localhost'];

function validateRedirectUrl(url: string): { valid: boolean; safePath: string; reason: string } {
  const defaultPath = '/';

  if (!url) {
    return { valid: false, safePath: defaultPath, reason: 'Empty URL' };
  }

  // Decode URL to catch encoded attacks
  let decoded: string;
  try {
    decoded = decodeURIComponent(url);
    decoded = decodeURIComponent(decoded); // Double decode
  } catch {
    return { valid: false, safePath: defaultPath, reason: 'Invalid URL encoding' };
  }

  decoded = decoded.trim();

  // Block dangerous patterns
  const dangerousPatterns = [
    { pattern: /^https?:\/\//i, reason: 'External URL (http/https)' },
    { pattern: /^javascript:/i, reason: 'JavaScript URL' },
    { pattern: /^data:/i, reason: 'Data URL' },
    { pattern: /^vbscript:/i, reason: 'VBScript URL' },
    { pattern: /^\/\//, reason: 'Protocol-relative URL' },
    { pattern: /^[a-z][a-z0-9+.-]*:/i, reason: 'Unknown protocol' }
  ];

  for (const { pattern, reason } of dangerousPatterns) {
    if (pattern.test(decoded)) {
      return { valid: false, safePath: defaultPath, reason };
    }
  }

  // Extract path
  const path = decoded.split('?')[0].split('#')[0];
  const normalizedPath = '/' + path.replace(/^\/+/, '').replace(/\/+/g, '/');

  // Check allowlist
  const isAllowed = ALLOWED_PATHS.some(allowed =>
    normalizedPath === allowed || normalizedPath.startsWith(allowed + '/')
  );

  if (!isAllowed) {
    return { valid: false, safePath: defaultPath, reason: `Path not in allowlist` };
  }

  return { valid: true, safePath: decoded, reason: 'URL passed validation' };
}

function validateExternalUrl(url: string): { valid: boolean; reason: string } {
  try {
    const parsed = new URL(url, 'http://localhost');

    // Check protocol
    if (!SAFE_PROTOCOLS.includes(parsed.protocol)) {
      return { valid: false, reason: `Blocked protocol: ${parsed.protocol}` };
    }

    // For http/https, check domain
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      const isTrusted = TRUSTED_DOMAINS.some(domain =>
        parsed.host === domain || parsed.host.endsWith('.' + domain)
      );

      if (!isTrusted) {
        return { valid: false, reason: `Untrusted domain: ${parsed.host}` };
      }
    }

    return { valid: true, reason: 'URL is safe' };
  } catch {
    return { valid: false, reason: 'Invalid URL format' };
  }
}

describe('URL Validation Security', () => {
  describe('Redirect URL Validation', () => {
    describe('Allowed Paths', () => {
      it('should allow root path', () => {
        const result = validateRedirectUrl('/');
        expect(result.valid).toBe(true);
      });

      it('should allow /dashboard', () => {
        const result = validateRedirectUrl('/dashboard');
        expect(result.valid).toBe(true);
      });

      it('should allow /profile', () => {
        const result = validateRedirectUrl('/profile');
        expect(result.valid).toBe(true);
      });

      it('should allow paths with query strings', () => {
        const result = validateRedirectUrl('/dashboard?tab=overview');
        expect(result.valid).toBe(true);
      });

      it('should allow paths with fragments', () => {
        const result = validateRedirectUrl('/settings#notifications');
        expect(result.valid).toBe(true);
      });
    });

    describe('Blocked External URLs', () => {
      it('should block https:// URLs', () => {
        const result = validateRedirectUrl('https://evil.com/fake-login');
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('External URL');
      });

      it('should block http:// URLs', () => {
        const result = validateRedirectUrl('http://evil.com/phishing');
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('External URL');
      });
    });

    describe('Blocked JavaScript URLs', () => {
      it('should block javascript: URLs', () => {
        const result = validateRedirectUrl('javascript:alert(1)');
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('JavaScript URL');
      });

      it('should block JavaScript: with mixed case', () => {
        const result = validateRedirectUrl('JavaScript:alert(1)');
        expect(result.valid).toBe(false);
      });

      it('should block JAVASCRIPT: uppercase', () => {
        const result = validateRedirectUrl('JAVASCRIPT:alert(1)');
        expect(result.valid).toBe(false);
      });

      it('should block URL-encoded javascript:', () => {
        const result = validateRedirectUrl('javascript%3Aalert(1)');
        expect(result.valid).toBe(false);
      });
    });

    describe('Blocked Data URLs', () => {
      it('should block data: URLs', () => {
        const result = validateRedirectUrl('data:text/html,<script>alert(1)</script>');
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('Data URL');
      });

      it('should block base64 data URLs', () => {
        const result = validateRedirectUrl('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==');
        expect(result.valid).toBe(false);
      });
    });

    describe('Blocked Protocol-Relative URLs', () => {
      it('should block // URLs', () => {
        const result = validateRedirectUrl('//evil.com/path');
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('Protocol-relative');
      });

      it('should block URL-encoded // URLs', () => {
        const result = validateRedirectUrl('%2F%2Fevil.com');
        expect(result.valid).toBe(false);
      });
    });

    describe('Blocked VBScript URLs', () => {
      it('should block vbscript: URLs', () => {
        const result = validateRedirectUrl('vbscript:msgbox(1)');
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('VBScript');
      });
    });

    describe('URL Encoding Attack Prevention', () => {
      it('should decode URL-encoded paths before validation', () => {
        // %2F = /
        const result = validateRedirectUrl('%2Fdashboard');
        expect(result.valid).toBe(true);
      });

      it('should block double-encoded malicious URLs', () => {
        // %252F%252F = %2F%2F = //
        const result = validateRedirectUrl('%252F%252Fevil.com');
        expect(result.valid).toBe(false);
      });

      it('should block encoded javascript:', () => {
        const result = validateRedirectUrl('%6A%61%76%61%73%63%72%69%70%74:alert(1)');
        expect(result.valid).toBe(false);
      });
    });

    describe('Path Traversal Prevention', () => {
      it('should block paths not in allowlist', () => {
        const result = validateRedirectUrl('/admin/secret');
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('not in allowlist');
      });

      it('should handle empty URLs', () => {
        const result = validateRedirectUrl('');
        expect(result.valid).toBe(false);
        expect(result.safePath).toBe('/');
      });
    });

    describe('Default Safe Path', () => {
      it('should return / as safe default for blocked URLs', () => {
        const result = validateRedirectUrl('https://evil.com');
        expect(result.safePath).toBe('/');
      });

      it('should return / for empty URLs', () => {
        const result = validateRedirectUrl('');
        expect(result.safePath).toBe('/');
      });
    });
  });

  describe('External URL Validation', () => {
    describe('Protocol Validation', () => {
      it('should allow https: protocol', () => {
        const result = validateExternalUrl('https://example.com/page');
        expect(result.valid).toBe(true);
      });

      it('should allow http: protocol', () => {
        const result = validateExternalUrl('http://localhost/api');
        expect(result.valid).toBe(true);
      });

      it('should allow mailto: protocol', () => {
        const result = validateExternalUrl('mailto:user@example.com');
        expect(result.valid).toBe(true);
      });

      it('should allow tel: protocol', () => {
        const result = validateExternalUrl('tel:+1234567890');
        expect(result.valid).toBe(true);
      });

      it('should block ftp: protocol', () => {
        const result = validateExternalUrl('ftp://files.example.com');
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('Blocked protocol');
      });

      it('should block file: protocol', () => {
        const result = validateExternalUrl('file:///etc/passwd');
        expect(result.valid).toBe(false);
      });
    });

    describe('Domain Allowlist', () => {
      it('should allow trusted domain: example.com', () => {
        const result = validateExternalUrl('https://example.com/page');
        expect(result.valid).toBe(true);
      });

      it('should allow trusted domain: github.com', () => {
        const result = validateExternalUrl('https://github.com/repo');
        expect(result.valid).toBe(true);
      });

      it('should allow subdomain of trusted domain', () => {
        const result = validateExternalUrl('https://docs.angular.io/guide');
        expect(result.valid).toBe(true);
      });

      it('should block untrusted domains', () => {
        const result = validateExternalUrl('https://evil-site.com/phishing');
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('Untrusted domain');
      });

      it('should block domains that contain trusted domain as substring', () => {
        const result = validateExternalUrl('https://not-example.com');
        expect(result.valid).toBe(false);
      });
    });
  });
});

describe('Open Redirect Prevention', () => {
  const attackPayloads = [
    { name: 'External HTTPS', payload: 'https://evil.com/fake-login' },
    { name: 'External HTTP', payload: 'http://attacker.com/steal' },
    { name: 'JavaScript execution', payload: 'javascript:alert(document.cookie)' },
    { name: 'Data URL XSS', payload: 'data:text/html,<script>alert(1)</script>' },
    { name: 'Protocol-relative', payload: '//evil.com/path' },
    { name: 'URL-encoded external', payload: 'https%3A%2F%2Fevil.com' },
    { name: 'Double-encoded', payload: '%252F%252Fevil.com' },
    { name: 'Mixed case JavaScript', payload: 'JaVaScRiPt:alert(1)' },
    { name: 'Null byte injection', payload: '/dashboard%00.evil.com' },
    { name: 'Tab character', payload: 'java\tscript:alert(1)' },
  ];

  attackPayloads.forEach(({ name, payload }) => {
    it(`should block attack: ${name}`, () => {
      const result = validateRedirectUrl(payload);
      expect(result.valid).toBe(false);
    });
  });
});
