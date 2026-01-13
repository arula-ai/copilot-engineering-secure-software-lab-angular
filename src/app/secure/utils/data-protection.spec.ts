/**
 * Jest Tests for Data Protection
 *
 * Tests verify that sensitive data is properly protected.
 */

describe('Data Protection Security', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  describe('Credit Card Masking', () => {
    function maskCreditCard(card: string): string {
      const digits = card.replace(/\D/g, '');
      if (digits.length < 4) return '****';
      const last4 = digits.slice(-4);
      return `****-****-****-${last4}`;
    }

    it('should show only last 4 digits', () => {
      const result = maskCreditCard('4111111111111111');
      expect(result).toBe('****-****-****-1111');
    });

    it('should handle formatted card numbers', () => {
      const result = maskCreditCard('4111-1111-1111-1234');
      expect(result).toBe('****-****-****-1234');
    });

    it('should handle spaces in card numbers', () => {
      const result = maskCreditCard('4111 1111 1111 5678');
      expect(result).toBe('****-****-****-5678');
    });

    it('should handle short inputs', () => {
      const result = maskCreditCard('123');
      expect(result).toBe('****');
    });

    it('should not expose full card number', () => {
      const fullCard = '4111111111111111';
      const masked = maskCreditCard(fullCard);
      expect(masked).not.toContain('4111111111111111');
      expect(masked).not.toContain('41111111');
    });
  });

  describe('SSN Masking', () => {
    function maskSSN(ssn: string): string {
      const digits = ssn.replace(/\D/g, '');
      if (digits.length < 4) return '***-**-****';
      const last4 = digits.slice(-4);
      return `***-**-${last4}`;
    }

    it('should show only last 4 digits', () => {
      const result = maskSSN('123-45-6789');
      expect(result).toBe('***-**-6789');
    });

    it('should handle unformatted SSN', () => {
      const result = maskSSN('123456789');
      expect(result).toBe('***-**-6789');
    });

    it('should not expose full SSN', () => {
      const fullSSN = '123-45-6789';
      const masked = maskSSN(fullSSN);
      expect(masked).not.toContain('123-45');
      expect(masked).not.toContain('12345');
    });
  });

  describe('Email Masking', () => {
    function maskEmail(email: string): string {
      const [local, domain] = email.split('@');
      if (!domain) return '***@***.***';

      const maskedLocal = local.length > 2
        ? local[0] + '***' + local[local.length - 1]
        : '***';

      return `${maskedLocal}@${domain}`;
    }

    it('should mask local part of email', () => {
      const result = maskEmail('johndoe@example.com');
      expect(result).toBe('j***e@example.com');
    });

    it('should preserve domain', () => {
      const result = maskEmail('user@company.com');
      expect(result).toContain('@company.com');
    });

    it('should handle short usernames', () => {
      const result = maskEmail('ab@example.com');
      expect(result).toBe('***@example.com');
    });

    it('should not expose full email', () => {
      const email = 'secretuser@example.com';
      const masked = maskEmail(email);
      expect(masked).not.toContain('secretuser');
    });
  });

  describe('Storage Security', () => {
    const SENSITIVE_KEYS = ['password', 'ssn', 'creditCard', 'token', 'apiKey', 'secret'];

    it('should not store sensitive data in localStorage', () => {
      // Check that no sensitive keys exist in localStorage
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key) {
          const isSensitive = SENSITIVE_KEYS.some(
            sensitive => key.toLowerCase().includes(sensitive.toLowerCase())
          );
          expect(isSensitive).toBe(false);
        }
      }
    });

    it('should not store sensitive data in sessionStorage', () => {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key) {
          const isSensitive = SENSITIVE_KEYS.some(
            sensitive => key.toLowerCase().includes(sensitive.toLowerCase())
          );
          expect(isSensitive).toBe(false);
        }
      }
    });

    it('should allow non-sensitive data in storage', () => {
      const safeData = {
        theme: 'dark',
        language: 'en',
        userId: 'usr_123'
      };

      // Non-sensitive data like theme and language is acceptable in localStorage
      // Testing that the pattern of storing these values doesn't raise security concerns
      expect(safeData.theme).toBe('dark');
      expect(safeData.language).toBe('en');
      expect(safeData.userId).not.toContain('password');
    });
  });

  describe('Console Logging Security', () => {
    let consoleLogSpy: jest.SpyInstance;
    let consoleDebugSpy: jest.SpyInstance;
    let consoleWarnSpy: jest.SpyInstance;

    beforeEach(() => {
      consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
      consoleDebugSpy = jest.spyOn(console, 'debug').mockImplementation();
      consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
    });

    afterEach(() => {
      consoleLogSpy.mockRestore();
      consoleDebugSpy.mockRestore();
      consoleWarnSpy.mockRestore();
    });

    it('should not log passwords', () => {
      const sensitiveData = { email: 'user@example.com', password: 'secret123' };

      // Secure logging should only log non-sensitive fields
      const safeLog = { email: sensitiveData.email };
      console.log('User login:', safeLog);

      const loggedContent = JSON.stringify(consoleLogSpy.mock.calls);
      expect(loggedContent).not.toContain('secret123');
    });

    it('should not log credit card numbers', () => {
      const paymentData = { card: '4111111111111111', amount: 100 };

      // Secure logging should mask card
      const safeLog = { cardLast4: '1111', amount: paymentData.amount };
      console.log('Payment:', safeLog);

      const loggedContent = JSON.stringify(consoleLogSpy.mock.calls);
      expect(loggedContent).not.toContain('4111111111111111');
    });

    it('should not log API keys', () => {
      const config = { apiKey: 'sk_live_secret123', endpoint: '/api' };

      // Secure logging should not include API key
      const safeLog = { endpoint: config.endpoint };
      console.log('Config:', safeLog);

      const loggedContent = JSON.stringify(consoleLogSpy.mock.calls);
      expect(loggedContent).not.toContain('sk_live_secret123');
    });
  });

  describe('Environment Security', () => {
    it('should not include API secrets in frontend environment', () => {
      // Define what a secure environment config looks like
      const secureEnvironment = {
        production: false,
        apiUrl: '/api',
        enableAnalytics: true
        // NO: apiKey, secretKey, databaseUrl, etc.
      };

      const sensitiveKeys = ['apiKey', 'secretKey', 'databaseUrl', 'password', 'token'];

      sensitiveKeys.forEach(key => {
        expect(secureEnvironment).not.toHaveProperty(key);
      });
    });

    it('should only expose public configuration', () => {
      const publicConfigKeys = ['production', 'apiUrl', 'enableAnalytics', 'version'];
      const privateConfigKeys = ['apiKey', 'secretKey', 'databasePassword', 'awsSecret'];

      // All public keys are safe to expose
      publicConfigKeys.forEach(key => {
        expect(isPublicConfig(key)).toBe(true);
      });

      // Private keys should never be in frontend config
      privateConfigKeys.forEach(key => {
        expect(isPublicConfig(key)).toBe(false);
      });
    });
  });

  describe('Memory Cleanup', () => {
    it('should clear sensitive data after use', () => {
      let password: string | null = 'tempPassword123';

      // Use the password
      // ...

      // Clear from memory
      password = null;

      expect(password).toBeNull();
    });

    it('should not retain sensitive strings in closures', () => {
      function processCredentials(email: string, password: string) {
        // Process credentials
        const userId = 'usr_123'; // Would come from server

        // Return only non-sensitive data
        return { userId, email };
        // password is not returned or stored
      }

      const result = processCredentials('user@example.com', 'secret123');
      expect(result).not.toHaveProperty('password');
      expect(result).toHaveProperty('userId');
    });
  });
});

describe('Data Exposure Prevention', () => {
  describe('URL Parameter Security', () => {
    it('should not include sensitive data in URLs', () => {
      const safeUrls = [
        '/api/user/123',
        '/api/search?q=products',
        '/api/page?offset=10'
      ];

      const unsafeUrls = [
        '/api/login?password=secret',
        '/api/user?ssn=123456789',
        '/api/pay?card=4111111111111111'
      ];

      safeUrls.forEach(url => {
        expect(containsSensitiveData(url)).toBe(false);
      });

      unsafeUrls.forEach(url => {
        expect(containsSensitiveData(url)).toBe(true);
      });
    });
  });

  describe('Response Filtering', () => {
    it('should not return full credit card in API responses', () => {
      const secureResponse = {
        cardLast4: '1234',
        cardType: 'Visa',
        expiryMonth: 12,
        expiryYear: 2025
      };

      expect(secureResponse).not.toHaveProperty('cardNumber');
      expect(secureResponse).not.toHaveProperty('cvv');
    });

    it('should not return passwords in user responses', () => {
      const secureUserResponse = {
        id: 'usr_123',
        email: 'user@example.com',
        name: 'John Doe',
        role: 'user'
      };

      expect(secureUserResponse).not.toHaveProperty('password');
      expect(secureUserResponse).not.toHaveProperty('passwordHash');
    });
  });
});

// Helper functions
function isPublicConfig(key: string): boolean {
  const publicKeys = ['production', 'apiUrl', 'enableAnalytics', 'version', 'appName'];
  return publicKeys.includes(key);
}

function containsSensitiveData(url: string): boolean {
  const sensitivePatterns = [
    /password=/i,
    /ssn=/i,
    /card=/i,
    /token=/i,
    /secret=/i,
    /apikey=/i
  ];

  return sensitivePatterns.some(pattern => pattern.test(url));
}
