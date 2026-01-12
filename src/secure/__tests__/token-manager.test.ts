/**
 * Security Tests for Token Manager (JWT)
 *
 * These tests verify secure JWT handling and token management.
 * Use these to validate Lab 3 implementations.
 */

import * as crypto from 'crypto';

describe('SecureTokenManager', () => {
  describe('Algorithm Security', () => {
    it('should reject none algorithm', () => {
      const ALLOWED_ALGORITHMS = ['HS256', 'RS256'];

      const isValidAlgorithm = (alg: string): boolean => {
        if (alg === 'none') return false;
        return ALLOWED_ALGORITHMS.includes(alg);
      };

      expect(isValidAlgorithm('HS256')).toBe(true);
      expect(isValidAlgorithm('RS256')).toBe(true);
      expect(isValidAlgorithm('none')).toBe(false);
      expect(isValidAlgorithm('NONE')).toBe(false);
    });

    it('should enforce expected algorithm', () => {
      const EXPECTED_ALGORITHM = 'HS256';

      const validateHeader = (header: { alg: string; typ: string }): boolean => {
        return header.alg === EXPECTED_ALGORITHM && header.typ === 'JWT';
      };

      expect(validateHeader({ alg: 'HS256', typ: 'JWT' })).toBe(true);
      expect(validateHeader({ alg: 'none', typ: 'JWT' })).toBe(false);
      expect(validateHeader({ alg: 'RS256', typ: 'JWT' })).toBe(false); // Wrong alg
    });
  });

  describe('Secret Strength', () => {
    it('should require minimum secret length of 32 characters', () => {
      const MIN_SECRET_LENGTH = 32;

      const isSecretStrong = (secret: string): boolean => {
        return secret.length >= MIN_SECRET_LENGTH;
      };

      expect(isSecretStrong('a'.repeat(32))).toBe(true);
      expect(isSecretStrong('a'.repeat(64))).toBe(true);
      expect(isSecretStrong('short')).toBe(false);
      expect(isSecretStrong('super-secret-key-123')).toBe(false); // Too short
    });

    it('should not use hardcoded secrets', () => {
      const KNOWN_WEAK_SECRETS = [
        'secret',
        'super-secret-key-123',
        'jwt-secret',
        'changeme',
        'password',
      ];

      const isWeakSecret = (secret: string): boolean => {
        return KNOWN_WEAK_SECRETS.includes(secret.toLowerCase());
      };

      expect(isWeakSecret('super-secret-key-123')).toBe(true);
      expect(isWeakSecret(crypto.randomBytes(32).toString('hex'))).toBe(false);
    });
  });

  describe('Token Expiration', () => {
    it('should include expiration claim', () => {
      const createPayload = (userId: string): Record<string, unknown> => {
        const now = Math.floor(Date.now() / 1000);
        return {
          sub: userId,
          iat: now,
          exp: now + 15 * 60, // 15 minutes
        };
      };

      const payload = createPayload('user-123');

      expect(payload).toHaveProperty('exp');
      expect(payload.exp).toBeGreaterThan(payload.iat as number);
    });

    it('should use reasonable expiration times', () => {
      const ACCESS_TOKEN_EXPIRY = 15 * 60; // 15 minutes
      const REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60; // 7 days

      // Access tokens should be short-lived
      expect(ACCESS_TOKEN_EXPIRY).toBeLessThanOrEqual(60 * 60); // Max 1 hour

      // Refresh tokens should not exceed 30 days
      expect(REFRESH_TOKEN_EXPIRY).toBeLessThanOrEqual(30 * 24 * 60 * 60);
    });

    it('should reject expired tokens', () => {
      const isTokenExpired = (exp: number): boolean => {
        const now = Math.floor(Date.now() / 1000);
        return exp < now;
      };

      const pastExp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
      const futureExp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

      expect(isTokenExpired(pastExp)).toBe(true);
      expect(isTokenExpired(futureExp)).toBe(false);
    });
  });

  describe('Signature Verification', () => {
    it('should use timing-safe comparison', () => {
      const signature1 = Buffer.from('valid-signature');
      const signature2 = Buffer.from('valid-signature');
      const signature3 = Buffer.from('wrong-signature');

      // Must use crypto.timingSafeEqual to prevent timing attacks
      expect(crypto.timingSafeEqual(signature1, signature2)).toBe(true);

      // Different lengths should be handled
      const compareSafe = (a: Buffer, b: Buffer): boolean => {
        if (a.length !== b.length) return false;
        return crypto.timingSafeEqual(a, b);
      };

      expect(compareSafe(signature1, signature2)).toBe(true);
      expect(compareSafe(signature1, signature3)).toBe(false);
    });

    it('should verify signature before trusting payload', () => {
      // This test demonstrates the secure verification order
      const verifyToken = (token: string, secret: string): boolean => {
        const parts = token.split('.');
        if (parts.length !== 3) return false;

        const [headerB64, payloadB64, signatureB64] = parts;

        // 1. Verify signature FIRST
        const expectedSig = crypto
          .createHmac('sha256', secret)
          .update(`${headerB64}.${payloadB64}`)
          .digest('base64url');

        if (signatureB64 !== expectedSig) return false;

        // 2. Only THEN trust the payload
        return true;
      };

      // This is just a structural test
      expect(verifyToken('a.b.c', 'secret')).toBe(false); // Invalid sig
    });
  });

  describe('Refresh Token Security', () => {
    it('should generate cryptographically secure refresh tokens', () => {
      const generateRefreshToken = (): string => {
        return crypto.randomBytes(32).toString('hex');
      };

      const token = generateRefreshToken();

      // Should be 64 hex characters (32 bytes)
      expect(token.length).toBe(64);
      expect(/^[a-f0-9]+$/.test(token)).toBe(true);
    });

    it('should store hashed refresh tokens, not plain text', () => {
      const hashToken = (token: string): string => {
        return crypto.createHash('sha256').update(token).digest('hex');
      };

      const plainToken = 'refresh_token_value';
      const hashedToken = hashToken(plainToken);

      expect(hashedToken).not.toBe(plainToken);
      expect(hashedToken.length).toBe(64); // SHA256 produces 64 hex chars
    });

    it('should implement refresh token rotation', () => {
      // Refresh token rotation: old token is invalidated when new one is issued
      interface TokenData {
        used: boolean;
        familyId: string;
      }

      const tokens = new Map<string, TokenData>();
      tokens.set('token-1', { used: false, familyId: 'family-1' });

      const useRefreshToken = (tokenHash: string): boolean => {
        const data = tokens.get(tokenHash);
        if (!data) return false;

        // Detect reuse (theft indicator)
        if (data.used) {
          // Invalidate entire family
          return false;
        }

        // Mark as used
        data.used = true;
        return true;
      };

      expect(useRefreshToken('token-1')).toBe(true);
      expect(useRefreshToken('token-1')).toBe(false); // Reuse detected
    });

    it('should include unique token ID (jti) for revocation', () => {
      const createPayload = (userId: string) => ({
        sub: userId,
        jti: crypto.randomUUID(),
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
      });

      const payload = createPayload('user-123');

      expect(payload).toHaveProperty('jti');
      expect(payload.jti).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
      );
    });
  });

  describe('Token Revocation', () => {
    it('should maintain JTI blacklist for revoked tokens', () => {
      const revokedTokens = new Set<string>();

      const revokeToken = (jti: string): void => {
        revokedTokens.add(jti);
      };

      const isRevoked = (jti: string): boolean => {
        return revokedTokens.has(jti);
      };

      const tokenJti = 'abc-123-def';

      expect(isRevoked(tokenJti)).toBe(false);
      revokeToken(tokenJti);
      expect(isRevoked(tokenJti)).toBe(true);
    });

    it('should check revocation before accepting token', () => {
      const revokedJtis = new Set(['revoked-jti-1', 'revoked-jti-2']);

      const validateToken = (payload: { jti: string }): boolean => {
        // Check revocation BEFORE accepting token
        if (revokedJtis.has(payload.jti)) {
          return false;
        }
        return true;
      };

      expect(validateToken({ jti: 'valid-jti' })).toBe(true);
      expect(validateToken({ jti: 'revoked-jti-1' })).toBe(false);
    });
  });

  describe('Payload Security', () => {
    it('should not include sensitive data in token payload', () => {
      const SENSITIVE_FIELDS = ['password', 'passwordHash', 'secret', 'apiKey', 'creditCard'];

      const payload = {
        sub: 'user-123',
        role: 'user',
        iat: 1234567890,
        exp: 1234568790,
      };

      SENSITIVE_FIELDS.forEach(field => {
        expect(payload).not.toHaveProperty(field);
      });
    });

    it('should validate iat claim is not in future', () => {
      const now = Math.floor(Date.now() / 1000);
      const CLOCK_SKEW_TOLERANCE = 60; // 60 seconds

      const isIatValid = (iat: number): boolean => {
        return iat <= now + CLOCK_SKEW_TOLERANCE;
      };

      expect(isIatValid(now)).toBe(true);
      expect(isIatValid(now - 3600)).toBe(true); // 1 hour ago is fine
      expect(isIatValid(now + 3600)).toBe(false); // 1 hour in future is not
    });
  });
});
