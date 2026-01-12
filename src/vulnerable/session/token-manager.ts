/**
 * VULNERABLE: Token Manager (JWT)
 *
 * Security Issues:
 * - A02: Cryptographic Failures
 * - A07: Identification and Authentication Failures
 * - A08: Software and Data Integrity Failures
 *
 * DO NOT USE IN PRODUCTION
 */

import * as crypto from 'crypto';

interface TokenPayload {
  userId: string;
  role: string;
  email: string;
  exp?: number;
}

// VULN: Hardcoded secret
const JWT_SECRET = 'super-secret-key-123';

export class VulnerableTokenManager {

  // VULN: Accepts 'none' algorithm, allowing signature bypass
  verifyToken(token: string): TokenPayload | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return null;
      }

      const [headerB64, payloadB64, signature] = parts;
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());

      // VULN: Accepts 'none' algorithm - attacker can forge tokens
      if (header.alg === 'none') {
        console.log('Warning: Using none algorithm');
        return payload; // VULN: No signature verification!
      }

      // VULN: Accepts HS256 even when RS256 was expected
      // Algorithm confusion attack possible
      if (header.alg === 'HS256') {
        const expectedSig = this.sign(headerB64 + '.' + payloadB64, JWT_SECRET);
        if (signature === expectedSig) {
          return payload;
        }
      }

      return null;
    } catch {
      return null;
    }
  }

  // VULN: Creates tokens with weak configuration
  createToken(payload: TokenPayload): string {
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    };

    // VULN: No expiration by default
    // VULN: Sensitive data (email) in payload
    const tokenPayload = {
      ...payload,
      iat: Math.floor(Date.now() / 1000),
      // VULN: Missing exp claim
    };

    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(tokenPayload)).toString('base64url');

    // VULN: Using weak secret
    const signature = this.sign(headerB64 + '.' + payloadB64, JWT_SECRET);

    return `${headerB64}.${payloadB64}.${signature}`;
  }

  // VULN: Weak signing using hardcoded secret
  private sign(data: string, secret: string): string {
    return crypto.createHmac('sha256', secret).update(data).digest('base64url');
  }

  // VULN: Decodes without verification
  decodeWithoutVerification(token: string): TokenPayload | null {
    try {
      const parts = token.split('.');
      // VULN: Does not verify signature at all!
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      return payload;
    } catch {
      return null;
    }
  }

  // VULN: Refresh token stored in plain text, no rotation
  private refreshTokens: Map<string, { userId: string; createdAt: Date }> = new Map();

  createRefreshToken(userId: string): string {
    // VULN: Predictable refresh token
    const token = `refresh_${userId}_${Date.now()}`;
    this.refreshTokens.set(token, {
      userId,
      createdAt: new Date(),
    });
    // VULN: No expiration set
    // VULN: Old tokens not invalidated
    return token;
  }

  // VULN: No refresh token rotation
  useRefreshToken(refreshToken: string): string | null {
    const data = this.refreshTokens.get(refreshToken);
    if (!data) return null;

    // VULN: Same refresh token can be used multiple times
    // VULN: No check for token age
    // VULN: Should invalidate old token and issue new one

    return this.createToken({
      userId: data.userId,
      role: 'user',
      email: 'user@example.com',
    });
  }
}

/**
 * ATTACK EXAMPLES:
 *
 * 1. Algorithm None Attack:
 *    - Take a valid token
 *    - Change header.alg to "none"
 *    - Remove signature
 *    - Server accepts forged token
 *
 * 2. Algorithm Confusion:
 *    - Server expects RS256 (asymmetric)
 *    - Attacker uses HS256 with public key as secret
 *    - Signature validates with public key
 *
 * 3. Weak Secret Brute Force:
 *    - Extract JWT from network traffic
 *    - Brute force weak secret "super-secret-key-123"
 *    - Forge tokens with discovered secret
 *
 * 4. Refresh Token Theft:
 *    - Steal refresh token (predictable format)
 *    - Use indefinitely (no expiration)
 *    - Generate unlimited access tokens
 */
