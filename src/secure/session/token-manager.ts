/**
 * SECURE: Token Manager (JWT)
 *
 * Security Patterns Implemented:
 * - A02: Strong cryptographic configuration
 * - A07: Proper token validation and expiration
 * - A08: Token integrity verification
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */

import * as crypto from 'crypto';

interface TokenPayload {
  sub: string;      // Subject (user ID)
  role: string;
  iat: number;      // Issued at
  exp: number;      // Expiration
  jti: string;      // JWT ID (for revocation)
}

interface RefreshTokenData {
  userId: string;
  tokenHash: string;   // Store hash, not plain token
  familyId: string;    // For refresh token rotation
  createdAt: Date;
  expiresAt: Date;
  used: boolean;
}

// SECURE: Configuration
const TOKEN_CONFIG = {
  accessTokenExpiry: 15 * 60,           // 15 minutes
  refreshTokenExpiry: 7 * 24 * 60 * 60, // 7 days
  algorithm: 'HS256' as const,
  // SECURE: Secret should come from environment, not hardcoded
  // In production: Use asymmetric keys (RS256) for better security
};

export class SecureTokenManager {
  private readonly secret: Buffer;
  private refreshTokens: Map<string, RefreshTokenData> = new Map();
  private revokedTokens: Set<string> = new Set(); // JTI blacklist

  constructor(secret?: string) {
    // SECURE: Require secret from environment
    const secretValue = secret || process.env.JWT_SECRET;
    if (!secretValue || secretValue.length < 32) {
      throw new Error('JWT_SECRET must be at least 32 characters');
    }
    this.secret = Buffer.from(secretValue);
  }

  // SECURE: Create token with proper claims
  createAccessToken(userId: string, role: string): string {
    const now = Math.floor(Date.now() / 1000);

    const payload: TokenPayload = {
      sub: userId,
      role,
      iat: now,
      exp: now + TOKEN_CONFIG.accessTokenExpiry,
      jti: crypto.randomUUID(), // Unique token ID for revocation
    };

    return this.sign(payload);
  }

  // SECURE: Verify token with all security checks
  verifyAccessToken(token: string): TokenPayload | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return null;
      }

      const [headerB64, payloadB64, signatureB64] = parts;

      // SECURE: Verify header
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());

      // SECURE: Reject 'none' algorithm
      if (header.alg === 'none') {
        console.warn('SECURITY: Rejected token with none algorithm');
        return null;
      }

      // SECURE: Only accept expected algorithm
      if (header.alg !== TOKEN_CONFIG.algorithm) {
        console.warn(`SECURITY: Rejected token with unexpected algorithm: ${header.alg}`);
        return null;
      }

      // SECURE: Verify signature using timing-safe comparison
      const expectedSignature = this.computeSignature(headerB64, payloadB64);
      const providedSignature = Buffer.from(signatureB64, 'base64url');

      if (expectedSignature.length !== providedSignature.length) {
        return null;
      }

      if (!crypto.timingSafeEqual(expectedSignature, providedSignature)) {
        return null;
      }

      // SECURE: Parse and validate payload
      const payload: TokenPayload = JSON.parse(
        Buffer.from(payloadB64, 'base64url').toString()
      );

      // SECURE: Check expiration
      const now = Math.floor(Date.now() / 1000);
      if (!payload.exp || payload.exp < now) {
        return null;
      }

      // SECURE: Check issued at (not in future)
      if (!payload.iat || payload.iat > now + 60) { // 60s clock skew tolerance
        return null;
      }

      // SECURE: Check if token is revoked
      if (payload.jti && this.revokedTokens.has(payload.jti)) {
        console.warn(`SECURITY: Rejected revoked token: ${payload.jti}`);
        return null;
      }

      return payload;
    } catch (error) {
      return null;
    }
  }

  // SECURE: Create refresh token with proper security
  createRefreshToken(userId: string): { token: string; expiresAt: Date } {
    // SECURE: Generate cryptographically secure token
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = this.hashToken(token);
    const familyId = crypto.randomUUID();

    const expiresAt = new Date(Date.now() + TOKEN_CONFIG.refreshTokenExpiry * 1000);

    this.refreshTokens.set(tokenHash, {
      userId,
      tokenHash,
      familyId,
      createdAt: new Date(),
      expiresAt,
      used: false,
    });

    return { token, expiresAt };
  }

  // SECURE: Refresh token rotation
  rotateRefreshToken(oldToken: string): { accessToken: string; refreshToken: string; expiresAt: Date } | null {
    const oldTokenHash = this.hashToken(oldToken);
    const tokenData = this.refreshTokens.get(oldTokenHash);

    if (!tokenData) {
      return null;
    }

    // SECURE: Check expiration
    if (tokenData.expiresAt < new Date()) {
      this.refreshTokens.delete(oldTokenHash);
      return null;
    }

    // SECURE: Detect token reuse (refresh token theft)
    if (tokenData.used) {
      // Token was already used! Possible theft detected
      // Invalidate entire token family
      console.warn(`SECURITY: Refresh token reuse detected for family ${tokenData.familyId}`);
      this.invalidateTokenFamily(tokenData.familyId);
      return null;
    }

    // SECURE: Mark old token as used (not deleted, for reuse detection)
    tokenData.used = true;

    // SECURE: Create new tokens
    const accessToken = this.createAccessToken(tokenData.userId, 'user');
    const newRefresh = this.createRefreshToken(tokenData.userId);

    // SECURE: New refresh token inherits family ID
    const newTokenHash = this.hashToken(newRefresh.token);
    const newTokenData = this.refreshTokens.get(newTokenHash);
    if (newTokenData) {
      newTokenData.familyId = tokenData.familyId;
    }

    return {
      accessToken,
      refreshToken: newRefresh.token,
      expiresAt: newRefresh.expiresAt,
    };
  }

  // SECURE: Revoke access token by JTI
  revokeAccessToken(jti: string): void {
    this.revokedTokens.add(jti);
  }

  // SECURE: Revoke all refresh tokens for a user
  revokeAllUserTokens(userId: string): number {
    let revokedCount = 0;

    for (const [hash, data] of this.refreshTokens.entries()) {
      if (data.userId === userId) {
        this.refreshTokens.delete(hash);
        revokedCount++;
      }
    }

    return revokedCount;
  }

  // SECURE: Invalidate token family (on suspected theft)
  private invalidateTokenFamily(familyId: string): void {
    for (const [hash, data] of this.refreshTokens.entries()) {
      if (data.familyId === familyId) {
        this.refreshTokens.delete(hash);
      }
    }
  }

  // SECURE: Sign token payload
  private sign(payload: TokenPayload): string {
    const header = { alg: TOKEN_CONFIG.algorithm, typ: 'JWT' };

    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');

    const signature = this.computeSignature(headerB64, payloadB64);

    return `${headerB64}.${payloadB64}.${signature.toString('base64url')}`;
  }

  // SECURE: Compute HMAC signature
  private computeSignature(headerB64: string, payloadB64: string): Buffer {
    return crypto
      .createHmac('sha256', this.secret)
      .update(`${headerB64}.${payloadB64}`)
      .digest();
  }

  // SECURE: Hash refresh token for storage
  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  // SECURE: Cleanup expired tokens (run periodically)
  cleanupExpiredTokens(): number {
    const now = new Date();
    let cleanedCount = 0;

    for (const [hash, data] of this.refreshTokens.entries()) {
      if (data.expiresAt < now) {
        this.refreshTokens.delete(hash);
        cleanedCount++;
      }
    }

    return cleanedCount;
  }
}
