/**
 * SECURE: Session Manager
 *
 * Security Patterns Implemented:
 * - A01: Session-based access control
 * - A07: Secure token generation, expiration, rotation
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */

import * as crypto from 'crypto';

interface Session {
  userId: string;
  token: string;
  createdAt: Date;
  expiresAt: Date;
  lastActivity: Date;
  ipAddress: string;
  userAgent: string;
  data: Record<string, unknown>; // SECURE: typed as unknown, not any
}

// SECURE: Session configuration
const SESSION_CONFIG = {
  tokenLength: 32,              // 256 bits of entropy
  absoluteTimeout: 8 * 60 * 60 * 1000,  // 8 hours max session lifetime
  idleTimeout: 30 * 60 * 1000,          // 30 minutes of inactivity
  renewThreshold: 5 * 60 * 1000,        // Renew if less than 5 min remaining
};

// SECURE: Sensitive data that should never be stored in sessions
const FORBIDDEN_SESSION_KEYS = [
  'password',
  'passwordHash',
  'creditCard',
  'ssn',
  'token',
  'secret',
  'apiKey',
];

export class SecureSessionManager {
  private sessions: Map<string, Session> = new Map();

  // SECURE: Create session with cryptographically secure token
  createSession(
    userId: string,
    ipAddress: string,
    userAgent: string
  ): { token: string; expiresAt: Date } {
    // SECURE: Generate cryptographically secure random token
    const token = crypto.randomBytes(SESSION_CONFIG.tokenLength).toString('hex');

    const now = new Date();
    const expiresAt = new Date(now.getTime() + SESSION_CONFIG.absoluteTimeout);

    const session: Session = {
      userId,
      token,
      createdAt: now,
      expiresAt,
      lastActivity: now,
      ipAddress,
      userAgent,
      data: {},
    };

    // SECURE: Store session (in production, use Redis/database with encryption)
    this.sessions.set(token, session);

    return { token, expiresAt };
  }

  // SECURE: Get session with expiration and idle timeout checks
  getSession(token: string, currentIp?: string): Session | null {
    if (!token || typeof token !== 'string') {
      return null;
    }

    const session = this.sessions.get(token);

    if (!session) {
      return null;
    }

    const now = new Date();

    // SECURE: Check absolute expiration
    if (now > session.expiresAt) {
      this.invalidateSession(token);
      return null;
    }

    // SECURE: Check idle timeout
    const idleTime = now.getTime() - session.lastActivity.getTime();
    if (idleTime > SESSION_CONFIG.idleTimeout) {
      this.invalidateSession(token);
      return null;
    }

    // SECURE: Optional IP binding check (can be configurable)
    // Uncomment for strict IP binding:
    // if (currentIp && session.ipAddress !== currentIp) {
    //   this.invalidateSession(token);
    //   return null;
    // }

    // SECURE: Update last activity
    session.lastActivity = now;

    return session;
  }

  // SECURE: Regenerate session token (call after privilege changes)
  regenerateSession(oldToken: string): { token: string; expiresAt: Date } | null {
    const oldSession = this.sessions.get(oldToken);

    if (!oldSession) {
      return null;
    }

    // SECURE: Generate new token
    const newToken = crypto.randomBytes(SESSION_CONFIG.tokenLength).toString('hex');

    // SECURE: Create new session with same data but new token
    const newSession: Session = {
      ...oldSession,
      token: newToken,
      lastActivity: new Date(),
      // Keep existing expiration to maintain absolute timeout
    };

    // SECURE: Invalidate old session immediately
    this.sessions.delete(oldToken);

    // SECURE: Store new session
    this.sessions.set(newToken, newSession);

    return { token: newToken, expiresAt: newSession.expiresAt };
  }

  // SECURE: Proper session invalidation on logout
  logout(token: string): boolean {
    if (!token) {
      return false;
    }

    // SECURE: Actually remove the session
    const deleted = this.sessions.delete(token);

    return deleted;
  }

  // SECURE: Invalidate all sessions for a user (password change, security event)
  invalidateAllUserSessions(userId: string): number {
    let invalidatedCount = 0;

    for (const [token, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        this.sessions.delete(token);
        invalidatedCount++;
      }
    }

    return invalidatedCount;
  }

  // SECURE: Store data in session with validation
  setSessionData(token: string, key: string, value: unknown): boolean {
    const session = this.sessions.get(token);

    if (!session) {
      return false;
    }

    // SECURE: Prevent storing sensitive data in sessions
    const lowerKey = key.toLowerCase();
    for (const forbidden of FORBIDDEN_SESSION_KEYS) {
      if (lowerKey.includes(forbidden)) {
        console.warn(`SECURITY: Attempted to store forbidden key '${key}' in session`);
        return false;
      }
    }

    // SECURE: Validate value is serializable (no functions, circular refs)
    try {
      JSON.stringify(value);
    } catch {
      console.warn(`SECURITY: Attempted to store non-serializable value in session`);
      return false;
    }

    session.data[key] = value;
    return true;
  }

  // SECURE: Get session data
  getSessionData(token: string, key: string): unknown {
    const session = this.sessions.get(token);
    return session?.data[key];
  }

  // SECURE: Internal method to invalidate a session
  private invalidateSession(token: string): void {
    this.sessions.delete(token);
  }

  // SECURE: Cleanup expired sessions (call periodically)
  cleanupExpiredSessions(): number {
    const now = new Date();
    let cleanedCount = 0;

    for (const [token, session] of this.sessions.entries()) {
      const isExpired = now > session.expiresAt;
      const isIdle = now.getTime() - session.lastActivity.getTime() > SESSION_CONFIG.idleTimeout;

      if (isExpired || isIdle) {
        this.sessions.delete(token);
        cleanedCount++;
      }
    }

    return cleanedCount;
  }

  // SECURE: Get active session count for a user (detect concurrent sessions)
  getActiveSessionCount(userId: string): number {
    let count = 0;
    const now = new Date();

    for (const session of this.sessions.values()) {
      if (session.userId === userId && now < session.expiresAt) {
        count++;
      }
    }

    return count;
  }
}
