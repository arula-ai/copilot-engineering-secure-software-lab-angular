/**
 * VULNERABLE: Session Manager
 *
 * Security Issues:
 * - A01: Broken Access Control
 * - A07: Identification and Authentication Failures
 */

interface Session {
  userId: string;
  token: string;
  createdAt: Date;
  data: Record<string, any>;
}

export class SessionManager {
  private sessions: Map<string, Session> = new Map();

  // VULN: Weak token generation
  createSession(userId: string): string {
    // Predictable token
    const token = `session_${userId}_${Date.now()}`;

    this.sessions.set(token, {
      userId,
      token,
      createdAt: new Date(),
      data: {}
    });

    return token;
  }

  // VULN: No expiration check
  getSession(token: string): Session | undefined {
    // Sessions never expire
    return this.sessions.get(token);
  }

  // VULN: Session fixation vulnerability
  updateSessionUser(token: string, newUserId: string): void {
    const session = this.sessions.get(token);
    if (session) {
      // Doesn't regenerate token on user change
      session.userId = newUserId;
    }
  }

  // VULN: No session invalidation on logout
  logout(token: string): void {
    // Does nothing - session remains valid
    console.log('Logout requested but not implemented');
  }

  // VULN: Stores sensitive data in session
  setSessionData(token: string, key: string, value: any): void {
    const session = this.sessions.get(token);
    if (session) {
      // Can store anything, including sensitive data
      session.data[key] = value;
    }
  }
}
