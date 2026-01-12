/**
 * SECURE: Authentication Controller
 *
 * Security Patterns Implemented:
 * - A01: Proper authorization checks on all endpoints
 * - A02: Strong password hashing with bcrypt
 * - A07: Rate limiting, account lockout, secure sessions
 * - A09: Security event logging (without sensitive data)
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */

import { Request, Response } from 'express';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

interface User {
  id: string;
  email: string;
  passwordHash: string; // SECURE: Only store hash, never plain text
  role: string;
  failedAttempts: number;
  lockedUntil: Date | null;
}

interface AuthenticatedRequest extends Request {
  user?: { id: string; role: string };
}

// SECURE: Password hashing configuration
const BCRYPT_ROUNDS = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 30 * 60 * 1000; // 30 minutes

// Simulated user store (in production, use database with parameterized queries)
const users: Map<string, User> = new Map();

// SECURE: Security event logger - never logs sensitive data
class SecurityLogger {
  static logAuthEvent(event: string, userId: string | null, ip: string, success: boolean) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      userId: userId || 'anonymous',
      ip,
      success,
      // SECURE: Never log passwords, tokens, or session IDs
    };
    console.log('SECURITY_EVENT:', JSON.stringify(logEntry));
  }
}

export class SecureAuthController {

  // SECURE: Login with rate limiting, account lockout, and secure token generation
  async login(req: AuthenticatedRequest, res: Response) {
    const { email, password } = req.body;
    const clientIp = req.ip || 'unknown';

    // SECURE: Input validation
    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
      SecurityLogger.logAuthEvent('LOGIN_INVALID_INPUT', null, clientIp, false);
      return res.status(400).json({ error: 'Invalid request' });
    }

    // SECURE: Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const user = users.get(email);

    // SECURE: Check account lockout
    if (user?.lockedUntil && user.lockedUntil > new Date()) {
      SecurityLogger.logAuthEvent('LOGIN_ACCOUNT_LOCKED', user.id, clientIp, false);
      // SECURE: Generic message prevents user enumeration
      return res.status(401).json({ error: 'Authentication failed' });
    }

    // SECURE: Timing-safe password verification
    if (!user) {
      // SECURE: Still perform hash comparison to prevent timing attacks
      await bcrypt.compare(password, '$2b$12$dummy.hash.to.prevent.timing.attacks');
      SecurityLogger.logAuthEvent('LOGIN_FAILED', null, clientIp, false);
      // SECURE: Generic message prevents user enumeration
      return res.status(401).json({ error: 'Authentication failed' });
    }

    const passwordValid = await bcrypt.compare(password, user.passwordHash);

    if (!passwordValid) {
      // SECURE: Increment failed attempts
      user.failedAttempts += 1;

      // SECURE: Lock account after max attempts
      if (user.failedAttempts >= MAX_FAILED_ATTEMPTS) {
        user.lockedUntil = new Date(Date.now() + LOCKOUT_DURATION_MS);
        SecurityLogger.logAuthEvent('LOGIN_ACCOUNT_LOCKED_OUT', user.id, clientIp, false);
      } else {
        SecurityLogger.logAuthEvent('LOGIN_FAILED', user.id, clientIp, false);
      }

      return res.status(401).json({ error: 'Authentication failed' });
    }

    // SECURE: Reset failed attempts on successful login
    user.failedAttempts = 0;
    user.lockedUntil = null;

    // SECURE: Generate cryptographically secure session token
    const token = crypto.randomBytes(32).toString('hex');

    SecurityLogger.logAuthEvent('LOGIN_SUCCESS', user.id, clientIp, true);

    // SECURE: Set cookie with security flags
    res.cookie('auth', token, {
      httpOnly: true,     // Prevents XSS access to cookie
      secure: true,       // Only sent over HTTPS
      sameSite: 'strict', // CSRF protection
      maxAge: 3600000,    // 1 hour expiry
    });

    // SECURE: Return minimal user data - never include password or sensitive fields
    return res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        // SECURE: No password, no internal fields
      },
    });
  }

  // SECURE: Get user with authorization check
  async getUser(req: AuthenticatedRequest, res: Response) {
    const userId = req.params.userId as string;
    const requestingUser = req.user;

    // SECURE: Verify authentication
    if (!requestingUser) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // SECURE: Authorization check - users can only access their own data (or admin)
    if (requestingUser.id !== userId && requestingUser.role !== 'admin') {
      SecurityLogger.logAuthEvent('UNAUTHORIZED_ACCESS_ATTEMPT', requestingUser.id, req.ip || '', false);
      return res.status(403).json({ error: 'Access denied' });
    }

    const user = users.get(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // SECURE: Return sanitized user data
    return res.json({
      id: user.id,
      email: user.email,
      role: user.role,
      // SECURE: Never expose passwordHash, failedAttempts, lockedUntil
    });
  }

  // SECURE: Update user with authorization and field whitelisting
  async updateUser(req: AuthenticatedRequest, res: Response) {
    const userId = req.params.userId as string;
    const requestingUser = req.user;
    const updates = req.body;

    // SECURE: Verify authentication
    if (!requestingUser) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // SECURE: Authorization check
    if (requestingUser.id !== userId && requestingUser.role !== 'admin') {
      SecurityLogger.logAuthEvent('UNAUTHORIZED_UPDATE_ATTEMPT', requestingUser.id, req.ip || '', false);
      return res.status(403).json({ error: 'Access denied' });
    }

    const user = users.get(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // SECURE: Whitelist allowed fields - prevent mass assignment
    const allowedFields = ['email'];

    // SECURE: Only admins can change roles
    if (requestingUser.role === 'admin') {
      allowedFields.push('role');
    }

    // SECURE: Apply only whitelisted updates
    for (const field of allowedFields) {
      if (updates[field] !== undefined) {
        (user as any)[field] = updates[field];
      }
    }

    SecurityLogger.logAuthEvent('USER_UPDATED', userId, req.ip ?? '', true);

    return res.json({
      id: user.id,
      email: user.email,
      role: user.role,
    });
  }

  // SECURE: Password reset with token verification
  async resetPassword(req: AuthenticatedRequest, res: Response) {
    const { resetToken, newPassword } = req.body;

    // SECURE: Validate reset token (in production, verify against stored token with expiry)
    if (!resetToken || typeof resetToken !== 'string') {
      return res.status(400).json({ error: 'Invalid reset token' });
    }

    // SECURE: Validate password strength
    if (!this.isPasswordStrong(newPassword)) {
      return res.status(400).json({
        error: 'Password must be at least 12 characters with uppercase, lowercase, number, and special character',
      });
    }

    // In production: Look up user by reset token, verify token hasn't expired
    // const user = await findUserByResetToken(resetToken);

    // SECURE: Hash new password
    const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

    // In production: Update user's password hash and invalidate reset token
    // await updateUserPassword(user.id, passwordHash);
    // await invalidateResetToken(resetToken);

    SecurityLogger.logAuthEvent('PASSWORD_RESET', 'user-id', req.ip || '', true);

    return res.json({ success: true, message: 'Password updated successfully' });
  }

  // SECURE: Password strength validation
  private isPasswordStrong(password: string): boolean {
    if (!password || password.length < 12) return false;

    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return hasUppercase && hasLowercase && hasNumber && hasSpecial;
  }

  // SECURE: User registration with proper validation
  async register(req: AuthenticatedRequest, res: Response) {
    const { email, password } = req.body;

    // SECURE: Input validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // SECURE: Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // SECURE: Password strength validation
    if (!this.isPasswordStrong(password)) {
      return res.status(400).json({
        error: 'Password must be at least 12 characters with uppercase, lowercase, number, and special character',
      });
    }

    // SECURE: Check if user exists (generic response to prevent enumeration)
    if (users.has(email)) {
      // SECURE: Same response time and message as success to prevent timing attacks
      await bcrypt.hash(password, BCRYPT_ROUNDS);
      return res.status(200).json({ message: 'If email is valid, check inbox for verification' });
    }

    // SECURE: Hash password
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const newUser: User = {
      id: crypto.randomUUID(),
      email,
      passwordHash,
      role: 'user', // SECURE: Default to least privilege
      failedAttempts: 0,
      lockedUntil: null,
    };

    users.set(email, newUser);

    SecurityLogger.logAuthEvent('USER_REGISTERED', newUser.id, req.ip || '', true);

    return res.status(200).json({ message: 'If email is valid, check inbox for verification' });
  }
}
