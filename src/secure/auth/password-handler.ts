/**
 * SECURE: Password Handler
 *
 * Security Patterns Implemented:
 * - A02: Strong cryptographic hashing (bcrypt with appropriate cost)
 * - A07: Password strength validation, timing-safe comparison
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */

import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

// SECURE: Bcrypt cost factor - adjust based on server capability
// Cost 12 = ~250ms on modern hardware, good balance of security/performance
const BCRYPT_COST = 12;

// SECURE: Password policy configuration
const PASSWORD_POLICY = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  maxLength: 128, // Prevent DoS via extremely long passwords
};

export class SecurePasswordHandler {

  // SECURE: Hash password using bcrypt with appropriate cost factor
  async hashPassword(password: string): Promise<string> {
    // SECURE: Validate password length to prevent DoS
    if (password.length > PASSWORD_POLICY.maxLength) {
      throw new Error('Password exceeds maximum length');
    }

    // SECURE: bcrypt automatically generates a unique salt per hash
    return bcrypt.hash(password, BCRYPT_COST);
  }

  // SECURE: Comprehensive password strength validation
  validatePasswordStrength(password: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!password) {
      return { valid: false, errors: ['Password is required'] };
    }

    if (password.length < PASSWORD_POLICY.minLength) {
      errors.push(`Password must be at least ${PASSWORD_POLICY.minLength} characters`);
    }

    if (password.length > PASSWORD_POLICY.maxLength) {
      errors.push(`Password must not exceed ${PASSWORD_POLICY.maxLength} characters`);
    }

    if (PASSWORD_POLICY.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (PASSWORD_POLICY.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (PASSWORD_POLICY.requireNumbers && !/[0-9]/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (PASSWORD_POLICY.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/`~]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    // SECURE: Check for common weak patterns
    const commonPatterns = [
      /^(.)\1+$/,           // All same character
      /^123456/,            // Sequential numbers
      /^password/i,         // Contains 'password'
      /^qwerty/i,           // Keyboard pattern
    ];

    for (const pattern of commonPatterns) {
      if (pattern.test(password)) {
        errors.push('Password contains a common weak pattern');
        break;
      }
    }

    return { valid: errors.length === 0, errors };
  }

  // SECURE: Timing-safe password comparison using bcrypt
  async comparePasswords(inputPassword: string, storedHash: string): Promise<boolean> {
    // SECURE: bcrypt.compare is timing-safe by design
    // It always takes the same amount of time regardless of where comparison fails
    try {
      return await bcrypt.compare(inputPassword, storedHash);
    } catch {
      // SECURE: Return false on any error, don't expose error details
      return false;
    }
  }

  // SECURE: Generate cryptographically secure temporary password
  generateTemporaryPassword(): string {
    // SECURE: Use crypto.randomBytes for unpredictable values
    const bytes = crypto.randomBytes(16);

    // SECURE: Convert to base64url (URL-safe, no special chars that cause issues)
    const tempPassword = bytes.toString('base64url');

    // SECURE: Ensure it meets password policy by adding required char types
    // This is for temporary passwords that will be changed immediately
    return `T${tempPassword}1!`;
  }

  // SECURE: Generate secure password reset token
  generateResetToken(): { token: string; expiresAt: Date } {
    // SECURE: Use crypto.randomBytes for 32 bytes of entropy
    const token = crypto.randomBytes(32).toString('hex');

    // SECURE: Token expires in 1 hour
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

    return { token, expiresAt };
  }

  // SECURE: Hash reset token for storage (don't store plain tokens)
  hashResetToken(token: string): string {
    // SECURE: Use SHA-256 for token hashing (fast, one-way)
    // bcrypt not needed here since tokens are high-entropy random values
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  // SECURE: Check if password was recently used (password history)
  async isPasswordInHistory(
    password: string,
    hashedHistory: string[]
  ): Promise<boolean> {
    // SECURE: Check against hashed history, not plain text
    for (const historicHash of hashedHistory) {
      if (await bcrypt.compare(password, historicHash)) {
        return true;
      }
    }
    return false;
  }
}
