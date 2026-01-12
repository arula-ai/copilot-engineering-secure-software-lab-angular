/**
 * VULNERABLE: Password Handler
 *
 * Security Issues:
 * - A02: Cryptographic Failures (weak hashing, no salt)
 * - A07: Identification and Authentication Failures
 */

import * as crypto from 'crypto';

export class PasswordHandler {

  // VULN: MD5 is cryptographically broken
  hashPassword(password: string): string {
    return crypto.createHash('md5').update(password).digest('hex');
  }

  // VULN: No password strength validation
  validatePasswordStrength(password: string): boolean {
    // Only checks length - no complexity requirements
    return password.length >= 4;
  }

  // VULN: Timing attack vulnerability
  comparePasswords(input: string, stored: string): boolean {
    return this.hashPassword(input) === stored;
  }

  // VULN: Predictable password generation
  generateTemporaryPassword(): string {
    // Uses predictable sequence
    return 'temp' + Date.now().toString().slice(-4);
  }

  // VULN: Stores password history in plain text
  private passwordHistory: Map<string, string[]> = new Map();

  addToHistory(userId: string, password: string): void {
    const history = this.passwordHistory.get(userId) || [];
    history.push(password); // Plain text!
    this.passwordHistory.set(userId, history);
  }
}
