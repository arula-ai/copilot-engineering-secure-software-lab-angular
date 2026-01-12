/**
 * VULNERABLE: Authentication Controller
 *
 * Security Issues Present:
 * - A01: Broken Access Control
 * - A02: Cryptographic Failures
 * - A07: Authentication Failures
 * - A09: Security Logging Failures
 *
 * DO NOT USE IN PRODUCTION
 */

import { Request, Response } from 'express';

interface User {
  id: string;
  email: string;
  password: string; // VULN: Stored in plain text
  role: string;
}

// VULN: In-memory storage with plain text passwords
const users: User[] = [
  { id: '1', email: 'admin@example.com', password: 'admin123', role: 'admin' },
  { id: '2', email: 'user@example.com', password: 'password', role: 'user' }
];

export class AuthController {

  // VULN: Multiple authentication vulnerabilities
  async login(req: Request, res: Response) {
    const { email, password } = req.body;

    // VULN: No input validation
    // VULN: No rate limiting
    // VULN: SQL injection possible if connected to DB
    const user = users.find(u => u.email === email && u.password === password);

    if (user) {
      // VULN: Sensitive data in response
      // VULN: Weak token generation
      const token = Buffer.from(`${user.id}:${user.role}`).toString('base64');

      // VULN: Logging password
      console.log(`Login successful for ${email} with password ${password}`);

      // VULN: No httpOnly, no secure flag
      res.cookie('auth', token);

      return res.json({
        success: true,
        token,
        user: user // VULN: Returns password in response
      });
    }

    // VULN: User enumeration possible
    return res.status(401).json({
      error: `User ${email} not found`
    });
  }

  // VULN: No authorization check
  async getUser(req: Request, res: Response) {
    const { userId } = req.params;
    // VULN: IDOR - Any user can access any other user's data
    const user = users.find(u => u.id === userId);
    return res.json(user);
  }

  // VULN: Mass assignment vulnerability
  async updateUser(req: Request, res: Response) {
    const { userId } = req.params;
    const updates = req.body;

    const userIndex = users.findIndex(u => u.id === userId);
    if (userIndex >= 0) {
      // VULN: Can update role without authorization
      users[userIndex] = { ...users[userIndex], ...updates };
      return res.json(users[userIndex]);
    }
    return res.status(404).json({ error: 'Not found' });
  }

  // VULN: Password reset without proper verification
  async resetPassword(req: Request, res: Response) {
    const { email, newPassword } = req.body;

    // VULN: No token verification
    // VULN: No password strength validation
    // VULN: No old password verification
    const userIndex = users.findIndex(u => u.email === email);
    if (userIndex >= 0) {
      users[userIndex].password = newPassword;
      return res.json({ success: true });
    }
    return res.status(404).json({ error: 'Not found' });
  }
}
