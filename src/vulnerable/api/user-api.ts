/**
 * VULNERABLE: User API
 *
 * Security Issues:
 * - A01: Broken Access Control
 * - A03: Injection
 * - A05: Security Misconfiguration
 * - A09: Security Logging and Monitoring Failures
 */

import { Request, Response, Router } from 'express';

export const userRouter = Router();

// VULN: No authentication required
userRouter.get('/users', async (req: Request, res: Response) => {
  // Returns all users including sensitive data
  const users = [
    { id: 1, email: 'admin@example.com', password: 'hashed', ssn: '123-45-6789' }
  ];
  res.json(users);
});

// VULN: IDOR - No authorization check
userRouter.get('/users/:id', async (req: Request, res: Response) => {
  const { id } = req.params;
  // Any user can access any other user's data
  res.json({ id, email: 'user@example.com', role: 'admin' });
});

// VULN: Mass assignment
userRouter.put('/users/:id', async (req: Request, res: Response) => {
  const { id } = req.params;
  const updates = req.body;
  // Can update role, permissions, etc.
  res.json({ id, ...updates });
});

// VULN: No input validation, verbose errors
userRouter.post('/users/search', async (req: Request, res: Response) => {
  try {
    const { query } = req.body;
    // Direct query execution
    throw new Error(`Database error: SELECT * FROM users WHERE ${query}`);
  } catch (error: any) {
    // VULN: Exposes internal details
    res.status(500).json({
      error: error.message,
      stack: error.stack
    });
  }
});

// VULN: Rate limiting absent, account enumeration
userRouter.post('/users/check-email', async (req: Request, res: Response) => {
  const { email } = req.body;
  const exists = email === 'admin@example.com';
  // Reveals whether email exists
  res.json({ exists, message: exists ? 'Email taken' : 'Email available' });
});

// VULN: Debug endpoint in production
userRouter.get('/debug/users', async (req: Request, res: Response) => {
  res.json({
    databaseConnection: 'postgres://admin:password123@localhost/db',
    apiKey: 'sk-secret-api-key-12345',
    users: []
  });
});
