/**
 * SECURE: User API
 *
 * Security Patterns Implemented:
 * - A01: Proper authentication and authorization
 * - A03: Input validation
 * - A05: Secure configuration (no debug endpoints)
 * - A09: Proper error handling without information leakage
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */

import { Request, Response, Router, NextFunction } from 'express';
import * as crypto from 'crypto';

// SECURE: Type definitions
interface AuthenticatedRequest extends Request {
  user?: { id: string; role: string };
}

interface User {
  id: string;
  email: string;
  role: string;
  createdAt: Date;
}

// SECURE: Simulated user store
const users: Map<string, User> = new Map();

// SECURE: Security logger
const logSecurityEvent = (event: string, req: Request, details: Record<string, unknown> = {}) => {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    requestId: req.headers['x-request-id'] || crypto.randomUUID(),
    ...details,
    // SECURE: Never log sensitive data
  }));
};

// SECURE: Authentication middleware
const requireAuth = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // In production: Verify JWT or session token
  // const user = await verifyToken(token);

  // Simulated for demo
  req.user = { id: 'user-123', role: 'user' };
  next();
};

// SECURE: Authorization middleware
const requireRole = (...roles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!roles.includes(req.user.role)) {
      logSecurityEvent('AUTHORIZATION_FAILURE', req, {
        userId: req.user.id,
        requiredRoles: roles,
        actualRole: req.user.role,
      });
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
};

export const secureUserRouter = Router();

// SECURE: List users - requires authentication and admin role
secureUserRouter.get('/users', requireAuth, requireRole('admin'), async (req: AuthenticatedRequest, res: Response) => {
  // SECURE: Pagination to prevent data dumps
  const page = Math.max(1, parseInt(req.query.page as string) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 20));

  const allUsers = Array.from(users.values());
  const paginatedUsers = allUsers.slice((page - 1) * limit, page * limit);

  // SECURE: Return only necessary fields
  const sanitizedUsers = paginatedUsers.map(user => ({
    id: user.id,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt,
    // SECURE: No password, no internal fields
  }));

  res.json({
    users: sanitizedUsers,
    pagination: {
      page,
      limit,
      total: allUsers.length,
      totalPages: Math.ceil(allUsers.length / limit),
    },
  });
});

// SECURE: Get user by ID - requires auth and ownership check
secureUserRouter.get('/users/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const id = req.params.id as string;

  // SECURE: Validate ID format
  if (!id || !/^[a-zA-Z0-9_-]+$/.test(id)) {
    return res.status(400).json({ error: 'Invalid user ID format' });
  }

  // SECURE: Authorization check - users can only access their own data (or admin)
  if (req.user!.id !== id && req.user!.role !== 'admin') {
    logSecurityEvent('IDOR_ATTEMPT', req, { targetUserId: id, requestingUserId: req.user!.id });
    return res.status(403).json({ error: 'Access denied' });
  }

  const user = users.get(id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // SECURE: Return sanitized data
  res.json({
    id: user.id,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt,
  });
});

// SECURE: Update user - requires auth, ownership, and field whitelisting
secureUserRouter.put('/users/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const id = req.params.id as string;
  const updates = req.body;

  // SECURE: Validate ID format
  if (!id || !/^[a-zA-Z0-9_-]+$/.test(id)) {
    return res.status(400).json({ error: 'Invalid user ID format' });
  }

  // SECURE: Authorization check
  if (req.user!.id !== id && req.user!.role !== 'admin') {
    logSecurityEvent('UNAUTHORIZED_UPDATE_ATTEMPT', req, { targetUserId: id });
    return res.status(403).json({ error: 'Access denied' });
  }

  const user = users.get(id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // SECURE: Whitelist allowed fields - prevent mass assignment
  const allowedFields = ['email'];

  // SECURE: Only admins can change roles
  if (req.user!.role === 'admin') {
    allowedFields.push('role');
  }

  // SECURE: Validate and apply updates
  for (const field of allowedFields) {
    if (updates[field] !== undefined) {
      // SECURE: Type validation for each field
      if (field === 'email') {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(updates[field])) {
          return res.status(400).json({ error: 'Invalid email format' });
        }
      }
      if (field === 'role' && !['user', 'admin'].includes(updates[field])) {
        return res.status(400).json({ error: 'Invalid role' });
      }
      (user as any)[field] = updates[field];
    }
  }

  logSecurityEvent('USER_UPDATED', req, { userId: id, updatedFields: allowedFields.filter(f => updates[f] !== undefined) });

  res.json({
    id: user.id,
    email: user.email,
    role: user.role,
  });
});

// SECURE: Search users with input validation
secureUserRouter.post('/users/search', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { query } = req.body;

    // SECURE: Validate search query
    if (!query || typeof query !== 'string') {
      return res.status(400).json({ error: 'Search query is required' });
    }

    // SECURE: Limit query length
    if (query.length > 100) {
      return res.status(400).json({ error: 'Search query too long' });
    }

    // SECURE: Sanitize query for safe searching
    const sanitizedQuery = query.toLowerCase().replace(/[^a-z0-9@._-]/g, '');

    // SECURE: Perform search (in production, use parameterized database query)
    const results = Array.from(users.values())
      .filter(u => u.email.toLowerCase().includes(sanitizedQuery))
      .slice(0, 20) // SECURE: Limit results
      .map(u => ({
        id: u.id,
        email: u.email,
        role: u.role,
      }));

    res.json({ results });
  } catch (error) {
    // SECURE: Log error internally but don't expose details
    console.error('Search error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// SECURE: Email check with timing-attack prevention
secureUserRouter.post('/users/check-email', async (req: Request, res: Response) => {
  const { email } = req.body;

  // SECURE: Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email)) {
    return res.status(400).json({ error: 'Valid email required' });
  }

  // SECURE: Add artificial delay to prevent timing attacks
  await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 100));

  // SECURE: Generic response prevents user enumeration
  res.json({
    message: 'If this email is available, you may proceed with registration',
    // SECURE: Don't reveal whether email exists
  });
});

// SECURE: NO debug endpoints in production code
// Debug endpoints should be:
// 1. In a separate module that's excluded from production builds
// 2. Protected by strong authentication
// 3. IP-restricted to internal networks only
// 4. Logged and monitored

// SECURE: Error handling middleware
export const errorHandler = (err: Error, req: Request, res: Response, next: NextFunction) => {
  // SECURE: Log full error internally
  console.error('Unhandled error:', {
    message: err.message,
    stack: err.stack,
    requestId: req.headers['x-request-id'],
  });

  // SECURE: Return generic error to client
  res.status(500).json({
    error: 'An unexpected error occurred',
    requestId: req.headers['x-request-id'],
    // SECURE: No stack trace, no internal details
  });
};
