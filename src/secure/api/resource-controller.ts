/**
 * SECURE: Resource Controller
 *
 * Security Patterns Implemented:
 * - A01: Proper authorization with ownership verification
 * - A05: Secure CORS configuration
 * - A10: SSRF prevention with URL allowlisting
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */

import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';

// SECURE: Type definitions
interface AuthenticatedRequest extends Request {
  user?: { id: string; role: string };
}

interface Resource {
  id: string;
  ownerId: string;
  data: string;
  permissions: Record<string, string[]>;
  createdAt: Date;
}

// SECURE: Configuration
const SECURITY_CONFIG = {
  // Allowed external domains for fetching
  allowedExternalDomains: [
    'api.trusted-partner.com',
    'cdn.example.com',
    'storage.googleapis.com',
  ],
  // Allowed redirect domains
  allowedRedirectDomains: [
    'example.com',
    'www.example.com',
    'app.example.com',
  ],
  // CORS configuration
  allowedOrigins: [
    'https://app.example.com',
    'https://www.example.com',
  ],
};

// Simulated resource store
const resources: Map<string, Resource> = new Map();

// SECURE: Security logger
const logSecurityEvent = (
  event: string,
  userId: string | null,
  req: Request,
  details: Record<string, unknown> = {}
) => {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event,
    userId,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    ...details,
  }));
};

export class SecureResourceController {

  // SECURE: Get resource with authorization check
  async getResource(req: AuthenticatedRequest, res: Response) {
    // SECURE: Require authentication
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const resourceId = req.params.resourceId as string;

    // SECURE: Validate resource ID format
    if (!resourceId || !/^[a-zA-Z0-9_-]+$/.test(resourceId)) {
      return res.status(400).json({ error: 'Invalid resource ID format' });
    }

    const resource = resources.get(resourceId);
    if (!resource) {
      return res.status(404).json({ error: 'Resource not found' });
    }

    // SECURE: Authorization check - verify user has access
    if (!this.hasPermission(req.user, resource, 'read')) {
      logSecurityEvent('UNAUTHORIZED_RESOURCE_ACCESS', req.user.id, req, {
        resourceId,
        action: 'read',
      });
      return res.status(403).json({ error: 'Access denied' });
    }

    return res.json({
      id: resource.id,
      data: resource.data,
      createdAt: resource.createdAt,
      // SECURE: Don't expose full permissions object
    });
  }

  // SECURE: Update permissions with authorization
  async updateResourcePermissions(req: AuthenticatedRequest, res: Response) {
    // SECURE: Require authentication
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const resourceId = req.params.resourceId as string;
    const { permissions } = req.body;

    // SECURE: Validate resource ID
    if (!resourceId || !/^[a-zA-Z0-9_-]+$/.test(resourceId)) {
      return res.status(400).json({ error: 'Invalid resource ID format' });
    }

    const resource = resources.get(resourceId);
    if (!resource) {
      return res.status(404).json({ error: 'Resource not found' });
    }

    // SECURE: Only owner or admin can modify permissions
    if (resource.ownerId !== req.user.id && req.user.role !== 'admin') {
      logSecurityEvent('UNAUTHORIZED_PERMISSION_CHANGE', req.user.id, req, {
        resourceId,
        ownerId: resource.ownerId,
      });
      return res.status(403).json({ error: 'Only resource owner can modify permissions' });
    }

    // SECURE: Validate permissions structure
    if (!this.validatePermissions(permissions)) {
      return res.status(400).json({ error: 'Invalid permissions format' });
    }

    resource.permissions = permissions;

    logSecurityEvent('PERMISSIONS_UPDATED', req.user.id, req, {
      resourceId,
      permissionCount: Object.keys(permissions).length,
    });

    return res.json({ resourceId, message: 'Permissions updated' });
  }

  // SECURE: Fetch external resource with SSRF prevention
  async fetchExternalResource(req: AuthenticatedRequest, res: Response) {
    // SECURE: Require authentication
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { url } = req.body;

    // SECURE: Validate URL format
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // SECURE: Only allow HTTPS
    if (parsedUrl.protocol !== 'https:') {
      logSecurityEvent('SSRF_BLOCKED_PROTOCOL', req.user.id, req, {
        protocol: parsedUrl.protocol,
      });
      return res.status(400).json({ error: 'Only HTTPS URLs are allowed' });
    }

    // SECURE: Check domain allowlist
    if (!SECURITY_CONFIG.allowedExternalDomains.includes(parsedUrl.hostname)) {
      logSecurityEvent('SSRF_BLOCKED_DOMAIN', req.user.id, req, {
        hostname: parsedUrl.hostname,
      });
      return res.status(400).json({
        error: 'Domain not in allowlist',
        allowedDomains: SECURITY_CONFIG.allowedExternalDomains,
      });
    }

    // SECURE: Block internal IP addresses
    // In production: resolve DNS and check against internal ranges
    const blockedPatterns = [
      /^localhost$/i,
      /^127\./,
      /^10\./,
      /^172\.(1[6-9]|2\d|3[01])\./,
      /^192\.168\./,
      /^169\.254\./, // AWS metadata
      /^0\./,
    ];

    for (const pattern of blockedPatterns) {
      if (pattern.test(parsedUrl.hostname)) {
        logSecurityEvent('SSRF_BLOCKED_INTERNAL', req.user.id, req, {
          hostname: parsedUrl.hostname,
        });
        return res.status(400).json({ error: 'Internal addresses not allowed' });
      }
    }

    try {
      // SECURE: Fetch with timeout and redirect disabled
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      const response = await fetch(url, {
        signal: controller.signal,
        redirect: 'error', // SECURE: Don't follow redirects
        headers: {
          'User-Agent': 'SecureApp/1.0',
        },
      });

      clearTimeout(timeout);

      if (!response.ok) {
        return res.status(502).json({ error: 'External request failed' });
      }

      // SECURE: Limit response size
      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > 10 * 1024 * 1024) {
        return res.status(400).json({ error: 'Response too large' });
      }

      const data = await response.text();

      logSecurityEvent('EXTERNAL_FETCH_SUCCESS', req.user.id, req, {
        hostname: parsedUrl.hostname,
        responseSize: data.length,
      });

      return res.json({ data: data.slice(0, 10000) }); // SECURE: Limit response
    } catch (error) {
      return res.status(502).json({ error: 'Failed to fetch external resource' });
    }
  }

  // SECURE: Safe redirect with URL validation
  async redirect(req: AuthenticatedRequest, res: Response) {
    const returnUrl = req.query.returnUrl as string;

    if (!returnUrl) {
      return res.redirect('/');
    }

    // SECURE: Parse and validate URL
    let parsedUrl: URL;
    try {
      // SECURE: Only allow absolute URLs to prevent protocol-relative URLs
      if (!returnUrl.startsWith('https://')) {
        // Allow relative URLs
        if (returnUrl.startsWith('/') && !returnUrl.startsWith('//')) {
          return res.redirect(returnUrl);
        }
        return res.redirect('/');
      }
      parsedUrl = new URL(returnUrl);
    } catch {
      return res.redirect('/');
    }

    // SECURE: Check domain allowlist for external redirects
    if (!SECURITY_CONFIG.allowedRedirectDomains.includes(parsedUrl.hostname)) {
      logSecurityEvent('OPEN_REDIRECT_BLOCKED', req.user?.id || null, req, {
        targetDomain: parsedUrl.hostname,
      });
      return res.redirect('/');
    }

    return res.redirect(returnUrl);
  }

  // SECURE: CORS endpoint with proper configuration
  async corsEndpoint(req: AuthenticatedRequest, res: Response) {
    const origin = req.get('origin');

    // SECURE: Check origin against allowlist
    if (origin && SECURITY_CONFIG.allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
    }
    // SECURE: If origin not in allowlist, don't set CORS headers (request will fail)

    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }

    return res.json({ message: 'Secure CORS endpoint' });
  }

  // SECURE: Permission checking helper
  private hasPermission(user: { id: string; role: string }, resource: Resource, action: string): boolean {
    // Admin has all permissions
    if (user.role === 'admin') return true;

    // Owner has all permissions
    if (resource.ownerId === user.id) return true;

    // Check explicit permissions
    const userPermissions = resource.permissions[user.id];
    if (userPermissions && userPermissions.includes(action)) return true;

    return false;
  }

  // SECURE: Validate permissions structure
  private validatePermissions(permissions: unknown): permissions is Record<string, string[]> {
    if (typeof permissions !== 'object' || permissions === null) return false;

    for (const [userId, actions] of Object.entries(permissions)) {
      // Validate user ID format
      if (!/^[a-zA-Z0-9_-]+$/.test(userId)) return false;

      // Validate actions array
      if (!Array.isArray(actions)) return false;

      const validActions = ['read', 'write', 'delete', 'admin'];
      for (const action of actions) {
        if (!validActions.includes(action)) return false;
      }
    }

    return true;
  }
}

// SECURE: CORS middleware factory
export const createCorsMiddleware = (allowedOrigins: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const origin = req.get('origin');

    if (origin && allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Vary', 'Origin');
    }

    next();
  };
};
