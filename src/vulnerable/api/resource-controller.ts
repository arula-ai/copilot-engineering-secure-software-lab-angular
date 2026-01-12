/**
 * VULNERABLE: Resource Controller
 *
 * Security Issues:
 * - A01: Broken Access Control
 * - A05: Security Misconfiguration
 * - A10: Server-Side Request Forgery (SSRF)
 */

import { Request, Response } from 'express';

export class ResourceController {

  // VULN: No access control
  async getResource(req: Request, res: Response) {
    const { resourceId } = req.params;
    // Anyone can access any resource
    return res.json({ id: resourceId, data: 'sensitive data' });
  }

  // VULN: Privilege escalation
  async updateResourcePermissions(req: Request, res: Response) {
    const { resourceId } = req.params;
    const { permissions } = req.body;
    // No check if user can modify permissions
    return res.json({ resourceId, permissions });
  }

  // VULN: SSRF - Server-Side Request Forgery
  async fetchExternalResource(req: Request, res: Response) {
    const { url } = req.body;

    // VULN: No URL validation - can access internal services
    // Examples of malicious URLs:
    // - http://169.254.169.254/latest/meta-data/ (AWS metadata)
    // - http://localhost:8080/admin
    // - file:///etc/passwd

    try {
      const response = await fetch(url);
      const data = await response.text();
      return res.json({ data });
    } catch (error) {
      return res.status(500).json({ error: 'Fetch failed' });
    }
  }

  // VULN: Unsafe redirect
  async redirect(req: Request, res: Response) {
    const { returnUrl } = req.query;
    // VULN: Open redirect - can redirect to malicious site
    return res.redirect(returnUrl as string);
  }

  // VULN: CORS misconfiguration
  async corsEndpoint(req: Request, res: Response) {
    // Allows any origin
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    return res.json({ secret: 'data' });
  }
}
