/**
 * SECURE: Safe Redirect Handling
 *
 * Security Controls:
 * - A01: Broken Access Control Prevention
 *
 * This component demonstrates SECURE redirect handling patterns
 * that prevent open redirect vulnerabilities.
 *
 * SAFE FOR PRODUCTION (with proper configuration)
 */

import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';

// Allowlist of safe redirect paths (internal only)
const ALLOWED_PATHS = [
  '/',
  '/dashboard',
  '/profile',
  '/settings',
  '/account',
  '/orders'
];

// Allowlist of trusted external domains (if any external redirects needed)
const TRUSTED_EXTERNAL_DOMAINS = [
  'docs.yoursite.com',
  'help.yoursite.com'
];

@Component({
  selector: 'app-secure-redirect-handler',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="security-demo">
      <div class="header">
        <h2>SECURE: Safe Redirect Handling</h2>
        <span class="badge success">A01: Access Control</span>
      </div>

      <div class="description">
        <p>
          This component demonstrates secure redirect handling patterns that
          prevent open redirect vulnerabilities and phishing attacks.
        </p>
      </div>

      <div class="demo-section">
        <h3>Login Return URL (Validated)</h3>
        <p class="context">After login, users are redirected only to allowed paths...</p>

        <div class="input-group">
          <label for="returnUrl">Return URL:</label>
          <input
            id="returnUrl"
            type="text"
            [(ngModel)]="returnUrl"
            placeholder="/dashboard"
          >
        </div>

        <button (click)="handleRedirect()">Validate & Redirect</button>

        @if (validationResult) {
          <div class="validation-result" [class.valid]="isUrlValid" [class.blocked]="!isUrlValid">
            <p><strong>Status:</strong> {{ validationResult.status }}</p>
            <p><strong>Reason:</strong> {{ validationResult.reason }}</p>
            @if (isUrlValid) {
              <p><strong>Safe redirect to:</strong> <code>{{ validationResult.safePath }}</code></p>
            }
          </div>
        }

        <div class="allowed-paths">
          <h4>Allowed Internal Paths:</h4>
          <ul>
            @for (path of allowedPaths; track path) {
              <li><code>{{ path }}</code></li>
            }
          </ul>
        </div>
      </div>

      <div class="demo-section">
        <h3>Attack Payload Tests</h3>
        <p class="context">Test that malicious redirects are blocked...</p>

        <div class="payload-buttons">
          <button (click)="testPayload('external')">External Site</button>
          <button (click)="testPayload('javascript')">JavaScript URL</button>
          <button (click)="testPayload('data')">Data URL</button>
          <button (click)="testPayload('encoded')">URL Encoded</button>
          <button (click)="testPayload('doubleSlash')">Protocol-relative</button>
        </div>

        @if (testResult) {
          <div class="test-result success">
            <p><strong>Payload:</strong> <code>{{ testResult.payload }}</code></p>
            <p><strong>Result:</strong> {{ testResult.result }}</p>
            <span class="success-text">Attack blocked!</span>
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>Safe Navigation</h3>
        <p class="context">Navigation restricted to internal routes...</p>

        <div class="input-group">
          <label for="navTarget">Navigate to:</label>
          <select id="navTarget" [(ngModel)]="navTarget">
            <option value="">Select destination</option>
            @for (path of allowedPaths; track path) {
              <option [value]="path">{{ path }}</option>
            }
          </select>
        </div>

        <button (click)="navigate()">Navigate Safely</button>

        @if (navResult) {
          <div class="nav-result success">{{ navResult }}</div>
        }
      </div>

      <div class="code-section">
        <h3>Secure Implementation</h3>
        <pre><code>{{ secureCode }}</code></pre>
      </div>

      <div class="explanation">
        <h3>Security Controls Applied</h3>
        <ul>
          <li><strong>Path allowlist:</strong> Only predefined internal paths are allowed</li>
          <li><strong>No external redirects:</strong> URLs starting with http/https are blocked</li>
          <li><strong>Protocol blocking:</strong> javascript:, data:, and other dangerous protocols rejected</li>
          <li><strong>Encoded URL handling:</strong> URLs are decoded before validation</li>
          <li><strong>Router.navigate:</strong> Using Angular Router instead of window.location</li>
          <li><strong>Default fallback:</strong> Invalid URLs redirect to safe default (home)</li>
        </ul>
      </div>
    </div>
  `,
  styles: [`
    .security-demo { max-width: 800px; }
    .header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
    .header h2 { margin: 0; color: #28a745; }
    .badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .badge.success { background: #28a745; color: white; }
    .description { background: #d4edda; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; border-left: 4px solid #28a745; }
    .demo-section { background: #f8f9fa; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; }
    .demo-section h3 { margin-top: 0; }
    .context { color: #666; font-style: italic; }
    .input-group { margin-bottom: 1rem; }
    .input-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
    .input-group input, .input-group select { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
    button { padding: 0.75rem 1.5rem; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; margin-right: 0.5rem; margin-bottom: 0.5rem; }
    .validation-result { margin-top: 1rem; padding: 1rem; border-radius: 4px; }
    .validation-result.valid { background: #d4edda; border: 1px solid #28a745; }
    .validation-result.blocked { background: #f8d7da; border: 1px solid #dc3545; }
    .validation-result code { background: #e9ecef; padding: 0.125rem 0.375rem; border-radius: 4px; }
    .allowed-paths { margin-top: 1.5rem; padding: 1rem; background: white; border-radius: 4px; border: 1px solid #ddd; }
    .allowed-paths h4 { margin-top: 0; }
    .allowed-paths ul { margin: 0; padding-left: 1.5rem; }
    .allowed-paths code { background: #d4edda; padding: 0.125rem 0.375rem; border-radius: 4px; }
    .payload-buttons button { background: #6c757d; }
    .test-result { margin-top: 1rem; padding: 1rem; border-radius: 4px; }
    .test-result.success { background: #d4edda; }
    .test-result code { word-break: break-all; background: #c3e6cb; padding: 0.125rem 0.375rem; border-radius: 4px; }
    .success-text { color: #155724; font-weight: 600; display: block; margin-top: 0.5rem; }
    .nav-result { margin-top: 1rem; padding: 1rem; border-radius: 4px; }
    .nav-result.success { background: #d4edda; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #d4edda; padding: 1rem; border-radius: 8px; border-left: 4px solid #28a745; }
    .explanation h3 { margin-top: 0; }
  `]
})
export class SecureRedirectHandlerComponent implements OnInit {
  returnUrl = '';
  navTarget = '';
  validationResult: { status: string; reason: string; safePath?: string } | null = null;
  isUrlValid = false;
  testResult: { payload: string; result: string } | null = null;
  navResult = '';

  allowedPaths = ALLOWED_PATHS;

  private attackPayloads: Record<string, string> = {
    external: 'https://evil-site.com/fake-login',
    javascript: 'javascript:alert(document.cookie)',
    data: 'data:text/html,<script>alert("XSS")</script>',
    encoded: 'https://evil.com%2F%2Eyoursite.com',
    doubleSlash: '//evil.com/path'
  };

  secureCode = `
// SECURE: Redirect handling with allowlist

// Allowlist of permitted redirect paths
const ALLOWED_PATHS = ['/dashboard', '/profile', '/settings'];

// Validate redirect URL
validateRedirectUrl(url: string): { valid: boolean; safePath: string; reason: string } {
  // Default safe path
  const defaultPath = '/';

  if (!url) {
    return { valid: false, safePath: defaultPath, reason: 'Empty URL' };
  }

  // Decode URL to catch encoded attacks
  let decoded: string;
  try {
    decoded = decodeURIComponent(url);
  } catch {
    return { valid: false, safePath: defaultPath, reason: 'Invalid encoding' };
  }

  // Block absolute URLs and dangerous protocols
  const dangerous = [
    /^https?:\\/\\//i,      // http:// or https://
    /^javascript:/i,       // javascript:
    /^data:/i,             // data:
    /^\\/\\//,               // Protocol-relative //
    /^[a-z]+:/i            // Any other protocol
  ];

  for (const pattern of dangerous) {
    if (pattern.test(decoded)) {
      return { valid: false, safePath: defaultPath, reason: 'Blocked protocol/URL' };
    }
  }

  // Normalize path
  const normalizedPath = decoded.split('?')[0].split('#')[0];

  // Check against allowlist
  if (!ALLOWED_PATHS.includes(normalizedPath)) {
    return { valid: false, safePath: defaultPath, reason: 'Path not in allowlist' };
  }

  return { valid: true, safePath: decoded, reason: 'URL is safe' };
}

// Safe navigation using Angular Router (not window.location)
safeNavigate(path: string) {
  const result = this.validateRedirectUrl(path);
  this.router.navigateByUrl(result.safePath);
}
  `.trim();

  constructor(
    private route: ActivatedRoute,
    private router: Router
  ) {}

  ngOnInit(): void {
    // SECURE: Validate returnUrl from query params
    this.route.queryParams.subscribe(params => {
      if (params['returnUrl']) {
        this.returnUrl = params['returnUrl'];
        // Automatically validate on load
        const result = this.validateRedirectUrl(this.returnUrl);
        this.validationResult = {
          status: result.valid ? 'Valid' : 'Blocked',
          reason: result.reason,
          safePath: result.safePath
        };
        this.isUrlValid = result.valid;
      }
    });
  }

  handleRedirect(): void {
    if (!this.returnUrl) {
      this.validationResult = { status: 'Invalid', reason: 'Please enter a URL' };
      this.isUrlValid = false;
      return;
    }

    const result = this.validateRedirectUrl(this.returnUrl);
    this.validationResult = {
      status: result.valid ? 'Valid' : 'Blocked',
      reason: result.reason,
      safePath: result.safePath
    };
    this.isUrlValid = result.valid;

    if (result.valid) {
      // In a real app, would navigate here:
      // this.router.navigateByUrl(result.safePath);
      console.log('Would safely navigate to:', result.safePath);
    }
  }

  navigate(): void {
    if (!this.navTarget) {
      this.navResult = 'Please select a destination';
      return;
    }

    // SECURE: Using Angular Router, not window.location
    // The select only contains allowed paths, but we validate anyway
    const result = this.validateRedirectUrl(this.navTarget);

    if (result.valid) {
      this.navResult = `Safe navigation to: ${result.safePath}`;
      // this.router.navigateByUrl(result.safePath);
    } else {
      this.navResult = `Blocked: ${result.reason}`;
    }
  }

  testPayload(type: string): void {
    const payload = this.attackPayloads[type];
    if (!payload) return;

    const result = this.validateRedirectUrl(payload);

    this.testResult = {
      payload,
      result: result.valid
        ? 'UNEXPECTED: URL was allowed!'
        : `Blocked: ${result.reason}. Would redirect to: ${result.safePath}`
    };
  }

  private validateRedirectUrl(url: string): { valid: boolean; safePath: string; reason: string } {
    const defaultPath = '/';

    if (!url) {
      return { valid: false, safePath: defaultPath, reason: 'Empty URL' };
    }

    // Decode URL to catch encoded attacks (e.g., %2F%2F = //)
    let decoded: string;
    try {
      decoded = decodeURIComponent(url);
      // Decode again to catch double-encoding
      decoded = decodeURIComponent(decoded);
    } catch {
      return { valid: false, safePath: defaultPath, reason: 'Invalid URL encoding' };
    }

    // Trim and normalize
    decoded = decoded.trim();

    // Block dangerous patterns
    const dangerousPatterns = [
      { pattern: /^https?:\/\//i, reason: 'External URL (http/https)' },
      { pattern: /^javascript:/i, reason: 'JavaScript URL' },
      { pattern: /^data:/i, reason: 'Data URL' },
      { pattern: /^vbscript:/i, reason: 'VBScript URL' },
      { pattern: /^\/\//, reason: 'Protocol-relative URL' },
      { pattern: /^[a-z][a-z0-9+.-]*:/i, reason: 'Unknown protocol' },
      { pattern: /[\r\n]/, reason: 'Line breaks in URL' },
      { pattern: /\\/, reason: 'Backslashes in URL' }
    ];

    for (const { pattern, reason } of dangerousPatterns) {
      if (pattern.test(decoded)) {
        return { valid: false, safePath: defaultPath, reason };
      }
    }

    // Extract path without query string and fragment
    const path = decoded.split('?')[0].split('#')[0];

    // Normalize multiple slashes
    const normalizedPath = '/' + path.replace(/^\/+/, '').replace(/\/+/g, '/');

    // Check against allowlist
    const isAllowed = ALLOWED_PATHS.some(allowed =>
      normalizedPath === allowed || normalizedPath.startsWith(allowed + '/')
    );

    if (!isAllowed) {
      return {
        valid: false,
        safePath: defaultPath,
        reason: `Path "${normalizedPath}" not in allowlist`
      };
    }

    return { valid: true, safePath: decoded, reason: 'URL passed validation' };
  }
}
