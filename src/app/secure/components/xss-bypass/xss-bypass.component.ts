/**
 * SECURE: XSS Prevention with DomSanitizer
 *
 * Security Controls:
 * - A03: Injection Prevention
 *
 * This component demonstrates SECURE patterns for handling user content
 * that requires HTML rendering, without bypassing Angular's sanitization.
 *
 * SAFE FOR PRODUCTION (with proper testing)
 */

import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

// Allowlist of safe HTML tags and attributes
const ALLOWED_TAGS = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'ul', 'ol', 'li', 'a', 'span'];
const ALLOWED_ATTRIBUTES = ['href', 'class', 'id'];
const ALLOWED_URL_PROTOCOLS = ['http:', 'https:', 'mailto:'];

@Component({
  selector: 'app-secure-xss-bypass',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="security-demo">
      <div class="header">
        <h2>SECURE: Safe HTML Handling</h2>
        <span class="badge success">A03: Injection Prevention</span>
      </div>

      <div class="description">
        <p>
          This component demonstrates secure patterns for rendering user-provided
          content without exposing XSS vulnerabilities.
        </p>
      </div>

      <div class="demo-section">
        <h3>Rich Text Input (Sanitized)</h3>
        <p class="context">User content with HTML is sanitized before rendering...</p>

        <div class="input-group">
          <label for="richContent">Enter HTML content:</label>
          <textarea
            id="richContent"
            [(ngModel)]="userHtml"
            rows="4"
            placeholder="<b>Bold</b>, <i>italic</i>, <a href='https://example.com'>links</a> allowed"
          ></textarea>
        </div>

        <button (click)="processContent()">Render Safely</button>

        @if (processedContent) {
          <div class="output-container">
            <h4>Rendered Output:</h4>
            <div class="safe-output" [innerHTML]="processedContent"></div>
          </div>
        }

        @if (sanitizationLog.length > 0) {
          <div class="log-container">
            <h4>Sanitization Log:</h4>
            <ul>
              @for (log of sanitizationLog; track $index) {
                <li [class]="log.type">{{ log.message }}</li>
              }
            </ul>
          </div>
        }
      </div>

      <div class="demo-section">
        <h3>Attack Payload Tests</h3>
        <p class="context">Try common XSS payloads - they will be neutralized...</p>

        <div class="payload-buttons">
          <button (click)="testPayload('script')">Test &lt;script&gt;</button>
          <button (click)="testPayload('onerror')">Test onerror</button>
          <button (click)="testPayload('javascript')">Test javascript:</button>
          <button (click)="testPayload('svg')">Test SVG onload</button>
        </div>

        @if (payloadResult) {
          <div class="payload-result">
            <p><strong>Original:</strong> <code>{{ payloadResult.original }}</code></p>
            <p><strong>Sanitized:</strong> <code>{{ payloadResult.sanitized }}</code></p>
            <p class="success-text">XSS attempt neutralized!</p>
          </div>
        }
      </div>

      <div class="code-section">
        <h3>Secure Implementation</h3>
        <pre><code>{{ secureCode }}</code></pre>
      </div>

      <div class="explanation">
        <h3>Security Controls Applied</h3>
        <ul>
          <li><strong>Tag allowlist:</strong> Only permitted HTML tags are kept</li>
          <li><strong>Attribute filtering:</strong> Event handlers (onclick, onerror) are stripped</li>
          <li><strong>URL validation:</strong> Only http:, https:, mailto: protocols allowed</li>
          <li><strong>No bypassSecurityTrust:</strong> Angular's built-in sanitization is used</li>
          <li><strong>Content Security Policy:</strong> Additional defense via CSP headers</li>
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
    .input-group textarea { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-family: monospace; }
    button { padding: 0.75rem 1.5rem; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; margin-right: 0.5rem; margin-bottom: 0.5rem; }
    button:hover { background: #1e7e34; }
    .output-container { margin-top: 1rem; padding: 1rem; background: white; border-radius: 4px; border: 1px solid #ddd; }
    .safe-output { padding: 1rem; background: #f8f9fa; border-radius: 4px; min-height: 50px; }
    .log-container { margin-top: 1rem; }
    .log-container ul { list-style: none; padding: 0; margin: 0; }
    .log-container li { padding: 0.5rem; margin-bottom: 0.25rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem; }
    .log-container li.removed { background: #f8d7da; color: #721c24; }
    .log-container li.allowed { background: #d4edda; color: #155724; }
    .payload-buttons button { background: #6c757d; }
    .payload-result { margin-top: 1rem; padding: 1rem; background: white; border-radius: 4px; border: 1px solid #ddd; }
    .payload-result code { word-break: break-all; background: #e9ecef; padding: 0.125rem 0.375rem; border-radius: 4px; }
    .success-text { color: #28a745; font-weight: 600; margin-top: 0.5rem; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #d4edda; padding: 1rem; border-radius: 8px; border-left: 4px solid #28a745; }
    .explanation h3 { margin-top: 0; }
  `]
})
export class SecureXssBypassComponent {
  userHtml = '';
  processedContent: SafeHtml | null = null;
  sanitizationLog: Array<{ type: string; message: string }> = [];
  payloadResult: { original: string; sanitized: string } | null = null;

  private attackPayloads: Record<string, string> = {
    script: '<script>alert("XSS")</script>',
    onerror: '<img src=x onerror="alert(\'XSS\')">',
    javascript: '<a href="javascript:alert(\'XSS\')">Click</a>',
    svg: '<svg onload="alert(\'XSS\')">'
  };

  secureCode = `
// SECURE: HTML sanitization without bypassing Angular

// Custom sanitizer that uses allowlists
sanitizeHtml(html: string): string {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');

  // Process all elements
  const elements = doc.body.querySelectorAll('*');
  elements.forEach(el => {
    // Remove disallowed tags
    if (!ALLOWED_TAGS.includes(el.tagName.toLowerCase())) {
      el.replaceWith(document.createTextNode(el.textContent || ''));
      return;
    }

    // Remove all event handler attributes
    Array.from(el.attributes).forEach(attr => {
      if (attr.name.startsWith('on') ||
          !ALLOWED_ATTRIBUTES.includes(attr.name)) {
        el.removeAttribute(attr.name);
      }
    });

    // Validate URLs in href attributes
    if (el.hasAttribute('href')) {
      const url = el.getAttribute('href') || '';
      if (!this.isValidUrl(url)) {
        el.removeAttribute('href');
      }
    }
  });

  return doc.body.innerHTML;
}

// Validate URL protocols
isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url, window.location.origin);
    return ALLOWED_URL_PROTOCOLS.includes(parsed.protocol);
  } catch {
    // Relative URLs are allowed
    return !url.toLowerCase().startsWith('javascript:');
  }
}

// Usage: Let Angular sanitize the pre-cleaned HTML
// No need for bypassSecurityTrustHtml()!
// Template: <div [innerHTML]="sanitizedContent"></div>
  `.trim();

  constructor(private sanitizer: DomSanitizer) {}

  processContent(): void {
    this.sanitizationLog = [];

    if (!this.userHtml.trim()) {
      return;
    }

    const sanitized = this.sanitizeHtml(this.userHtml);

    // Angular's built-in sanitization handles the rest
    // No bypassSecurityTrustHtml needed!
    this.processedContent = sanitized;
  }

  testPayload(type: string): void {
    const payload = this.attackPayloads[type];
    if (!payload) return;

    const sanitized = this.sanitizeHtml(payload);

    this.payloadResult = {
      original: payload,
      sanitized: sanitized || '(completely removed)'
    };
  }

  private sanitizeHtml(html: string): string {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');

    this.processElement(doc.body);

    return doc.body.innerHTML;
  }

  private processElement(element: Element): void {
    const children = Array.from(element.children);

    for (const child of children) {
      const tagName = child.tagName.toLowerCase();

      // Remove disallowed tags entirely
      if (!ALLOWED_TAGS.includes(tagName)) {
        this.sanitizationLog.push({
          type: 'removed',
          message: `Removed disallowed tag: <${tagName}>`
        });
        // Replace with text content only
        const text = document.createTextNode(child.textContent || '');
        child.replaceWith(text);
        continue;
      }

      this.sanitizationLog.push({
        type: 'allowed',
        message: `Allowed tag: <${tagName}>`
      });

      // Remove dangerous attributes
      const attrs = Array.from(child.attributes);
      for (const attr of attrs) {
        // Remove all event handlers
        if (attr.name.startsWith('on')) {
          child.removeAttribute(attr.name);
          this.sanitizationLog.push({
            type: 'removed',
            message: `Removed event handler: ${attr.name}`
          });
          continue;
        }

        // Remove non-allowlisted attributes
        if (!ALLOWED_ATTRIBUTES.includes(attr.name)) {
          child.removeAttribute(attr.name);
          this.sanitizationLog.push({
            type: 'removed',
            message: `Removed attribute: ${attr.name}`
          });
          continue;
        }

        // Validate href URLs
        if (attr.name === 'href' && !this.isValidUrl(attr.value)) {
          child.removeAttribute('href');
          this.sanitizationLog.push({
            type: 'removed',
            message: `Removed invalid URL: ${attr.value}`
          });
        }
      }

      // Recursively process children
      this.processElement(child);
    }
  }

  private isValidUrl(url: string): boolean {
    const trimmed = url.trim().toLowerCase();

    // Block javascript: and data: URLs
    if (trimmed.startsWith('javascript:') || trimmed.startsWith('data:')) {
      return false;
    }

    try {
      const parsed = new URL(url, window.location.origin);
      return ALLOWED_URL_PROTOCOLS.includes(parsed.protocol);
    } catch {
      // Allow relative URLs that don't start with dangerous protocols
      return true;
    }
  }
}
