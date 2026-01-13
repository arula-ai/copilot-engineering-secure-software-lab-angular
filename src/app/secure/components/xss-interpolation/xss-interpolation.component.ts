/**
 * SECURE: Safe URL and Template Handling
 *
 * Security Controls:
 * - A03: Injection Prevention
 *
 * This component demonstrates SECURE patterns for handling URLs
 * and DOM manipulation without XSS vulnerabilities.
 *
 * SAFE FOR PRODUCTION (with proper testing)
 */

import { Component, OnInit, ElementRef, ViewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';

// Allowlist of safe URL protocols
const SAFE_PROTOCOLS = ['http:', 'https:', 'mailto:', 'tel:'];

// Allowlist of trusted domains for external links
const TRUSTED_DOMAINS = [
  'example.com',
  'github.com',
  'angular.io',
  'localhost'
];

@Component({
  selector: 'app-secure-xss-interpolation',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="security-demo">
      <div class="header">
        <h2>SECURE: Safe URL & Template Handling</h2>
        <span class="badge success">A03: Injection Prevention</span>
      </div>

      <div class="description">
        <p>
          This component demonstrates secure patterns for URL handling
          and DOM manipulation that prevent XSS attacks.
        </p>
      </div>

      <div class="demo-section">
        <h3>Safe Link Generation</h3>
        <p class="context">URLs are validated against an allowlist before use...</p>

        <div class="input-group">
          <label for="shareUrl">Share URL:</label>
          <input
            id="shareUrl"
            type="text"
            [(ngModel)]="shareUrl"
            placeholder="https://example.com/share?id=123"
          >
          <button (click)="validateUrl()">Validate & Create Link</button>
        </div>

        @if (validationResult) {
          <div class="validation-result" [class.valid]="isUrlValid" [class.invalid]="!isUrlValid">
            <p><strong>Status:</strong> {{ validationResult.status }}</p>
            <p><strong>Reason:</strong> {{ validationResult.reason }}</p>
            @if (isUrlValid && safeUrl) {
              <a [href]="safeUrl" target="_blank" rel="noopener noreferrer">
                Click to visit (opens in new tab)
              </a>
            }
          </div>
        }

        <div class="trusted-domains">
          <strong>Trusted domains:</strong>
          <ul>
            @for (domain of trustedDomains; track domain) {
              <li>{{ domain }}</li>
            }
          </ul>
        </div>
      </div>

      <div class="demo-section">
        <h3>Safe DOM Updates</h3>
        <p class="context">Using Angular's renderer instead of innerHTML...</p>

        <div class="input-group">
          <label for="username">Username:</label>
          <input
            id="username"
            type="text"
            [(ngModel)]="username"
            placeholder="Enter username"
          >
          <button (click)="generateWelcome()">Generate Welcome</button>
        </div>

        <!-- Target for safe DOM updates -->
        <div #welcomeContainer class="welcome-container"></div>

        <div class="security-note">
          <strong>Note:</strong> DOM is updated via Renderer2, not innerHTML
        </div>
      </div>

      <div class="demo-section">
        <h3>Safe Error Display</h3>
        <p class="context">Error parameters displayed with text interpolation...</p>

        @if (errorMessage) {
          <div class="error-display">
            <!-- SECURE: Interpolation auto-escapes HTML -->
            <p class="error">Error: {{ errorMessage }}</p>
          </div>
        }

        <div class="url-hint">
          <strong>Current error param:</strong> {{ errorMessage || '(none)' }}<br>
          <small>Try: <code>?error=&lt;script&gt;alert(1)&lt;/script&gt;</code> - will be escaped!</small>
        </div>
      </div>

      <div class="demo-section">
        <h3>Attack Payload Tests</h3>
        <div class="payload-buttons">
          <button (click)="testUrlPayload('javascript:')">javascript: URL</button>
          <button (click)="testUrlPayload('data:')">data: URL</button>
          <button (click)="testUrlPayload('untrusted')">Untrusted Domain</button>
          <button (click)="testDomPayload()">DOM Injection</button>
        </div>

        @if (testResult) {
          <div class="test-result success">
            <p><strong>Attack type:</strong> {{ testResult.type }}</p>
            <p><strong>Result:</strong> {{ testResult.message }}</p>
            <span class="success-text">Attack blocked!</span>
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
          <li><strong>URL validation:</strong> Only http:, https:, mailto:, tel: protocols allowed</li>
          <li><strong>Domain allowlist:</strong> External links restricted to trusted domains</li>
          <li><strong>Text interpolation:</strong> Using {{ '{{}}' }} for user data (auto-escaped)</li>
          <li><strong>Renderer2:</strong> DOM updates via Angular's Renderer2, not innerHTML</li>
          <li><strong>noopener noreferrer:</strong> External links prevent window.opener access</li>
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
    .input-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
    .input-group button { margin-top: 0.5rem; padding: 0.5rem 1rem; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
    .validation-result { padding: 1rem; border-radius: 4px; margin-top: 1rem; }
    .validation-result.valid { background: #d4edda; border: 1px solid #28a745; }
    .validation-result.invalid { background: #f8d7da; border: 1px solid #dc3545; }
    .trusted-domains { margin-top: 1rem; padding: 0.75rem; background: #e9ecef; border-radius: 4px; }
    .trusted-domains ul { margin: 0.5rem 0 0 1.5rem; }
    .welcome-container { min-height: 50px; padding: 1rem; background: white; border-radius: 4px; border: 1px solid #ddd; margin-top: 1rem; }
    .security-note { margin-top: 0.5rem; padding: 0.5rem; background: #d4edda; border-radius: 4px; font-size: 0.875rem; }
    .error-display { padding: 1rem; background: #f8d7da; border-radius: 4px; border: 1px solid #f5c6cb; }
    .error { color: #721c24; margin: 0; }
    .url-hint { margin-top: 1rem; padding: 0.75rem; background: #e9ecef; border-radius: 4px; }
    .url-hint code { background: #dee2e6; padding: 0.125rem 0.375rem; border-radius: 4px; }
    .payload-buttons button { background: #6c757d; color: white; border: none; border-radius: 4px; padding: 0.5rem 1rem; cursor: pointer; margin-right: 0.5rem; margin-bottom: 0.5rem; }
    .test-result { margin-top: 1rem; padding: 1rem; border-radius: 4px; }
    .test-result.success { background: #d4edda; }
    .success-text { color: #155724; font-weight: 600; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #d4edda; padding: 1rem; border-radius: 8px; border-left: 4px solid #28a745; }
    .explanation h3 { margin-top: 0; }
  `]
})
export class SecureXssInterpolationComponent implements OnInit {
  shareUrl = '';
  username = '';
  errorMessage = '';

  validationResult: { status: string; reason: string } | null = null;
  isUrlValid = false;
  safeUrl: string | null = null;

  testResult: { type: string; message: string } | null = null;

  trustedDomains = TRUSTED_DOMAINS;

  @ViewChild('welcomeContainer') welcomeContainer!: ElementRef;

  secureCode = `
// SECURE: URL and template handling patterns

// 1. Validate URLs against protocol allowlist
validateUrl(url: string): { valid: boolean; reason: string } {
  try {
    const parsed = new URL(url, window.location.origin);

    // Check protocol
    if (!SAFE_PROTOCOLS.includes(parsed.protocol)) {
      return { valid: false, reason: 'Blocked protocol: ' + parsed.protocol };
    }

    // Check domain for external URLs
    if (parsed.host !== window.location.host) {
      if (!TRUSTED_DOMAINS.some(d => parsed.host.endsWith(d))) {
        return { valid: false, reason: 'Untrusted domain: ' + parsed.host };
      }
    }

    return { valid: true, reason: 'URL is safe' };
  } catch {
    return { valid: false, reason: 'Invalid URL format' };
  }
}

// 2. Safe DOM updates using Renderer2
constructor(private renderer: Renderer2) {}

updateWelcome(username: string) {
  const container = this.welcomeContainer.nativeElement;

  // Clear existing content safely
  while (container.firstChild) {
    this.renderer.removeChild(container, container.firstChild);
  }

  // Create elements using Renderer2 (auto-escapes text)
  const heading = this.renderer.createElement('h3');
  const text = this.renderer.createText('Welcome, ' + username + '!');
  this.renderer.appendChild(heading, text);
  this.renderer.appendChild(container, heading);
}

// 3. For displaying user input, always use interpolation
// Template: <span>{{ userInput }}</span>
// Angular automatically HTML-encodes the value

// 4. External links should include security attributes
// <a [href]="validatedUrl" target="_blank" rel="noopener noreferrer">
  `.trim();

  constructor(private route: ActivatedRoute) {}

  ngOnInit(): void {
    // SECURE: Error from URL displayed via interpolation (auto-escaped)
    this.route.queryParams.subscribe(params => {
      if (params['error']) {
        this.errorMessage = params['error'];
      }
    });
  }

  validateUrl(): void {
    if (!this.shareUrl) {
      this.validationResult = { status: 'Invalid', reason: 'URL is empty' };
      this.isUrlValid = false;
      this.safeUrl = null;
      return;
    }

    const result = this.validateUrlSecurity(this.shareUrl);
    this.validationResult = { status: result.valid ? 'Valid' : 'Blocked', reason: result.reason };
    this.isUrlValid = result.valid;
    this.safeUrl = result.valid ? this.shareUrl : null;
  }

  private validateUrlSecurity(url: string): { valid: boolean; reason: string } {
    try {
      const parsed = new URL(url, window.location.origin);

      // Block dangerous protocols
      if (!SAFE_PROTOCOLS.includes(parsed.protocol)) {
        return {
          valid: false,
          reason: `Protocol "${parsed.protocol}" is not allowed. Only ${SAFE_PROTOCOLS.join(', ')} are permitted.`
        };
      }

      // For external URLs, check domain allowlist
      if (parsed.host !== window.location.host) {
        const isTrusted = TRUSTED_DOMAINS.some(domain =>
          parsed.host === domain || parsed.host.endsWith('.' + domain)
        );

        if (!isTrusted) {
          return {
            valid: false,
            reason: `Domain "${parsed.host}" is not in the trusted domains list.`
          };
        }
      }

      return { valid: true, reason: 'URL passed all security checks.' };
    } catch (e) {
      return { valid: false, reason: 'Invalid URL format.' };
    }
  }

  generateWelcome(): void {
    if (!this.username) {
      alert('Please enter a username');
      return;
    }

    const container = this.welcomeContainer.nativeElement;

    // SECURE: Clear content by setting textContent (safe)
    container.textContent = '';

    // SECURE: Create elements with textContent (auto-escapes)
    const heading = document.createElement('h3');
    heading.textContent = `Welcome, ${this.username}!`;

    const paragraph = document.createElement('p');
    paragraph.textContent = 'Thank you for joining our platform.';

    container.appendChild(heading);
    container.appendChild(paragraph);

    // Note: Using textContent instead of innerHTML prevents XSS
  }

  testUrlPayload(type: string): void {
    let testUrl = '';
    let expectedBlock = '';

    switch (type) {
      case 'javascript:':
        testUrl = 'javascript:alert(1)';
        expectedBlock = 'Blocked protocol';
        break;
      case 'data:':
        testUrl = 'data:text/html,<script>alert(1)</script>';
        expectedBlock = 'Blocked protocol';
        break;
      case 'untrusted':
        testUrl = 'https://evil-site.com/phishing';
        expectedBlock = 'Untrusted domain';
        break;
    }

    const result = this.validateUrlSecurity(testUrl);

    this.testResult = {
      type: `${type} URL attack`,
      message: result.valid ? 'UNEXPECTED: URL was allowed!' : `Blocked: ${result.reason}`
    };
  }

  testDomPayload(): void {
    // Test that username with HTML is safely escaped
    const maliciousInput = '<img src=x onerror=alert(1)>';

    const container = this.welcomeContainer.nativeElement;
    container.textContent = '';

    const heading = document.createElement('h3');
    heading.textContent = `Welcome, ${maliciousInput}!`; // textContent escapes HTML

    container.appendChild(heading);

    this.testResult = {
      type: 'DOM injection attack',
      message: 'HTML was escaped via textContent. No script execution possible.'
    };
  }
}
