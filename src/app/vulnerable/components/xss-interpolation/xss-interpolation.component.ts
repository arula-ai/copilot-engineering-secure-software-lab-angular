/**
 * VULNERABLE: XSS via Template Interpolation
 *
 * Security Issues:
 * - A03: Injection (Cross-Site Scripting)
 *
 * This component demonstrates how Angular's template interpolation
 * can be misused when combined with DOM manipulation or URL handling.
 *
 * DO NOT USE IN PRODUCTION
 */

import { Component, OnInit, ElementRef, ViewChild, AfterViewInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeUrl } from '@angular/platform-browser';

@Component({
  selector: 'app-vulnerable-xss-interpolation',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="vulnerability-demo">
      <div class="header">
        <h2>VULNERABLE: XSS via Interpolation & URLs</h2>
        <span class="badge danger">A03: Injection</span>
      </div>

      <div class="description">
        <p>
          While Angular's interpolation {{ '{{}}' }} auto-escapes content, vulnerabilities
          arise when combining with DOM APIs, URL parameters, or bypassing sanitization.
        </p>
      </div>

      <div class="demo-section">
        <h3>Dynamic Link Generation</h3>
        <p class="context">A "share" feature that creates links from user input...</p>

        <div class="input-group">
          <label for="shareUrl">Share URL:</label>
          <input
            id="shareUrl"
            type="text"
            [(ngModel)]="shareUrl"
            placeholder="https://example.com/share?id=123"
          >
        </div>

        <div class="link-preview">
          <p>Generated link:</p>
          <!-- VULN: Using bypassSecurityTrustUrl for user input -->
          <a [href]="trustedShareUrl">Click to share</a>
        </div>

        <div class="attack-examples">
          <h4>Try these payloads:</h4>
          <div class="payload-buttons">
            <button (click)="setSharePayload('javascript')">javascript: URL</button>
            <button (click)="setSharePayload('data')">data: URL</button>
          </div>
        </div>
      </div>

      <div class="demo-section">
        <h3>Template to DOM Injection</h3>
        <p class="context">Dynamically generating HTML from template values...</p>

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

        <!-- Target for DOM manipulation -->
        <div #welcomeContainer class="welcome-container"></div>

        <div class="attack-examples">
          <h4>Try:</h4>
          <code>&lt;img src=x onerror=alert('XSS')&gt;</code>
        </div>
      </div>

      <div class="demo-section">
        <h3>URL Parameter Reflection</h3>
        <p class="context">Error messages that include URL parameters...</p>

        @if (errorMessage) {
          <div class="error-display">
            <!-- VULN: Error message from URL displayed in template -->
            <p class="error">Error: {{ errorMessage }}</p>
            <p class="context">The interpolation is safe, but check the code below...</p>
          </div>
        }

        <div class="url-hint">
          <strong>Current error param:</strong> <code>{{ errorMessage || '(none)' }}</code>
          <p>Try: <code>?error=Something%20went%20wrong</code></p>
        </div>
      </div>

      <div class="code-section">
        <h3>Vulnerable Patterns</h3>
        <pre><code>{{ vulnerableCode }}</code></pre>
      </div>

      <div class="explanation">
        <h3>Why These Patterns Are Dangerous</h3>
        <ul>
          <li><strong>bypassSecurityTrustUrl:</strong> Allows javascript: and data: URLs that execute code</li>
          <li><strong>innerHTML via ElementRef:</strong> Bypasses Angular's template sanitization entirely</li>
          <li><strong>URL parameter handling:</strong> While interpolation escapes, downstream processing may not</li>
          <li><strong>Dynamic script loading:</strong> User-controlled URLs for scripts enable code injection</li>
        </ul>
      </div>
    </div>
  `,
  styles: [`
    .vulnerability-demo { max-width: 800px; }
    .header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
    .header h2 { margin: 0; color: #dc3545; }
    .badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .badge.danger { background: #dc3545; color: white; }
    .description { background: #fff5f5; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; border-left: 4px solid #dc3545; }
    .demo-section { background: #f8f9fa; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; }
    .demo-section h3 { margin-top: 0; }
    .context { color: #666; font-style: italic; }
    .input-group { margin-bottom: 1rem; }
    .input-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
    .input-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
    .input-group button { margin-top: 0.5rem; padding: 0.5rem 1rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
    .link-preview { padding: 1rem; background: white; border-radius: 4px; border: 1px solid #ddd; margin-bottom: 1rem; }
    .link-preview a { color: #007bff; word-break: break-all; }
    .welcome-container { min-height: 50px; padding: 1rem; background: white; border-radius: 4px; border: 1px solid #ddd; margin-top: 1rem; }
    .error-display { padding: 1rem; background: #f8d7da; border-radius: 4px; border: 1px solid #f5c6cb; }
    .error { color: #721c24; margin: 0 0 0.5rem 0; }
    .attack-examples { margin-top: 1rem; padding: 0.75rem; background: #fff3cd; border-radius: 4px; }
    .payload-buttons { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.5rem; }
    .payload-buttons button { background: #dc3545; padding: 0.5rem 1rem; color: white; border: none; border-radius: 4px; cursor: pointer; }
    .url-hint { padding: 0.75rem; background: #e9ecef; border-radius: 4px; margin-top: 1rem; }
    .url-hint code { background: #dee2e6; padding: 0.125rem 0.375rem; border-radius: 4px; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #fff3cd; padding: 1rem; border-radius: 8px; border-left: 4px solid #ffc107; }
    .explanation h3 { margin-top: 0; }
  `]
})
export class VulnerableXssInterpolationComponent implements OnInit, AfterViewInit {
  shareUrl = 'https://example.com/share?id=123';
  trustedShareUrl: SafeUrl = '';
  username = '';
  errorMessage = '';

  @ViewChild('welcomeContainer') welcomeContainer!: ElementRef;

  private sharePayloads: Record<string, string> = {
    javascript: 'javascript:alert(document.cookie)',
    data: 'data:text/html,<script>alert("XSS")</script>'
  };

  vulnerableCode = `
// VULNERABLE: Multiple interpolation-related XSS patterns

// 1. Bypassing URL sanitization
shareUrl = 'javascript:alert(1)';
trustedUrl = this.sanitizer.bypassSecurityTrustUrl(this.shareUrl);
// Template: <a [href]="trustedUrl">Click</a>

// 2. DOM manipulation bypassing Angular
@ViewChild('container') container: ElementRef;

generateContent(userInput: string) {
  // VULN: Direct innerHTML bypasses Angular sanitization!
  this.container.nativeElement.innerHTML =
    '<h1>Welcome, ' + userInput + '</h1>';
}

// 3. Dynamic script injection
loadScript(url: string) {
  const script = document.createElement('script');
  script.src = url; // VULN: User-controlled script URL
  document.body.appendChild(script);
}

// 4. URL parameter to attribute
ngOnInit() {
  this.route.queryParams.subscribe(params => {
    this.redirectUrl = params['next']; // No validation
  });
}
// Template: <a [href]="redirectUrl">Continue</a>
  `.trim();

  constructor(
    private route: ActivatedRoute,
    private sanitizer: DomSanitizer
  ) {}

  ngOnInit(): void {
    // VULN: Reading error message from URL params
    this.route.queryParams.subscribe(params => {
      if (params['error']) {
        this.errorMessage = params['error'];
      }
    });

    this.updateTrustedUrl();
  }

  ngAfterViewInit(): void {
    // Component ready
  }

  updateTrustedUrl(): void {
    // VULN: Bypassing URL sanitization for user input!
    this.trustedShareUrl = this.sanitizer.bypassSecurityTrustUrl(this.shareUrl);
  }

  setSharePayload(type: string): void {
    this.shareUrl = this.sharePayloads[type] || '';
    this.updateTrustedUrl();
  }

  generateWelcome(): void {
    if (!this.username) {
      alert('Please enter a username');
      return;
    }

    // VULN: Direct DOM manipulation with user input!
    // This completely bypasses Angular's sanitization
    const html = `<h3>Welcome, ${this.username}!</h3>
                  <p>Thank you for joining our platform.</p>`;

    this.welcomeContainer.nativeElement.innerHTML = html;

    console.warn('DOM XSS: Injected raw HTML:', html);
  }
}
