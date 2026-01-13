/**
 * VULNERABLE: Open Redirect
 *
 * Security Issues:
 * - A01: Broken Access Control (Open Redirect)
 *
 * This component demonstrates unsafe redirect handling that can be
 * exploited for phishing attacks.
 *
 * DO NOT USE IN PRODUCTION
 */

import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';

@Component({
  selector: 'app-vulnerable-redirect-handler',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="vulnerability-demo">
      <div class="header">
        <h2>VULNERABLE: Open Redirect</h2>
        <span class="badge danger">A01: Access Control</span>
      </div>

      <div class="description">
        <p>
          This component demonstrates open redirect vulnerabilities where user-supplied
          URLs are used for navigation without validation, enabling phishing attacks.
        </p>
      </div>

      <div class="demo-section">
        <h3>Login Return URL</h3>
        <p class="context">After login, users are redirected to the URL in the "returnUrl" parameter...</p>

        <div class="input-group">
          <label for="returnUrl">Return URL:</label>
          <input
            id="returnUrl"
            type="text"
            [(ngModel)]="returnUrl"
            placeholder="https://example.com/dashboard"
          >
        </div>

        <button (click)="handleRedirect()">Simulate Login & Redirect</button>

        @if (willRedirectTo) {
          <div class="redirect-preview">
            <p>Will redirect to: <code>{{ willRedirectTo }}</code></p>
            @if (isDangerous) {
              <p class="warning">DANGER: This is an external URL - possible phishing attack!</p>
            }
          </div>
        }

        <div class="attack-examples">
          <h4>Attack Payloads:</h4>
          <div class="payload-buttons">
            <button (click)="setPayload('external')">External Site</button>
            <button (click)="setPayload('javascript')">JavaScript</button>
            <button (click)="setPayload('data')">Data URL</button>
            <button (click)="setPayload('encoded')">URL Encoded</button>
          </div>
        </div>
      </div>

      <div class="demo-section">
        <h3>Dynamic Navigation</h3>
        <p class="context">Admin panel with dynamic navigation based on user input...</p>

        <div class="input-group">
          <label for="navTarget">Navigate to:</label>
          <select id="navTarget" [(ngModel)]="navTarget">
            <option value="">Select destination</option>
            <option value="/dashboard">Dashboard</option>
            <option value="/settings">Settings</option>
            <option value="https://evil.com">Evil Site (attack)</option>
          </select>
        </div>

        <button (click)="navigate()">Navigate</button>
      </div>

      <div class="code-section">
        <h3>Vulnerable Code</h3>
        <pre><code>{{ vulnerableCode }}</code></pre>
      </div>

      <div class="explanation">
        <h3>Why This Is Dangerous</h3>
        <ul>
          <li><strong>Phishing attacks:</strong> Attackers send links like <code>yoursite.com/login?returnUrl=https://evil.com</code></li>
          <li><strong>Credential theft:</strong> Users think they're on your site but are redirected to a fake login</li>
          <li><strong>JavaScript execution:</strong> <code>javascript:</code> URLs can execute arbitrary code</li>
          <li><strong>Trust exploitation:</strong> Users trust links that start with your domain</li>
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
    .input-group input, .input-group select { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
    button { padding: 0.75rem 1.5rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; margin-right: 0.5rem; }
    .redirect-preview { margin-top: 1rem; padding: 1rem; background: white; border-radius: 4px; border: 1px solid #ddd; }
    .redirect-preview code { word-break: break-all; }
    .warning { color: #dc3545; font-weight: 500; }
    .attack-examples { margin-top: 1.5rem; }
    .payload-buttons { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.5rem; }
    .payload-buttons button { background: #dc3545; padding: 0.5rem 1rem; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #fff3cd; padding: 1rem; border-radius: 8px; border-left: 4px solid #ffc107; }
    .explanation h3 { margin-top: 0; }
  `]
})
export class VulnerableRedirectHandlerComponent implements OnInit {
  returnUrl = '';
  navTarget = '';
  willRedirectTo = '';
  isDangerous = false;

  private attackPayloads: Record<string, string> = {
    external: 'https://evil-site.com/fake-login',
    javascript: 'javascript:alert(document.cookie)',
    data: 'data:text/html,<script>alert("XSS")</script>',
    encoded: 'https://evil.com%2F%2Eyoursite.com'
  };

  vulnerableCode = `
// VULNERABLE: Open redirect patterns

// 1. Unvalidated returnUrl from query params
ngOnInit() {
  this.route.queryParams.subscribe(params => {
    this.returnUrl = params['returnUrl'];
  });
}

handleRedirect() {
  // VULN: No validation of destination URL!
  window.location.href = this.returnUrl;
}

// 2. Unsafe Router navigation
navigate(destination: string) {
  // VULN: Allows external URLs
  if (destination.startsWith('http')) {
    window.location.href = destination;
  } else {
    this.router.navigateByUrl(destination);
  }
}

// Attack URL:
// https://yoursite.com/login?returnUrl=https://evil.com/fake-login
//
// User sees: "yoursite.com" in the link
// User lands on: evil.com/fake-login (phishing page)
  `.trim();

  constructor(
    private route: ActivatedRoute,
    private router: Router
  ) {}

  ngOnInit(): void {
    // VULN: Reading returnUrl from query params without validation
    this.route.queryParams.subscribe(params => {
      if (params['returnUrl']) {
        this.returnUrl = params['returnUrl'];
        this.updatePreview();
      }
    });
  }

  handleRedirect(): void {
    if (!this.returnUrl) {
      alert('Please enter a return URL');
      return;
    }

    // VULN: No validation - redirects to ANY URL
    console.log('Redirecting to:', this.returnUrl);

    // For demo purposes, we'll just show an alert instead of actually redirecting
    if (this.isDangerous) {
      alert(`ATTACK DETECTED!\n\nThis would redirect to:\n${this.returnUrl}\n\nIn a real attack, users would land on a phishing site.`);
    } else {
      alert(`Redirecting to: ${this.returnUrl}`);
    }
  }

  navigate(): void {
    if (!this.navTarget) {
      alert('Please select a destination');
      return;
    }

    // VULN: Allows navigation to external URLs
    if (this.navTarget.startsWith('http')) {
      alert(`VULNERABLE: Would navigate to external URL:\n${this.navTarget}`);
    } else {
      this.router.navigateByUrl(this.navTarget);
    }
  }

  setPayload(type: string): void {
    this.returnUrl = this.attackPayloads[type] || '';
    this.updatePreview();
  }

  private updatePreview(): void {
    this.willRedirectTo = this.returnUrl;
    this.isDangerous = this.isExternalUrl(this.returnUrl);
  }

  private isExternalUrl(url: string): boolean {
    if (!url) return false;
    return (
      url.startsWith('http://') ||
      url.startsWith('https://') ||
      url.startsWith('javascript:') ||
      url.startsWith('data:') ||
      url.startsWith('//')
    );
  }
}
