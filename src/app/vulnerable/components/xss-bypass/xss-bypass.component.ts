/**
 * VULNERABLE: XSS via bypassSecurityTrust
 *
 * Security Issues:
 * - A03: Injection (Cross-Site Scripting)
 *
 * This component demonstrates DANGEROUS usage of Angular's DomSanitizer.
 * The bypassSecurityTrust* methods should NEVER be used with user input.
 *
 * DO NOT USE IN PRODUCTION
 */

import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-vulnerable-xss-bypass',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="vulnerability-demo">
      <div class="header">
        <h2>VULNERABLE: XSS via bypassSecurityTrustHtml</h2>
        <span class="badge danger">A03: Injection</span>
      </div>

      <div class="description">
        <p>
          This component uses <code>bypassSecurityTrustHtml()</code> on user input,
          completely bypassing Angular's XSS protection.
        </p>
      </div>

      <div class="demo-section">
        <h3>User Profile Bio Editor</h3>
        <p class="context">Users can customize their profile with "rich text"...</p>

        <div class="input-group">
          <label for="bio">Enter your bio (HTML allowed):</label>
          <textarea
            id="bio"
            [(ngModel)]="userBio"
            rows="4"
            placeholder="Enter HTML content..."
          ></textarea>
        </div>

        <div class="preview">
          <h4>Preview:</h4>
          <!-- VULN: Bypassing Angular's sanitizer with user input -->
          <div class="bio-content" [innerHTML]="getTrustedHtml()"></div>
        </div>

        <div class="attack-examples">
          <h4>Try these attack payloads:</h4>
          <div class="payload-buttons">
            <button (click)="setPayload('script')">Script Tag</button>
            <button (click)="setPayload('img')">IMG onerror</button>
            <button (click)="setPayload('svg')">SVG onload</button>
            <button (click)="setPayload('event')">Event Handler</button>
          </div>
        </div>
      </div>

      <div class="code-section">
        <h3>Vulnerable Code</h3>
        <pre><code>{{ vulnerableCode }}</code></pre>
      </div>

      <div class="explanation">
        <h3>Why This Is Dangerous</h3>
        <ul>
          <li><strong>Bypasses ALL sanitization:</strong> bypassSecurityTrustHtml tells Angular to trust the content completely</li>
          <li><strong>Enables script execution:</strong> Attackers can inject &lt;script&gt; tags or event handlers</li>
          <li><strong>Session hijacking:</strong> Stolen cookies can be sent to attacker's server</li>
          <li><strong>Keylogging:</strong> Injected scripts can capture user input</li>
          <li><strong>Defacement:</strong> Page content can be modified arbitrarily</li>
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
    .description code { background: #ffe0e0; padding: 0.125rem 0.375rem; border-radius: 4px; }
    .demo-section { background: #f8f9fa; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; }
    .demo-section h3 { margin-top: 0; }
    .context { color: #666; font-style: italic; }
    .input-group { margin-bottom: 1rem; }
    .input-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
    .input-group textarea { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-family: inherit; resize: vertical; }
    .preview { background: white; padding: 1rem; border-radius: 4px; border: 1px solid #ddd; margin-bottom: 1rem; }
    .preview h4 { margin-top: 0; color: #666; }
    .bio-content { min-height: 50px; padding: 0.5rem; background: #fafafa; border-radius: 4px; }
    .attack-examples { margin-top: 1rem; }
    .attack-examples h4 { margin-bottom: 0.5rem; }
    .payload-buttons { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    .payload-buttons button { padding: 0.5rem 1rem; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer; }
    .payload-buttons button:hover { background: #c82333; }
    .code-section { margin-bottom: 1.5rem; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #fff3cd; padding: 1rem; border-radius: 8px; border-left: 4px solid #ffc107; }
    .explanation h3 { margin-top: 0; }
    .explanation ul { margin-bottom: 0; }
    .explanation li { margin-bottom: 0.5rem; }
  `]
})
export class VulnerableXssBypassComponent {
  userBio = '<b>Hello!</b> I love <i>coding</i>.';

  // Attack payloads for demonstration
  private attackPayloads: Record<string, string> = {
    script: '<script>alert("XSS via script tag!")</script>',
    img: '<img src="x" onerror="alert(\'XSS via img onerror!\')">',
    svg: '<svg onload="alert(\'XSS via svg onload!\')">',
    event: '<div onmouseover="alert(\'XSS via event handler!\')">Hover me!</div>'
  };

  vulnerableCode = `
// VULNERABLE: Never use bypassSecurityTrustHtml with user input!
import { DomSanitizer } from '@angular/platform-browser';

constructor(private sanitizer: DomSanitizer) {}

// This completely bypasses Angular's XSS protection
getTrustedHtml(): SafeHtml {
  return this.sanitizer.bypassSecurityTrustHtml(this.userBio);
}

// Template usage:
// <div [innerHTML]="getTrustedHtml()"></div>
  `.trim();

  constructor(private sanitizer: DomSanitizer) {}

  // VULN: This method bypasses ALL sanitization
  // NEVER do this with user-controlled input!
  getTrustedHtml(): SafeHtml {
    return this.sanitizer.bypassSecurityTrustHtml(this.userBio);
  }

  setPayload(type: string): void {
    this.userBio = this.attackPayloads[type] || '';
  }
}
