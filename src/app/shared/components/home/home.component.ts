import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="home">
      <h2>Welcome to the Angular Security Lab</h2>

      <div class="warning-box">
        <h3>WARNING</h3>
        <p>This lab contains <strong>intentionally vulnerable code</strong> for educational purposes.</p>
        <ul>
          <li>DO NOT use vulnerable patterns in production</li>
          <li>DO NOT copy vulnerable code without fixing it</li>
          <li>Use GitHub Copilot to analyze and fix vulnerabilities</li>
        </ul>
      </div>

      <div class="overview">
        <h3>Lab Overview</h3>
        <p>This lab covers Angular-specific security vulnerabilities from the OWASP Top 10:</p>

        <div class="vulnerability-grid">
          <div class="vuln-card">
            <h4>A03: Injection (XSS)</h4>
            <ul>
              <li>bypassSecurityTrust misuse</li>
              <li>Unsafe innerHTML binding</li>
              <li>Template injection via interpolation</li>
            </ul>
          </div>

          <div class="vuln-card">
            <h4>A02: Cryptographic Failures</h4>
            <ul>
              <li>JWT stored in localStorage</li>
              <li>Sensitive data in environment.ts</li>
              <li>Insecure token handling</li>
            </ul>
          </div>

          <div class="vuln-card">
            <h4>A01: Broken Access Control</h4>
            <ul>
              <li>Missing CSRF protection</li>
              <li>Open redirects</li>
              <li>Insecure API calls</li>
            </ul>
          </div>

          <div class="vuln-card">
            <h4>A05: Security Misconfiguration</h4>
            <ul>
              <li>Permissive CORS</li>
              <li>Missing security headers</li>
              <li>Debug mode exposure</li>
            </ul>
          </div>
        </div>
      </div>

      <div class="getting-started">
        <h3>Getting Started</h3>
        <ol>
          <li>Select a vulnerable component from the sidebar</li>
          <li>Use Copilot Chat to analyze the security issues</li>
          <li>Compare with the secure implementation</li>
          <li>Complete the lab exercises in <code>exercises/</code></li>
        </ol>
      </div>
    </div>
  `,
  styles: [`
    .home {
      max-width: 800px;
    }

    h2 {
      color: #1a1a2e;
      margin-bottom: 1.5rem;
    }

    .warning-box {
      background: #fff5f5;
      border: 1px solid #dc3545;
      border-radius: 8px;
      padding: 1rem 1.5rem;
      margin-bottom: 2rem;
    }

    .warning-box h3 {
      color: #dc3545;
      margin: 0 0 0.5rem 0;
    }

    .warning-box ul {
      margin: 0.5rem 0 0 0;
      padding-left: 1.5rem;
    }

    .overview h3, .getting-started h3 {
      color: #16213e;
      margin-bottom: 1rem;
    }

    .vulnerability-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 1rem;
      margin: 1rem 0 2rem 0;
    }

    .vuln-card {
      background: #f8f9fa;
      border-radius: 8px;
      padding: 1rem;
    }

    .vuln-card h4 {
      color: #1a1a2e;
      margin: 0 0 0.5rem 0;
      font-size: 0.9rem;
    }

    .vuln-card ul {
      margin: 0;
      padding-left: 1.25rem;
      font-size: 0.85rem;
      color: #555;
    }

    .getting-started ol {
      padding-left: 1.5rem;
    }

    .getting-started li {
      margin-bottom: 0.5rem;
    }

    .getting-started code {
      background: #e9ecef;
      padding: 0.125rem 0.375rem;
      border-radius: 4px;
      font-size: 0.85rem;
    }
  `]
})
export class HomeComponent {}
