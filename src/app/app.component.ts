import { Component } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { CommonModule } from '@angular/common';

interface NavItem {
  label: string;
  path: string;
  description: string;
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  title = 'Copilot Security Lab';

  vulnerableItems: NavItem[] = [
    { label: 'XSS: bypassSecurityTrust', path: '/vulnerable/xss-bypass', description: 'A03: Injection' },
    { label: 'XSS: innerHTML', path: '/vulnerable/xss-innerhtml', description: 'A03: Injection' },
    { label: 'XSS: Interpolation', path: '/vulnerable/xss-interpolation', description: 'A03: Injection' },
    { label: 'Auth: localStorage JWT', path: '/vulnerable/auth', description: 'A02: Crypto Failures' },
    { label: 'CSRF: Missing Protection', path: '/vulnerable/csrf', description: 'A01: Access Control' },
    { label: 'Open Redirect', path: '/vulnerable/redirect', description: 'A01: Access Control' },
    { label: 'Sensitive Data Exposure', path: '/vulnerable/data-exposure', description: 'A02: Crypto Failures' },
  ];

  secureItems: NavItem[] = [
    { label: 'XSS: Safe Sanitization', path: '/secure/xss-bypass', description: 'Proper DomSanitizer usage' },
    { label: 'XSS: Safe Rendering', path: '/secure/xss-innerhtml', description: 'Sanitized innerHTML' },
    { label: 'XSS: Safe Interpolation', path: '/secure/xss-interpolation', description: 'Proper encoding' },
    { label: 'Auth: Secure Storage', path: '/secure/auth', description: 'HttpOnly cookies' },
    { label: 'CSRF: Token Protection', path: '/secure/csrf', description: 'XSRF token handling' },
    { label: 'Safe Redirects', path: '/secure/redirect', description: 'Allowlist validation' },
    { label: 'Data Protection', path: '/secure/data-exposure', description: 'Secure patterns' },
  ];
}
