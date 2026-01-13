---
description: OWASP Top 10 frontend vulnerability patterns for vulnerable component analysis
applyTo: "**/vulnerable/**"
---

# OWASP Top 10 Frontend Vulnerabilities

These files contain **intentionally vulnerable code** for educational purposes.
When analyzing vulnerable components, identify these OWASP patterns:

## A01:2021 - Broken Access Control

### Frontend Manifestations
- Client-side role/permission checks without server validation
- URL-based access control bypasses
- Open redirects to external URLs
- Direct object references in client code

### Vulnerable Patterns in This Lab
```typescript
// VULN: Client-side role check
isAdmin(): boolean {
  return this.decodeToken()?.role === 'admin';
}

// VULN: Unvalidated redirect
window.location.href = this.returnUrl;
```

## A02:2021 - Cryptographic Failures

### Frontend Manifestations
- Tokens stored in localStorage (accessible via XSS)
- Sensitive data in browser storage
- API keys/secrets in frontend code
- Credentials logged to console

### Vulnerable Patterns in This Lab
```typescript
// VULN: Token in localStorage
localStorage.setItem('auth_token', token);

// VULN: Credential logging
console.log('Login:', { email, password });

// VULN: API key in environment
apiKey: 'sk_live_51ABC123...'
```

## A03:2021 - Injection (XSS)

### Frontend Manifestations
- DOM-based XSS via innerHTML
- Reflected XSS via URL parameters
- Stored XSS via unsanitized storage
- Sanitizer bypass methods

### Vulnerable Patterns in This Lab
```typescript
// VULN: Sanitizer bypass with user input
this.sanitizer.bypassSecurityTrustHtml(userInput)

// VULN: innerHTML binding
<div [innerHTML]="userContent"></div>

// VULN: Direct DOM manipulation
element.nativeElement.innerHTML = userInput

// VULN: URL bypass
this.sanitizer.bypassSecurityTrustUrl(userUrl)
```

## A04:2021 - Insecure Design

### Frontend Manifestations
- Missing rate limiting on forms
- No CAPTCHA on sensitive operations
- Predictable resource identifiers
- Missing security controls in design

## A05:2021 - Security Misconfiguration

### Frontend Manifestations
- Missing CSP headers
- Verbose error messages
- Default credentials
- Unnecessary features enabled

## A06:2021 - Vulnerable Components

### Frontend Manifestations
- Outdated npm packages
- Known vulnerable libraries
- Unpatched frameworks

## A07:2021 - Auth Failures

### Frontend Manifestations
- Weak session management
- Missing logout functionality
- Session tokens in URL
- No session timeout

### Vulnerable Patterns in This Lab
```typescript
// VULN: No server-side logout
logout(): void {
  localStorage.removeItem('token');
  // Token still valid on server!
}
```

## A08:2021 - Software Integrity

### Frontend Manifestations
- Missing SRI on external scripts
- No integrity checks on updates
- Unsigned packages

## A09:2021 - Logging Failures

### Frontend Manifestations
- No audit logging
- Sensitive data in logs
- Missing security event logging

### Vulnerable Patterns in This Lab
```typescript
// VULN: Sensitive data logging
console.log('Credit Card:', this.creditCard);
console.log('SSN:', this.ssn);
```

## A10:2021 - SSRF

### Frontend Manifestations
- Unvalidated URL parameters passed to backend
- User-controlled redirect targets

---

## Analysis Checklist

When reviewing vulnerable components, check for:

- [ ] `bypassSecurityTrust*()` usage
- [ ] `[innerHTML]` bindings with user data
- [ ] `localStorage/sessionStorage` for tokens
- [ ] `console.log` with sensitive data
- [ ] Unvalidated URL redirects
- [ ] Client-side authorization
- [ ] Missing XSRF configuration
- [ ] Hardcoded secrets in code
