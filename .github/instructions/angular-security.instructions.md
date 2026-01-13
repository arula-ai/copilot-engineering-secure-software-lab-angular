---
description: Core Angular security guidelines applied to all TypeScript files
applyTo: "**/*.ts"
---

# Angular Security Guidelines

When working with Angular TypeScript files, follow these security principles:

## XSS Prevention

### Never Do
- Never use `bypassSecurityTrustHtml()` with user-controlled input
- Never use `bypassSecurityTrustUrl()` with unvalidated URLs
- Never assign to `nativeElement.innerHTML` directly
- Never use `eval()` or `new Function()` with dynamic content

### Always Do
- Trust Angular's built-in sanitization for template bindings
- Use text interpolation `{{ value }}` instead of innerHTML when possible
- Validate and sanitize URLs before navigation
- Use allowlists for HTML tags and attributes

## Authentication Security

### Never Do
- Never store JWT tokens in localStorage or sessionStorage
- Never log passwords, tokens, or credentials to console
- Never expose tokens in URL parameters
- Never trust client-side role checks for authorization

### Always Do
- Use HttpOnly cookies for session tokens (requires backend support)
- Keep authentication state in memory (Angular signals or services)
- Always include `withCredentials: true` for authenticated requests
- Validate sessions server-side for sensitive operations

## Data Handling

### Never Do
- Never log sensitive data (PII, credentials, tokens)
- Never store sensitive data in browser storage
- Never expose API keys in frontend code

### Always Do
- Mask sensitive data before display (credit cards, SSN, etc.)
- Redact sensitive fields in log output
- Use environment variables for configuration (not secrets)

## HTTP Security

### Configuration Required
```typescript
// app.config.ts
provideHttpClient(
  withXsrfConfiguration({
    cookieName: 'XSRF-TOKEN',
    headerName: 'X-XSRF-TOKEN'
  })
)
```

### HTTP Methods
- Use POST/PUT/DELETE for state-changing operations
- Never use GET for operations that modify data
- Always include XSRF token in state-changing requests

## URL Handling

### Validation Required
- Validate redirect URLs against an allowlist
- Block `javascript:`, `data:`, `vbscript:` protocols
- Block protocol-relative URLs (`//`)
- Decode URLs before validation to catch encoding attacks

## Dangerous Patterns to Avoid

```typescript
// DANGEROUS - XSS via sanitizer bypass
this.sanitizer.bypassSecurityTrustHtml(userInput)

// DANGEROUS - Token in localStorage
localStorage.setItem('token', jwt)

// DANGEROUS - Credential logging
console.log('Login:', { password })

// DANGEROUS - Unvalidated redirect
window.location.href = urlParam

// DANGEROUS - Direct DOM manipulation
element.innerHTML = userContent
```

## Secure Patterns to Follow

```typescript
// SECURE - Use built-in sanitization
<div>{{ userContent }}</div>

// SECURE - HttpOnly cookies (server sets cookie)
http.post(url, data, { withCredentials: true })

// SECURE - Memory-only state
private userSignal = signal<User | null>(null);

// SECURE - Validated redirect
if (ALLOWED_PATHS.includes(path)) {
  router.navigate([path]);
}

// SECURE - Safe logging
console.log('User:', { id, email }); // No password
```
