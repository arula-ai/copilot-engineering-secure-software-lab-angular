---
description: Reference secure implementation patterns
applyTo: "**/secure/**"
---

# Secure Implementation Patterns

These files contain **reference secure implementations**. Follow these patterns when fixing vulnerabilities.

## Pattern: HTML Sanitization

**Implementation:** `src/app/secure/components/xss-bypass/`

**Key Points:**
- Use tag allowlist: `['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'ul', 'ol', 'li', 'a', 'span']`
- Remove all event handler attributes (`on*`)
- Validate href protocols: `http:`, `https:`, `mailto:` only
- Remove script, iframe, object, embed tags completely

**Test File:** `src/app/secure/utils/html-sanitizer.spec.ts`

```typescript
// Reference implementation
function sanitizeHtml(html: string): string {
  // Parse HTML
  // Filter to allowed tags
  // Remove dangerous attributes
  // Validate URLs
  return cleanedHtml;
}
```

## Pattern: HttpOnly Cookie Authentication

**Implementation:** `src/app/secure/services/auth.service.ts`

**Key Points:**
- Never store tokens in localStorage/sessionStorage
- Use `withCredentials: true` for all auth requests
- Keep user state in memory (signals)
- Validate session on app initialization
- Clear state on logout

**Test File:** `src/app/secure/services/auth.service.spec.ts`

```typescript
// Reference implementation
@Injectable({ providedIn: 'root' })
export class SecureAuthService {
  private currentUser = signal<User | null>(null);

  login(email: string, password: string): Observable<User> {
    return this.http.post('/api/auth/login',
      { email, password },
      { withCredentials: true }
    );
  }
}
```

## Pattern: URL Validation

**Implementation:** `src/app/secure/components/redirect-handler/`

**Key Points:**
- Use path allowlist: `['/', '/dashboard', '/profile', '/settings']`
- Block dangerous protocols: `javascript:`, `data:`, `vbscript:`
- Block protocol-relative URLs: `//`
- Decode URLs before validation (handle double encoding)
- Return safe default on validation failure

**Test File:** `src/app/secure/utils/url-validator.spec.ts`

```typescript
// Reference implementation
function validateRedirectUrl(url: string): string {
  const ALLOWED_PATHS = ['/', '/dashboard', '/profile', '/settings'];
  // Decode, validate protocol, check allowlist
  return validPath || '/';
}
```

## Pattern: CSRF Protection

**Implementation:** `src/app/secure/components/csrf-demo/`

**Key Points:**
- Configure `withXsrfConfiguration()` in app.config.ts
- Use POST/PUT/DELETE for state-changing operations
- Ensure server sets SameSite cookie attribute

**Test File:** `src/app/secure/utils/csrf-protection.spec.ts`

```typescript
// Reference implementation in app.config.ts
export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(
      withXsrfConfiguration({
        cookieName: 'XSRF-TOKEN',
        headerName: 'X-XSRF-TOKEN'
      })
    )
  ]
};
```

## Pattern: Data Masking

**Implementation:** `src/app/secure/components/data-exposure/`

**Key Points:**
- Mask credit cards: `****-****-****-1234`
- Mask SSN: `***-**-6789`
- Mask email: `j***e@example.com`
- Redact sensitive fields in logs

**Test File:** `src/app/secure/utils/data-protection.spec.ts`

```typescript
// Reference implementations
function maskCreditCard(card: string): string {
  const digits = card.replace(/\D/g, '');
  return `****-****-****-${digits.slice(-4)}`;
}

function safeLog(label: string, data: object): void {
  const sensitiveFields = ['password', 'token', 'ssn', 'creditCard'];
  // Redact matching fields
  console.log(label, sanitizedData);
}
```

## Running Tests

Verify implementations with:

```bash
# All security tests
npm test

# Specific pattern tests
npm test -- --testPathPattern="html-sanitizer"
npm test -- --testPathPattern="url-validator"
npm test -- --testPathPattern="auth.service"
npm test -- --testPathPattern="csrf-protection"
npm test -- --testPathPattern="data-protection"
```

## Code Review Checklist

When reviewing secure implementations:

- [ ] No `bypassSecurityTrust*()` with user input
- [ ] No tokens in localStorage/sessionStorage
- [ ] No credentials in console.log
- [ ] URL validation with allowlist
- [ ] XSRF configuration present
- [ ] Sensitive data masked in UI
- [ ] Tests cover attack payloads
