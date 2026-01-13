# Lab 1: Angular Security Vulnerability Identification

**Duration:** 30-45 minutes
**Objective:** Identify security vulnerabilities in Angular components using AI assistance (GitHub Copilot or Claude).

---

## Prerequisites

- GitHub Copilot or Claude Code extension installed
- Lab environment running (`ng serve`)
- Browser DevTools knowledge

---

## Important: AI-Assisted Workflow

Use AI assistance for analysis:
1. **Copilot Chat** (`Ctrl+Shift+I` / `Cmd+Shift+I`)
2. **Claude Code** or other AI assistants
3. Reference: Open vulnerable components for analysis

---

## Files to Analyze

| # | Component | Route | Time | Focus Areas |
|---|-----------|-------|------|-------------|
| 1 | xss-bypass | /vulnerable/xss-bypass | 8 min | DomSanitizer bypass |
| 2 | xss-innerhtml | /vulnerable/xss-innerhtml | 7 min | innerHTML binding |
| 3 | auth service | /vulnerable/auth | 7 min | Token storage, logging |
| 4 | csrf-demo | /vulnerable/csrf | 5 min | XSRF configuration |
| 5 | redirect-handler | /vulnerable/redirect | 5 min | URL validation |
| 6 | data-exposure | /vulnerable/data-exposure | 5 min | Sensitive data |

---

## Step-by-Step Instructions

### Step 1: XSS via bypassSecurityTrust (8 min)

1. Navigate to `http://localhost:4200/vulnerable/xss-bypass`
2. Open `src/app/vulnerable/components/xss-bypass/xss-bypass.component.ts`

**AI Prompt:**
```
Analyze this Angular component for XSS vulnerabilities.
Focus on:
- Usage of DomSanitizer.bypassSecurityTrust*() methods
- How user input flows to the sanitizer
- What attack payloads would work

For each issue: OWASP category, severity, line numbers, attack scenario.
```

**Test the vulnerability:**
- Click attack payload buttons in the UI
- Check browser console for XSS execution

### Step 2: XSS via innerHTML (7 min)

1. Navigate to `/vulnerable/xss-innerhtml`
2. Open `src/app/vulnerable/components/xss-innerhtml/xss-innerhtml.component.ts`

**AI Prompt:**
```
Review this component for innerHTML-related XSS:
- Stored XSS in comments
- Reflected XSS via URL parameters
- What sanitization is missing?

Show attack payloads for each vector.
```

**Test:**
- Post a comment with: `<img src=x onerror="alert('XSS')">`
- Try URL: `?q=<script>alert(1)</script>`

### Step 3: Authentication Vulnerabilities (7 min)

1. Navigate to `/vulnerable/auth`
2. Open `src/app/vulnerable/services/auth.service.ts`

**AI Prompt:**
```
Identify authentication security issues:
- Where are tokens stored?
- What gets logged to console?
- How is the user's role determined?
- What could an XSS attack steal?

List OWASP categories for each issue.
```

**Test:**
- Log in with demo credentials
- Click "Simulate XSS Token Theft"
- Check DevTools → Application → Local Storage

### Step 4: CSRF/XSRF Issues (5 min)

1. Navigate to `/vulnerable/csrf`
2. Review component and app.config.ts

**AI Prompt:**
```
Check for CSRF vulnerabilities:
- Is withXsrfConfiguration() used?
- Are state-changing operations using POST?
- What SameSite cookie configuration is needed?

Explain how a CSRF attack would work here.
```

### Step 5: Open Redirect (5 min)

1. Navigate to `/vulnerable/redirect`
2. Open `src/app/vulnerable/components/redirect-handler/redirect-handler.component.ts`

**AI Prompt:**
```
Analyze for open redirect vulnerabilities:
- How is returnUrl validated?
- What protocols are blocked?
- How could this be used for phishing?

List attack payloads that would work.
```

### Step 6: Data Exposure (5 min)

1. Navigate to `/vulnerable/data-exposure`
2. Check `src/environments/environment.ts`

**AI Prompt:**
```
Find sensitive data exposure issues:
- What's in environment.ts that shouldn't be?
- What gets logged to console?
- What's stored in localStorage?

Rate severity of each exposure.
```

---

## Response Template

### Component: xss-bypass

| # | OWASP | Severity | Line | Description |
|---|-------|----------|------|-------------|
| 1 | | | | |
| 2 | | | | |

**Attack Scenario:**


---

### Component: xss-innerhtml

| # | OWASP | Severity | Line | Description |
|---|-------|----------|------|-------------|
| 1 | | | | |
| 2 | | | | |

---

### Service: auth.service

| # | OWASP | Severity | Line | Description |
|---|-------|----------|------|-------------|
| 1 | | | | |
| 2 | | | | |

---

### Component: csrf-demo

| # | OWASP | Severity | Line | Description |
|---|-------|----------|------|-------------|
| 1 | | | | |

---

### Component: redirect-handler

| # | OWASP | Severity | Line | Description |
|---|-------|----------|------|-------------|
| 1 | | | | |

---

### Component: data-exposure

| # | OWASP | Severity | Line | Description |
|---|-------|----------|------|-------------|
| 1 | | | | |

---

## Angular Security Patterns to Identify

### XSS Vulnerabilities
```typescript
// Dangerous patterns - look for these:
this.sanitizer.bypassSecurityTrustHtml(userInput)
this.sanitizer.bypassSecurityTrustUrl(userInput)
[innerHTML]="userInput"
element.nativeElement.innerHTML = userInput
```

### Authentication Issues
```typescript
// Dangerous patterns:
localStorage.setItem('token', jwt)
console.log('Password:', password)
const role = decodedToken.role  // Client-side role check
```

### CSRF Red Flags
```typescript
// Missing XSRF configuration:
provideHttpClient()  // Should use withXsrfConfiguration()

// GET for state changes:
this.http.get('/api/delete/' + id)  // Should be DELETE
```

### Data Exposure
```typescript
// Environment file secrets:
apiKey: 'sk_live_...'  // Never in frontend code!

// Console logging sensitive data:
console.log('Credit Card:', cardNumber)
```

---

## Validation

Compare your findings with `answer-key.md`

**Target:** Find at least 10 vulnerabilities across all components.

---

## Next Steps

After completing this lab, proceed to Lab 2: Threat Modeling.
