# Lab 2: Angular Threat Modeling

**Duration:** 30-45 minutes
**Objective:** Create STRIDE threat models for Angular frontend security vulnerabilities.

---

## Prerequisites

- Completed Lab 1
- Understanding of STRIDE methodology
- Lab environment running

---

## STRIDE Reference

| Category | Description | Angular Examples |
|----------|-------------|------------------|
| **S**poofing | Pretending to be someone else | Token theft, session hijacking |
| **T**ampering | Modifying data | DOM manipulation, localStorage tampering |
| **R**epudiation | Denying actions | Missing audit logs |
| **I**nfo Disclosure | Exposing sensitive data | XSS data exfiltration, console logging |
| **D**enial of Service | Making unavailable | Infinite loops, memory exhaustion |
| **E**levation of Privilege | Gaining unauthorized access | Role manipulation, admin bypass |

---

## Part 1: Data Flow Diagram (10 min)

Create a DFD showing data flows and trust boundaries.

**AI Prompt:**
```
Create a data flow diagram for an Angular application with:
- User input → Components
- Components → Services (state management)
- Services → HttpClient → API
- localStorage and cookies as data stores
- Browser trust boundary
- Network trust boundary

Include trust boundary crossing points.
```

**Template:**
```
┌─────────────────────────────────────────────────────────┐
│                      BROWSER                            │
│  ┌───────────────────────────────────────────────────┐ │
│  │              Angular Application                   │ │
│  │  ┌─────────┐    ┌─────────┐    ┌─────────────┐   │ │
│  │  │Component│───▶│ Service │───▶│ HttpClient  │   │ │
│  │  └────▲────┘    └────┬────┘    └──────┬──────┘   │ │
│  │       │              │                 │          │ │
│  │  User Input    localStorage      API Request      │ │
│  └───────────────────────────────────────────────────┘ │
│                                           │            │
└───────────────────────────────────────────┼────────────┘
                                            │
                            ════════════════╪════════════
                                     Trust Boundary
                                            │
                                   ┌────────▼────────┐
                                   │   Backend API   │
                                   └─────────────────┘
```

---

## Part 2: STRIDE Analysis (15 min)

Analyze each vulnerable component using STRIDE.

### XSS Bypass Component

**AI Prompt:**
```
Perform STRIDE analysis for an Angular component that uses
bypassSecurityTrustHtml() with user input.

For each STRIDE category, identify:
- Threat description
- Attack vector
- Impact (High/Medium/Low)
- Mitigation
```

| STRIDE | Threat | Attack Vector | Impact | Mitigation |
|--------|--------|---------------|--------|------------|
| S | Session hijacking | Steal token via XSS | High | HttpOnly cookies |
| T | DOM tampering | Inject malicious HTML | High | Allowlist sanitization |
| R | — | N/A | — | — |
| I | Cookie theft | document.cookie access | High | HttpOnly flag |
| D | Page crash | Large payload injection | Low | Input length limits |
| E | Admin impersonation | Steal admin token | Critical | Token in HttpOnly cookie |

### Authentication Service

**AI Prompt:**
```
STRIDE analysis for an auth service that stores JWT in localStorage:

For each category, consider:
- How can the token be stolen?
- How can roles be manipulated?
- What data could be exposed?
```

**Complete the table:**

| STRIDE | Threat | Attack Vector | Impact | Mitigation |
|--------|--------|---------------|--------|------------|
| S | | | | |
| T | | | | |
| R | | | | |
| I | | | | |
| D | | | | |
| E | | | | |

### Open Redirect Component

**Complete STRIDE analysis for redirect-handler component:**

| STRIDE | Threat | Attack Vector | Impact | Mitigation |
|--------|--------|---------------|--------|------------|
| S | | | | |
| T | | | | |
| I | | | | |
| E | | | | |

---

## Part 3: Attack Trees (10 min)

### Attack Tree 1: Token Theft via XSS

```
Goal: Steal User's Authentication Token
├── XSS via bypassSecurityTrustHtml
│   ├── Inject script tag
│   │   └── Access localStorage.getItem('auth_token')
│   └── Inject img onerror
│       └── Send token to attacker server
├── XSS via innerHTML binding
│   ├── Stored XSS in comments
│   │   └── Token exfiltration on page load
│   └── Reflected XSS via URL
│       └── Phishing link with payload
└── XSS via DOM manipulation
    └── Direct innerHTML assignment
        └── Event handler execution
```

### Create Attack Tree: CSRF Attack

**AI Prompt:**
```
Create an attack tree for a CSRF attack against an Angular
application that doesn't use withXsrfConfiguration().

Goal: Execute unauthorized money transfer
```

---

## Part 4: Risk Assessment (5 min)

Rate threats using DREAD:

| Factor | Scale | Description |
|--------|-------|-------------|
| **D**amage | 1-10 | How bad? |
| **R**eproducibility | 1-10 | How easy to reproduce? |
| **E**xploitability | 1-10 | How easy to launch? |
| **A**ffected Users | 1-10 | How many impacted? |
| **D**iscoverability | 1-10 | How easy to find? |

| Threat | D | R | E | A | D | Total | Priority |
|--------|---|---|---|---|---|-------|----------|
| XSS via bypass | 9 | 10 | 7 | 10 | 8 | 44 | Critical |
| JWT in localStorage | 8 | 10 | 6 | 10 | 7 | 41 | Critical |
| Open redirect | 6 | 10 | 9 | 8 | 9 | 42 | High |
| Missing CSRF | 7 | 8 | 5 | 7 | 6 | 33 | Medium |
| Data in env.ts | | | | | | | |
| Console logging | | | | | | | |

---

## Part 5: Angular-Specific Considerations

### Trust Boundaries in Angular

1. **User Input → Component**: No automatic sanitization
2. **Template Binding → DOM**: Angular sanitizes by default
3. **Service → HttpClient**: Crosses network boundary
4. **localStorage/cookies**: Accessible to any script in same origin

### Angular Security Features

- Built-in XSS sanitization for templates
- `HttpClientXsrfModule` for CSRF protection
- Content Security Policy support
- AOT compilation prevents template injection

### Common Angular Threat Patterns

1. **Sanitizer bypass**: `bypassSecurityTrust*()` methods
2. **DOM access**: `nativeElement.innerHTML`
3. **URL injection**: Unvalidated router navigation
4. **Storage exposure**: Sensitive data in localStorage
5. **Environment leaks**: Secrets in environment.ts

---

## Deliverables

1. **Data Flow Diagram** with trust boundaries
2. **STRIDE Tables** for 3+ components
3. **Attack Tree** for token theft
4. **DREAD Assessment** with prioritization
5. **Top 5 Threats** with mitigations

---

## Validation

Your threat model should identify:
- At least 12 unique threats
- Coverage across all STRIDE categories
- Clear mitigation strategies
- Prioritized by risk

---

## Next Steps

Proceed to Lab 3: Secure Implementation to fix the identified threats.
