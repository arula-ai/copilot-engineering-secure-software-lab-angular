# Copilot Secure Development Lab

**Workshop:** Secure Software Development with GitHub Copilot
**Duration:** 90 minutes
**Audience:** Engineers advancing secure coding skills
**Stack:** Node.js, TypeScript, Express

---

## WARNING

This repository contains **intentionally vulnerable code** for educational purposes.

**DO NOT:**
- Deploy this code to production
- Use vulnerable patterns in real applications
- Copy code without fixing vulnerabilities

---

## Copilot-Only Workflow

**All lab work must be completed using GitHub Copilot.** This ensures you learn to leverage AI for security tasks.

### How to Use Copilot in This Lab

1. **Copilot Chat** (`Ctrl+Shift+I` / `Cmd+Shift+I`)
   - Analyze code for vulnerabilities
   - Generate secure implementations
   - Create threat models

2. **Inline Suggestions**
   - Type comments starting with `//` to get suggestions
   - Accept suggestions with `Tab`

3. **Terminal Commands**
   - Use `#runInTerminal` in Copilot Chat
   - Example: `#runInTerminal npm audit`

4. **File References**
   - Use `#file:path/to/file.ts` to include context
   - Use `@workspace` for project-wide queries

**Do NOT manually type code or terminal commands.**

---

## Getting Started

```
# Clone and install (via Copilot Chat)
#runInTerminal npm install

# Build the project
#runInTerminal npm run build

# Run tests
#runInTerminal npm test
```

---

## Lab Structure (90 minutes)

| Time | Lab | Duration | Focus |
|------|-----|----------|-------|
| 0:00 | **Lab 1:** Vulnerability Identification | 30 min | Find OWASP Top 10 issues |
| 0:30 | **Lab 2:** Threat Modeling | 25 min | Create STRIDE threat model |
| 0:55 | **Lab 3:** Secure Implementation | 35 min | Fix vulnerabilities |

---

## Repository Structure

```
copilot-secure-dev-lab/
├── src/
│   ├── vulnerable/           # Intentionally vulnerable code
│   │   ├── auth/             # Authentication vulnerabilities
│   │   ├── api/              # API vulnerabilities
│   │   ├── data/             # Injection vulnerabilities
│   │   ├── session/          # JWT/session vulnerabilities
│   │   └── dependencies/     # A06: Vulnerable components
│   └── secure/               # Reference implementations
│       ├── auth/             # Secure auth patterns
│       ├── api/              # Secure API patterns
│       ├── data/             # Secure data patterns
│       ├── session/          # Secure JWT patterns
│       └── __tests__/        # Security verification tests
├── exercises/
│   ├── lab1-identification/  # Vulnerability hunting
│   ├── lab2-threat-model/    # STRIDE analysis
│   └── lab3-implementation/  # Fixing vulnerabilities
├── threat-models/
│   ├── templates/            # STRIDE template
│   └── examples/             # Completed threat model
└── docs/
    ├── owasp-reference/      # OWASP Top 10 quick reference
    └── checklists/           # Security review checklist
```

---

## OWASP Top 10 Coverage

| Category | Vulnerable Files | Secure Reference |
|----------|-----------------|------------------|
| A01: Access Control | auth-controller.ts, resource-controller.ts | secure/auth/, secure/api/ |
| A02: Cryptography | password-handler.ts, token-manager.ts | secure/auth/, secure/session/ |
| A03: Injection | user-repository.ts, query-builder.ts | secure/data/ |
| A04: Insecure Design | payment-handler.ts | secure/api/payment-handler.ts |
| A05: Misconfiguration | user-api.ts | secure/api/user-api.ts |
| A06: Vulnerable Components | vulnerable-deps.ts | npm audit |
| A07: Authentication | auth-controller.ts, session-manager.ts | secure/auth/ |
| A08: Integrity Failures | token-manager.ts, payment-handler.ts | secure/session/, secure/api/ |
| A09: Logging Failures | auth-controller.ts, payment-handler.ts | secure/auth/, secure/api/ |
| A10: SSRF | resource-controller.ts, file-handler.ts | secure/api/, secure/data/ |

---

## Quick Start for Each Lab

### Lab 1: Vulnerability Identification

Open: `exercises/lab1-identification/instructions.md`

```
# Copilot Chat prompt to start:
@workspace I'm analyzing this codebase for OWASP Top 10 vulnerabilities.
The vulnerable code is in src/vulnerable/.
List all the files I should analyze and the expected vulnerabilities in each.
```

### Lab 2: Threat Modeling

Open: `exercises/lab2-threat-model/instructions.md`

```
# Copilot Chat prompt to start:
Create a STRIDE threat model for an authentication and payment system.
The system includes: Auth Controller, Payment Handler, Session Manager.
Generate a Mermaid architecture diagram and identify threats for each STRIDE category.
```

### Lab 3: Secure Implementation

Open: `exercises/lab3-implementation/instructions.md`

```
# Copilot Chat prompt to start:
#file:src/vulnerable/auth/auth-controller.ts
Refactor this code to fix all security vulnerabilities.
Use patterns from #file:src/secure/auth/auth-controller.ts as reference.
```

---

## Verification

### Run Security Tests

```
#runInTerminal npm test
```

### Run Dependency Audit

```
#runInTerminal npm audit
```

### Build Project

```
#runInTerminal npm run build
```

---

## Key Resources

| Resource | Location |
|----------|----------|
| OWASP Top 10 Reference | `docs/owasp-reference/top-10-summary.md` |
| Security Checklist | `docs/checklists/security-review-checklist.md` |
| STRIDE Template | `threat-models/templates/stride-template.md` |
| Completed Threat Model | `threat-models/examples/auth-payment-system-threat-model.md` |
| Lab 1 Answer Key | `exercises/lab1-identification/answer-key.md` |
| Secure Implementations | `src/secure/` |

---

## Helpful Copilot Prompts

### Security Analysis
```
Analyze this file for OWASP Top 10 vulnerabilities.
For each issue: OWASP category, severity, line number, attack scenario, fix.
```

### Threat Modeling
```
Perform STRIDE analysis for this system.
Identify threats for each category with impact and mitigation.
```

### Secure Refactoring
```
Refactor this code to follow secure coding practices.
Add: input validation, authorization, secure logging, parameterized queries.
```

### Code Review
```
Review this code against the security checklist.
Flag any violations with severity and recommended fix.
```

---

## Support

- **Documentation:** See `docs/` directory
- **Reference Code:** See `src/secure/` directory
- **Answer Keys:** See exercise directories

---

**Remember:** Security is everyone's responsibility. Use Copilot as a tool, but verify all suggestions.
