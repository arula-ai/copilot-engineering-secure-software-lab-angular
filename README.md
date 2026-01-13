# Angular Security Lab

A hands-on Angular 19 security training lab for learning frontend security vulnerabilities and their mitigations. This lab demonstrates OWASP Top 10 vulnerabilities specific to Angular applications.

## Overview

This lab provides side-by-side examples of **vulnerable** and **secure** Angular components, allowing you to:

- Identify common frontend security vulnerabilities
- Understand how attacks work in practice
- Learn secure coding patterns for Angular applications
- Practice fixing vulnerabilities with AI assistance (GitHub Copilot)

## Vulnerabilities Covered

| Vulnerability | OWASP Category | Components |
|--------------|----------------|------------|
| XSS via `bypassSecurityTrustHtml()` | A03: Injection | xss-bypass |
| XSS via `[innerHTML]` binding | A03: Injection | xss-innerhtml |
| XSS via URL/DOM manipulation | A03: Injection | xss-interpolation |
| JWT in localStorage (XSS accessible) | A02: Crypto Failures | auth service, login-form |
| Missing CSRF/XSRF protection | A01: Access Control | csrf-demo |
| Open redirect vulnerabilities | A01: Access Control | redirect-handler |
| Sensitive data exposure | A02: Crypto Failures | data-exposure |

## Quick Start

### Prerequisites

- Node.js 18+ and npm
- Angular CLI (`npm install -g @angular/cli`)

### Installation

```bash
# Clone the repository
git clone https://github.com/arula-ai/copilot-engineering-secure-software-lab-angular.git
cd copilot-engineering-secure-software-lab-angular

# Install dependencies
npm install

# Start the development server
ng serve
```

Open http://localhost:4200 to view the lab.

### Running the Mock Server (Optional)

For endpoints that demonstrate HTTP-based vulnerabilities:

```bash
npm run mock-server
```

The mock server runs on http://localhost:3001.

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch
```

## Project Structure

```
src/app/
├── vulnerable/                 # Insecure implementations
│   ├── components/
│   │   ├── xss-bypass/        # XSS via bypassSecurityTrust
│   │   ├── xss-innerhtml/     # XSS via innerHTML
│   │   ├── xss-interpolation/ # XSS via URL/DOM
│   │   ├── login-form/        # Insecure auth
│   │   ├── csrf-demo/         # Missing CSRF
│   │   ├── redirect-handler/  # Open redirect
│   │   └── data-exposure/     # Sensitive data leaks
│   └── services/
│       └── auth.service.ts    # JWT in localStorage
│
├── secure/                     # Secure implementations
│   ├── components/            # Secure counterparts
│   ├── services/
│   │   └── auth.service.ts    # HttpOnly cookies
│   └── utils/                 # Security utilities + tests
│
├── shared/
│   └── components/
│       └── home/              # Lab homepage
│
└── app.routes.ts              # Navigation routes
```

## Lab Exercises

### Lab 1: Vulnerability Identification
Navigate to `/vulnerable/*` components and identify security issues. Use the sidebar navigation to explore each vulnerability type.

See: `exercises/lab1-identification/instructions.md`

### Lab 2: Threat Modeling
Create threat models for the vulnerable components using STRIDE methodology.

See: `exercises/lab2-threat-model/instructions.md`

### Lab 3: Secure Implementation
Use GitHub Copilot to help fix vulnerabilities in the secure components.

See: `exercises/lab3-implementation/instructions.md`

## Angular Security Concepts Demonstrated

### XSS Prevention
- Angular's built-in sanitization
- When NOT to use `bypassSecurityTrustHtml()`
- Safe alternatives to `innerHTML`
- URL validation and sanitization

### Authentication Security
- HttpOnly cookies vs localStorage for tokens
- Session management best practices
- Credential handling (never log passwords)

### CSRF Protection
- Angular's `HttpClientXsrfModule`
- SameSite cookie configuration
- Proper HTTP methods for state changes

### Data Protection
- Environment file security
- Masking sensitive data
- Console logging best practices

## Available Routes

| Route | Description |
|-------|-------------|
| `/` | Lab homepage |
| `/vulnerable/xss-bypass` | XSS via bypassSecurityTrust |
| `/vulnerable/xss-innerhtml` | XSS via innerHTML |
| `/vulnerable/xss-interpolation` | XSS via URL handling |
| `/vulnerable/auth` | Insecure authentication |
| `/vulnerable/csrf` | Missing CSRF protection |
| `/vulnerable/redirect` | Open redirect |
| `/vulnerable/data-exposure` | Sensitive data exposure |
| `/secure/xss-bypass` | Secure HTML handling |
| `/secure/xss-innerhtml` | Safe innerHTML alternative |
| `/secure/xss-interpolation` | Safe URL handling |
| `/secure/auth` | Secure authentication |
| `/secure/csrf` | CSRF protected |
| `/secure/redirect` | Safe redirect handling |
| `/secure/data-exposure` | Data protection |

## Security Testing

The lab includes Jest tests that verify secure patterns:

```bash
# Run security tests
npm test
```

Test files are located in `src/app/secure/utils/*.spec.ts` and cover:
- URL validation
- HTML sanitization
- CSRF protection
- Data masking
- Authentication patterns

## Contributing

Contributions are welcome! Please ensure any new vulnerabilities include:
1. A vulnerable component demonstrating the issue
2. A secure component showing the fix
3. Tests verifying the secure implementation
4. Documentation in the component comments

## License

MIT License - See LICENSE file for details.

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Angular Security Guide](https://angular.io/guide/security)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
