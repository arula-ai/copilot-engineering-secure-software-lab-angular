# Copilot Customizations Plan for Angular Security Lab

This document outlines the planned agents, instructions, and prompts to enhance the lab with expert-level GitHub Copilot integration.

## Directory Structure

```
.github/
├── copilot-instructions.md          # Backwards-compatible (all VS Code versions)
├── agents/                          # Custom agents (latest VS Code)
│   ├── security-reviewer.agent.md   # OWASP vulnerability detection
│   ├── xss-hunter.agent.md          # XSS specialization
│   ├── threat-modeler.agent.md      # STRIDE analysis
│   ├── secure-coder.agent.md        # Secure implementation
│   └── lab-guide.agent.md           # Lab navigation assistant
├── chatmodes/                       # Chat modes (older VS Code versions)
│   ├── README.md                    # Usage instructions
│   ├── security-reviewer.md         # Same as agent, no tool config
│   ├── xss-hunter.md
│   ├── threat-modeler.md
│   ├── secure-coder.md
│   └── lab-guide.md
├── instructions/
│   ├── angular-security.instructions.md      # applyTo: **/*.ts
│   ├── owasp-frontend.instructions.md        # applyTo: **/vulnerable/**
│   ├── xss-prevention.instructions.md        # applyTo: **/*.component.ts
│   └── secure-patterns.instructions.md       # applyTo: **/secure/**
└── prompts/
    ├── identify-vulnerabilities.prompt.md    # Lab 1
    ├── create-stride-model.prompt.md         # Lab 2
    ├── fix-xss-vulnerability.prompt.md       # Lab 3
    ├── security-code-review.prompt.md        # General review
    └── generate-attack-tree.prompt.md        # Threat modeling
```

---

## Agents

### 1. security-reviewer.agent.md
**Purpose:** Comprehensive OWASP vulnerability detection for Angular applications

**Capabilities:**
- Identifies all OWASP Top 10 frontend vulnerabilities
- Maps findings to CWE/CVE references
- Provides severity ratings (CVSS-style)
- Suggests remediation with code examples

**Tools:** `read`, `search`, `edit`

### 2. xss-hunter.agent.md
**Purpose:** Specialized XSS vulnerability detection and exploitation analysis

**Capabilities:**
- Detects `bypassSecurityTrust*()` misuse
- Identifies `innerHTML` binding vulnerabilities
- Analyzes DOM manipulation patterns
- Generates proof-of-concept payloads
- Validates sanitization implementations

**Tools:** `read`, `search`

### 3. threat-modeler.agent.md
**Purpose:** STRIDE threat modeling for Angular applications

**Capabilities:**
- Creates data flow diagrams
- Performs STRIDE analysis per component
- Generates attack trees
- Calculates DREAD risk scores
- Identifies trust boundaries

**Tools:** `read`, `search`, `edit`

### 4. secure-coder.agent.md
**Purpose:** Implements secure coding patterns to fix vulnerabilities

**Capabilities:**
- Rewrites vulnerable code with secure patterns
- Implements proper sanitization
- Configures CSRF protection
- Sets up HttpOnly cookie authentication
- Creates data masking utilities

**Tools:** `read`, `search`, `edit`, `execute`

### 5. lab-guide.agent.md
**Purpose:** Navigates students through lab exercises

**Capabilities:**
- Explains vulnerability concepts
- Points to relevant vulnerable/secure components
- Suggests next steps
- Validates exercise completion

**Tools:** `read`, `search`

---

## Instructions

### angular-security.instructions.md
**Applies to:** `**/*.ts`

**Content Focus:**
- Never use `bypassSecurityTrust*()` with user input
- Prefer text content over innerHTML
- Use HttpOnly cookies for authentication
- Validate all URL parameters
- Never log sensitive data

### owasp-frontend.instructions.md
**Applies to:** `**/vulnerable/**`

**Content Focus:**
- OWASP A01-A10 frontend manifestations
- Common Angular security anti-patterns
- Attack vectors for each vulnerability type

### xss-prevention.instructions.md
**Applies to:** `**/*.component.ts`

**Content Focus:**
- Angular's built-in sanitization
- Safe alternatives to innerHTML
- Event handler injection prevention
- URL validation patterns

### secure-patterns.instructions.md
**Applies to:** `**/secure/**`

**Content Focus:**
- Reference implementation patterns
- Test-driven security validation
- Defense-in-depth strategies

---

## Prompts

### identify-vulnerabilities.prompt.md (Lab 1)
Analyzes components for security issues with structured output.

### create-stride-model.prompt.md (Lab 2)
Generates complete STRIDE analysis with attack trees.

### fix-xss-vulnerability.prompt.md (Lab 3)
Provides secure implementation for XSS fixes.

### security-code-review.prompt.md
General-purpose security review with findings table.

### generate-attack-tree.prompt.md
Creates visual attack trees for specific threats.

---

## Backwards Compatibility

### Option 1: copilot-instructions.md
For all VS Code versions, `copilot-instructions.md` provides:
- Core Angular security guidelines
- OWASP reference patterns
- Lab context and file locations
- Vulnerability identification checklist

### Option 2: Chat Modes
For older VS Code versions without agent support, use the chat modes in `.github/chatmodes/`:

| Chat Mode | Equivalent Agent | Usage |
|-----------|-----------------|-------|
| `security-reviewer.md` | `@security-reviewer` | Reference in chat |
| `xss-hunter.md` | `@xss-hunter` | Copy content to chat |
| `threat-modeler.md` | `@threat-modeler` | @workspace reference |
| `secure-coder.md` | `@secure-coder` | Manual invocation |
| `lab-guide.md` | `@lab-guide` | Lab guidance |

**How to use chat modes:**
```
# Method 1: Reference in chat
Use the security-reviewer chat mode from .github/chatmodes/ to analyze this code.

# Method 2: @workspace reference
@workspace Use the instructions in .github/chatmodes/xss-hunter.md to find XSS vulnerabilities.

# Method 3: Copy content
[Copy the chat mode content and paste into Copilot Chat]
```

---

## Usage Examples

### Using Agents (VS Code with Agent Support)
```
@security-reviewer Analyze src/app/vulnerable/components/xss-bypass/
@xss-hunter Find all bypassSecurityTrust usage in the codebase
@threat-modeler Create STRIDE analysis for auth.service.ts
@secure-coder Fix the XSS vulnerability in xss-innerhtml.component.ts
```

### Using Prompts
```
/identify-vulnerabilities src/app/vulnerable/services/auth.service.ts
/create-stride-model auth service with localStorage tokens
/fix-xss-vulnerability innerHTML binding in comment component
```

### Using Instructions
Instructions apply automatically based on file patterns. When editing files in `vulnerable/`, OWASP context is included. When editing `*.component.ts`, XSS prevention guidance is active.
