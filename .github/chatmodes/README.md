# Chat Modes (Backwards Compatible)

These chat modes provide the same functionality as the agents in `.github/agents/` but are compatible with older versions of GitHub Copilot that don't support custom agents.

## How to Use Chat Modes

### Method 1: Reference in Chat
Tell Copilot to use a specific chat mode:
```
Use the security-reviewer chat mode from .github/chatmodes/ to analyze this code.
```

### Method 2: Copy Content
1. Open the chat mode file (e.g., `security-reviewer.md`)
2. Copy the entire content
3. Paste into Copilot Chat as context
4. Then ask your question

### Method 3: @workspace Reference
```
@workspace Use the instructions in .github/chatmodes/security-reviewer.md to review src/app/vulnerable/
```

## Available Chat Modes

| Chat Mode | Description | Use For |
|-----------|-------------|---------|
| `security-reviewer.md` | OWASP vulnerability detection | Finding security issues |
| `xss-hunter.md` | XSS specialization with payloads | XSS analysis |
| `threat-modeler.md` | STRIDE/DREAD analysis | Threat modeling |
| `secure-coder.md` | Secure implementation patterns | Fixing vulnerabilities |
| `lab-guide.md` | Lab navigation assistant | Lab exercises |

## Comparison: Agents vs Chat Modes

| Feature | Agents (`.agent.md`) | Chat Modes (`.md`) |
|---------|---------------------|-------------------|
| VS Code Support | Latest versions | All versions |
| Auto-activation | Yes (`@agent-name`) | No (manual reference) |
| Tool restrictions | Configurable | N/A |
| MCP integration | Yes | No |
| GitHub.com | Coming soon | N/A |

## Example Usage

### Security Review
```
I'm using the security-reviewer chat mode from .github/chatmodes/security-reviewer.md

Please analyze src/app/vulnerable/services/auth.service.ts for security vulnerabilities.
```

### XSS Hunting
```
Using the xss-hunter instructions from .github/chatmodes/xss-hunter.md

Find all XSS vulnerabilities in src/app/vulnerable/components/
```

### Threat Modeling
```
Following the threat-modeler chat mode from .github/chatmodes/threat-modeler.md

Create a STRIDE threat model for the authentication service.
```

### Fixing Vulnerabilities
```
Using the secure-coder patterns from .github/chatmodes/secure-coder.md

Fix the XSS vulnerability in xss-innerhtml.component.ts
```

### Lab Guidance
```
I'm using the lab-guide from .github/chatmodes/lab-guide.md

Help me start Lab 1 - where should I begin?
```

## Migration Path

When your VS Code version supports custom agents:
1. Use `@security-reviewer` instead of referencing the chat mode
2. Use `@xss-hunter` instead of copying content
3. Use `@threat-modeler` for automatic STRIDE analysis
4. etc.

The agents in `.github/agents/` have the same instructions but with additional features like tool restrictions and automatic activation.
