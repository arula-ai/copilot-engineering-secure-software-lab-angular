---
description: Generate STRIDE threat model for Angular components (Lab 2)
---

# STRIDE Threat Model Generator

Create a comprehensive STRIDE threat model for the specified Angular component or service.

## Methodology

### 1. Component Analysis
- Identify the component's purpose and data it handles
- Map external interactions (APIs, storage, user input)
- Define trust boundaries

### 2. Data Flow Diagram
Create an ASCII diagram showing:
- Data sources and destinations
- Trust boundary crossings
- Data stores (localStorage, cookies, memory)

### 3. STRIDE Analysis
For each component/flow, analyze:

| Category | Question |
|----------|----------|
| **S**poofing | Can identity be faked? |
| **T**ampering | Can data be modified? |
| **R**epudiation | Can actions be denied? |
| **I**nformation Disclosure | Can data be exposed? |
| **D**enial of Service | Can availability be impacted? |
| **E**levation of Privilege | Can permissions be escalated? |

### 4. DREAD Scoring
Calculate risk scores (1-10 each):
- **D**amage: Impact severity
- **R**eproducibility: Ease of reproducing
- **E**xploitability: Skill required
- **A**ffected Users: Scope of impact
- **D**iscoverability: Ease of finding

## Output Format

```markdown
# Threat Model: [Component Name]

## Component Overview
- **Purpose:** [Description]
- **Data Handled:** [Types of data]
- **Trust Level:** [User/System/Admin]

## Data Flow Diagram

[ASCII diagram]

## STRIDE Analysis

### Spoofing Threats
| Threat | Attack Vector | Impact | Mitigation |
|--------|---------------|--------|------------|
| ... | ... | ... | ... |

[Repeat for T, R, I, D, E]

## Risk Assessment (DREAD)

| Threat | D | R | E | A | D | Total | Priority |
|--------|---|---|---|---|---|-------|----------|
| ... | . | . | . | . | . | .. | Critical/High/Med/Low |

## Attack Tree

Goal: [Primary attack objective]
├── Vector 1
│   └── Steps
└── Vector 2
    └── Steps

## Recommended Mitigations

1. [Mitigation with implementation details]
2. [...]
```

## Usage

```
/create-stride-model [component description]
```

Examples:
```
/create-stride-model auth service that stores JWT in localStorage
/create-stride-model component using bypassSecurityTrustHtml for user comments
/create-stride-model redirect handler with URL parameter
```
