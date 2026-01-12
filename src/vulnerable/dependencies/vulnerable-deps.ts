/**
 * VULNERABLE: Dependency Management
 *
 * Security Issues:
 * - A06: Vulnerable and Outdated Components
 *
 * This file demonstrates issues with vulnerable dependencies.
 * In a real codebase, these would be actual package imports.
 *
 * DO NOT USE IN PRODUCTION
 */

// VULN: Example of using packages with known vulnerabilities
// These version numbers represent historically vulnerable versions

/**
 * VULNERABLE DEPENDENCY EXAMPLES:
 *
 * 1. lodash < 4.17.21 - Prototype Pollution (CVE-2021-23337)
 *    Attack: _.set({}, '__proto__.isAdmin', true)
 *    Impact: Can modify object prototypes, leading to privilege escalation
 *
 * 2. minimist < 1.2.6 - Prototype Pollution (CVE-2021-44906)
 *    Attack: parseArgs(['--__proto__.admin', 'true'])
 *    Impact: Can pollute Object prototype via command line args
 *
 * 3. axios < 0.21.1 - SSRF (CVE-2020-28168)
 *    Attack: Bypass URL validation via DNS rebinding
 *    Impact: Server-side request forgery to internal services
 *
 * 4. jsonwebtoken < 9.0.0 - Algorithm Confusion (CVE-2022-23529)
 *    Attack: Use 'none' algorithm to bypass signature verification
 *    Impact: Token forgery, authentication bypass
 *
 * 5. express-fileupload < 1.2.1 - Prototype Pollution (CVE-2020-7699)
 *    Attack: Upload file with __proto__ in name
 *    Impact: Remote code execution
 *
 * 6. node-serialize - Arbitrary Code Execution (CVE-2017-5941)
 *    Attack: Include function in serialized data
 *    Impact: Remote code execution via deserialization
 */

// VULN: Simulating vulnerable usage patterns

// Pattern 1: Using outdated lodash with prototype pollution vulnerability
export function vulnerableMerge(target: any, source: any): any {
  // VULN: Deep merge without prototype pollution protection
  // In lodash < 4.17.12, this allows __proto__ pollution
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      vulnerableMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Pattern 2: Deserializing untrusted data (like node-serialize)
export function vulnerableDeserialize(serialized: string): any {
  // VULN: Using eval for deserialization allows code execution
  // node-serialize did this internally
  try {
    // This is what vulnerable deserialize libraries do internally
    return eval('(' + serialized + ')');
  } catch {
    return null;
  }
}

// Pattern 3: XML parsing without entity expansion limits (like older xml2js)
export function vulnerableXmlConfig(): object {
  // VULN: Configuration that allows XXE attacks
  return {
    explicitArray: false,
    // VULN: Missing these secure options:
    // xmlMode: true,
    // entityExpansionLimit: 0,
    // dtdValidation: false,
  };
}

// Pattern 4: Regex without ReDoS protection
// VULN: Exponential backtracking on malicious input
export const vulnerableEmailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;

// Pattern 5: Path concatenation without sanitization (like old path-to-regexp)
export function vulnerableRouteMatcher(pattern: string, path: string): boolean {
  // VULN: No validation of pattern - allows ReDoS
  const regex = new RegExp(pattern);
  return regex.test(path);
}

/**
 * HOW TO DETECT VULNERABLE DEPENDENCIES:
 *
 * 1. npm audit
 *    Run: npm audit
 *    Fix: npm audit fix
 *
 * 2. Snyk
 *    Run: npx snyk test
 *
 * 3. OWASP Dependency-Check
 *    Run: dependency-check --project "MyApp" --scan ./
 *
 * 4. GitHub Dependabot
 *    Enable in repository settings
 *
 * 5. Check package age and maintenance
 *    - Last publish date
 *    - Open issues/PRs
 *    - Download trends
 */

/**
 * REMEDIATION STRATEGIES:
 *
 * 1. Regular Updates
 *    - Run npm outdated weekly
 *    - Enable Dependabot alerts
 *    - Subscribe to security advisories
 *
 * 2. Lock File Maintenance
 *    - Commit package-lock.json
 *    - Use npm ci in CI/CD
 *    - Review lock file changes
 *
 * 3. Dependency Minimization
 *    - Audit unused dependencies: npx depcheck
 *    - Prefer built-in over packages
 *    - Choose well-maintained packages
 *
 * 4. Security Policies
 *    - Block packages with critical vulnerabilities
 *    - Require security review for new deps
 *    - Use .npmrc to enforce audit
 */

// Example .npmrc configuration for security
export const secureNpmrcConfig = `
# Require audit to pass before install
audit=true
audit-level=moderate

# Use exact versions
save-exact=true

# Prefer offline packages (verify integrity)
prefer-offline=true
`;
