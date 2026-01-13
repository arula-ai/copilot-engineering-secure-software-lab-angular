---
description: XSS prevention patterns for Angular components
applyTo: "**/*.component.ts"
---

# XSS Prevention for Angular Components

## Angular's Built-in Protection

Angular automatically sanitizes values in templates:
- Text interpolation `{{ }}` - HTML encoded
- Property binding `[property]` - Context-aware sanitization
- Attribute binding `[attr.x]` - Sanitized

## Dangerous Patterns

### Sanitizer Bypass (NEVER with user input)
```typescript
// DANGEROUS - Bypasses all protection
this.sanitizer.bypassSecurityTrustHtml(userInput)
this.sanitizer.bypassSecurityTrustUrl(userInput)
this.sanitizer.bypassSecurityTrustScript(userInput)
this.sanitizer.bypassSecurityTrustStyle(userInput)
this.sanitizer.bypassSecurityTrustResourceUrl(userInput)
```

### innerHTML Binding
```typescript
// DANGEROUS - Can execute scripts via event handlers
<div [innerHTML]="userContent"></div>
```

### Direct DOM Access
```typescript
// DANGEROUS - Bypasses Angular entirely
@ViewChild('container') container: ElementRef;
this.container.nativeElement.innerHTML = userInput;
```

### URL Injection
```typescript
// DANGEROUS - javascript: protocol execution
<a [href]="userUrl">Link</a>
```

## Safe Alternatives

### Use Text Content
```typescript
// SAFE - HTML encoded automatically
<div>{{ userContent }}</div>
```

### Custom Sanitizer with Allowlist
```typescript
// SAFE - Only allows specific tags
const ALLOWED_TAGS = ['b', 'i', 'u', 'p', 'br'];

sanitizeHtml(html: string): string {
  // Parse and filter to allowed tags only
  // Remove all attributes except href on <a>
  // Validate href protocols
}
```

### SafeHtml Pipe (for trusted content only)
```typescript
// SAFE - For static, trusted HTML only
@Pipe({ name: 'safeHtml' })
export class SafeHtmlPipe implements PipeTransform {
  constructor(private sanitizer: DomSanitizer) {}

  transform(html: string): SafeHtml {
    // Only use for TRUSTED content (not user input)
    return this.sanitizer.bypassSecurityTrustHtml(html);
  }
}
```

### URL Validation
```typescript
// SAFE - Validates before use
validateUrl(url: string): string {
  const ALLOWED_PROTOCOLS = ['http:', 'https:', 'mailto:'];
  try {
    const parsed = new URL(url);
    if (ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
      return url;
    }
  } catch {}
  return '';
}
```

## Component Security Checklist

When creating or reviewing components:

1. **User Input Sources**
   - [ ] Form inputs sanitized
   - [ ] URL parameters validated
   - [ ] Query params encoded
   - [ ] Route params validated

2. **Output Points**
   - [ ] No `bypassSecurityTrust*` with user data
   - [ ] No `innerHTML` with user data
   - [ ] No `nativeElement.innerHTML`
   - [ ] URLs validated before navigation

3. **Event Handlers**
   - [ ] No inline `on*` handlers in templates
   - [ ] Event data sanitized before use

4. **Third-party Content**
   - [ ] Iframe sandbox attributes set
   - [ ] External content validated
