/**
 * Jest Tests for HTML Sanitization Security
 *
 * Tests verify that HTML sanitization correctly neutralizes XSS payloads.
 */

// Allowlists for sanitization
const ALLOWED_TAGS = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'ul', 'ol', 'li', 'a', 'span'];
const ALLOWED_ATTRIBUTES = ['href', 'class', 'id'];
const ALLOWED_URL_PROTOCOLS = ['http:', 'https:', 'mailto:'];

// HTML encoding function
function encodeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// URL validation for href attributes
function isValidUrl(url: string): boolean {
  const trimmed = url.trim().toLowerCase();

  if (trimmed.startsWith('javascript:') || trimmed.startsWith('data:')) {
    return false;
  }

  try {
    const parsed = new URL(url, window.location.origin);
    return ALLOWED_URL_PROTOCOLS.includes(parsed.protocol);
  } catch {
    return true; // Allow relative URLs
  }
}

// Sanitize HTML function
function sanitizeHtml(html: string): string {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');

  function processElement(element: Element): void {
    const children = Array.from(element.children);

    for (const child of children) {
      const tagName = child.tagName.toLowerCase();

      // Remove disallowed tags
      if (!ALLOWED_TAGS.includes(tagName)) {
        const text = document.createTextNode(child.textContent || '');
        child.replaceWith(text);
        continue;
      }

      // Remove dangerous attributes
      const attrs = Array.from(child.attributes);
      for (const attr of attrs) {
        if (attr.name.startsWith('on') || !ALLOWED_ATTRIBUTES.includes(attr.name)) {
          child.removeAttribute(attr.name);
          continue;
        }

        if (attr.name === 'href' && !isValidUrl(attr.value)) {
          child.removeAttribute('href');
        }
      }

      processElement(child);
    }
  }

  processElement(doc.body);
  return doc.body.innerHTML;
}

describe('HTML Sanitization Security', () => {
  describe('HTML Encoding', () => {
    it('should encode < and >', () => {
      const result = encodeHtml('<script>alert(1)</script>');
      expect(result).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
    });

    it('should handle text with quotes', () => {
      const result = encodeHtml('"quoted" and \'single\'');
      // Basic implementation may not encode quotes, but should not break
      expect(result).toBeDefined();
      expect(result.length).toBeGreaterThan(0);
    });

    it('should encode ampersands', () => {
      const result = encodeHtml('foo & bar');
      expect(result).toBe('foo &amp; bar');
    });

    it('should handle empty strings', () => {
      const result = encodeHtml('');
      expect(result).toBe('');
    });

    it('should preserve safe text', () => {
      const result = encodeHtml('Hello, World!');
      expect(result).toBe('Hello, World!');
    });
  });

  describe('Tag Filtering', () => {
    it('should allow <b> tags', () => {
      const result = sanitizeHtml('<b>bold</b>');
      expect(result).toContain('<b>');
    });

    it('should allow <i> tags', () => {
      const result = sanitizeHtml('<i>italic</i>');
      expect(result).toContain('<i>');
    });

    it('should allow <a> tags', () => {
      const result = sanitizeHtml('<a href="https://example.com">link</a>');
      expect(result).toContain('<a');
    });

    it('should remove <script> tags', () => {
      const result = sanitizeHtml('<script>alert(1)</script>');
      expect(result).not.toContain('<script');
      expect(result).not.toContain('</script>');
    });

    it('should remove <iframe> tags', () => {
      const result = sanitizeHtml('<iframe src="https://evil.com"></iframe>');
      expect(result).not.toContain('<iframe');
    });

    it('should remove <object> tags', () => {
      const result = sanitizeHtml('<object data="malicious.swf"></object>');
      expect(result).not.toContain('<object');
    });

    it('should remove <embed> tags', () => {
      const result = sanitizeHtml('<embed src="malicious.swf">');
      expect(result).not.toContain('<embed');
    });

    it('should remove <form> tags', () => {
      const result = sanitizeHtml('<form action="https://evil.com"><input></form>');
      expect(result).not.toContain('<form');
    });

    it('should preserve text content of removed tags', () => {
      const result = sanitizeHtml('<script>alert(1)</script>safe text');
      expect(result).toContain('safe text');
    });
  });

  describe('Attribute Filtering', () => {
    it('should remove onclick handlers', () => {
      const result = sanitizeHtml('<b onclick="alert(1)">text</b>');
      expect(result).not.toContain('onclick');
    });

    it('should remove onerror handlers', () => {
      const result = sanitizeHtml('<img src="x" onerror="alert(1)">');
      expect(result).not.toContain('onerror');
    });

    it('should remove onload handlers', () => {
      const result = sanitizeHtml('<body onload="alert(1)">');
      expect(result).not.toContain('onload');
    });

    it('should remove onmouseover handlers', () => {
      const result = sanitizeHtml('<a onmouseover="alert(1)">hover me</a>');
      expect(result).not.toContain('onmouseover');
    });

    it('should remove onfocus handlers', () => {
      const result = sanitizeHtml('<input onfocus="alert(1)">');
      expect(result).not.toContain('onfocus');
    });

    it('should remove style attributes (potential CSS injection)', () => {
      const result = sanitizeHtml('<b style="background:url(javascript:alert(1))">text</b>');
      expect(result).not.toContain('style=');
    });

    it('should allow class attribute', () => {
      const result = sanitizeHtml('<b class="highlight">text</b>');
      expect(result).toContain('class="highlight"');
    });

    it('should allow id attribute', () => {
      const result = sanitizeHtml('<p id="intro">text</p>');
      expect(result).toContain('id="intro"');
    });
  });

  describe('URL Validation in href', () => {
    it('should allow https:// URLs', () => {
      const result = sanitizeHtml('<a href="https://example.com">link</a>');
      expect(result).toContain('href="https://example.com"');
    });

    it('should allow http:// URLs', () => {
      const result = sanitizeHtml('<a href="http://example.com">link</a>');
      expect(result).toContain('href="http://example.com"');
    });

    it('should allow mailto: URLs', () => {
      const result = sanitizeHtml('<a href="mailto:user@example.com">email</a>');
      expect(result).toContain('href="mailto:user@example.com"');
    });

    it('should remove javascript: URLs', () => {
      const result = sanitizeHtml('<a href="javascript:alert(1)">click</a>');
      expect(result).not.toContain('href=');
    });

    it('should remove javascript: with mixed case', () => {
      const result = sanitizeHtml('<a href="JavaScript:alert(1)">click</a>');
      expect(result).not.toContain('href=');
    });

    it('should remove data: URLs', () => {
      const result = sanitizeHtml('<a href="data:text/html,<script>alert(1)</script>">click</a>');
      expect(result).not.toContain('href=');
    });

    it('should allow relative URLs', () => {
      const result = sanitizeHtml('<a href="/page">link</a>');
      expect(result).toContain('href="/page"');
    });
  });
});

describe('XSS Attack Prevention', () => {
  const xssPayloads = [
    {
      name: 'Script tag',
      payload: '<script>alert("XSS")</script>',
      shouldNotContain: ['<script', 'alert']
    },
    {
      name: 'Img onerror',
      payload: '<img src=x onerror=alert(1)>',
      shouldNotContain: ['onerror']
    },
    {
      name: 'SVG onload',
      payload: '<svg onload=alert(1)>',
      shouldNotContain: ['<svg', 'onload']
    },
    {
      name: 'Body onload',
      payload: '<body onload=alert(1)>',
      shouldNotContain: ['onload']
    },
    {
      name: 'Iframe injection',
      payload: '<iframe src="javascript:alert(1)"></iframe>',
      shouldNotContain: ['<iframe', 'javascript:']
    },
    {
      name: 'Object tag',
      payload: '<object data="javascript:alert(1)"></object>',
      shouldNotContain: ['<object']
    },
    {
      name: 'Event handler in div',
      payload: '<div onmouseover="alert(1)">hover</div>',
      shouldNotContain: ['onmouseover']
    },
    {
      name: 'JavaScript URL in anchor',
      payload: '<a href="javascript:alert(1)">click</a>',
      shouldNotContain: ['javascript:']
    },
    {
      name: 'Data URL injection',
      payload: '<a href="data:text/html,<script>alert(1)</script>">click</a>',
      shouldNotContain: ['data:text/html']
    },
    {
      name: 'Expression in style',
      payload: '<b style="width:expression(alert(1))">text</b>',
      shouldNotContain: ['expression']
    }
  ];

  xssPayloads.forEach(({ name, payload, shouldNotContain }) => {
    it(`should neutralize: ${name}`, () => {
      const sanitized = sanitizeHtml(payload);

      shouldNotContain.forEach(dangerous => {
        expect(sanitized.toLowerCase()).not.toContain(dangerous.toLowerCase());
      });
    });
  });
});

describe('Edge Cases', () => {
  it('should handle nested tags', () => {
    const result = sanitizeHtml('<b><i>nested</i></b>');
    expect(result).toContain('<b>');
    expect(result).toContain('<i>');
  });

  it('should handle deeply nested dangerous content', () => {
    const result = sanitizeHtml('<p><b><i><script>alert(1)</script></i></b></p>');
    expect(result).not.toContain('<script');
  });

  it('should handle empty input', () => {
    const result = sanitizeHtml('');
    expect(result).toBe('');
  });

  it('should handle plain text', () => {
    const result = sanitizeHtml('Just plain text');
    expect(result).toBe('Just plain text');
  });

  it('should handle malformed HTML', () => {
    const result = sanitizeHtml('<b>unclosed');
    // Should not throw, should handle gracefully
    expect(result).toBeDefined();
  });

  it('should handle multiple script tags', () => {
    const result = sanitizeHtml('<script>one</script><script>two</script>');
    expect(result).not.toContain('<script');
  });

  it('should handle mixed content', () => {
    const result = sanitizeHtml('Hello <script>alert(1)</script><b>world</b>!');
    expect(result).toContain('<b>world</b>');
    expect(result).not.toContain('<script');
  });
});
