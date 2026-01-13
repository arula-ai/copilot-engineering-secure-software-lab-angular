/**
 * SECURE: Safe innerHTML Handling
 *
 * Security Controls:
 * - A03: Injection Prevention
 *
 * This component demonstrates SECURE patterns for handling innerHTML
 * with proper sanitization and encoding.
 *
 * SAFE FOR PRODUCTION (with proper testing)
 */

import { Component, OnInit, Pipe, PipeTransform } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

// Custom pipe for safe text display
@Pipe({
  name: 'safeText',
  standalone: true
})
export class SafeTextPipe implements PipeTransform {
  transform(value: string): string {
    // HTML encode the text to prevent injection
    const div = document.createElement('div');
    div.textContent = value;
    return div.innerHTML;
  }
}

@Component({
  selector: 'app-secure-xss-innerhtml',
  standalone: true,
  imports: [CommonModule, FormsModule, SafeTextPipe],
  template: `
    <div class="security-demo">
      <div class="header">
        <h2>SECURE: Safe Content Rendering</h2>
        <span class="badge success">A03: Injection Prevention</span>
      </div>

      <div class="description">
        <p>
          This component demonstrates secure patterns for rendering user content
          in comments and search results without XSS vulnerabilities.
        </p>
      </div>

      <div class="demo-section">
        <h3>Comment System (Sanitized)</h3>
        <p class="context">Comments are sanitized before display, allowing only safe formatting...</p>

        <div class="input-group">
          <label for="comment">Add a comment:</label>
          <textarea
            id="comment"
            [(ngModel)]="newComment"
            rows="3"
            placeholder="Use **bold** or *italic* markdown..."
          ></textarea>
          <button (click)="addComment()">Post Comment</button>
        </div>

        <div class="format-hint">
          <strong>Allowed formatting:</strong> **bold**, *italic*, [links](url)
        </div>

        <div class="comments-list">
          <h4>Comments ({{ comments.length }})</h4>
          @for (comment of comments; track $index) {
            <div class="comment">
              <div class="comment-author">{{ comment.author }}</div>
              <!-- SECURE: Sanitized HTML output -->
              <div class="comment-body" [innerHTML]="comment.safeBody"></div>
              <div class="comment-date">{{ comment.date }}</div>
            </div>
          }
        </div>
      </div>

      <div class="demo-section">
        <h3>Search Results (Encoded)</h3>
        <p class="context">Search queries are HTML-encoded before display...</p>

        <div class="input-group">
          <label for="search">Search query:</label>
          <input
            id="search"
            type="text"
            [(ngModel)]="searchQuery"
            placeholder="Enter search term..."
          >
        </div>

        <!-- SECURE: Using text interpolation (auto-escaped) -->
        <div class="search-results">
          <p>Showing results for: <strong>{{ searchQuery }}</strong></p>
          <p class="no-results">No results found for your query.</p>
        </div>

        <div class="security-note">
          <strong>Security Note:</strong> Angular's {{ '{{}}' }} interpolation automatically
          HTML-encodes content, preventing XSS.
        </div>
      </div>

      <div class="demo-section">
        <h3>Attack Payload Tests</h3>
        <p class="context">Test that XSS payloads are properly neutralized...</p>

        <div class="payload-buttons">
          <button (click)="testSearchPayload('<script>alert(1)</script>')">Script Tag</button>
          <button (click)="testSearchPayload('<img src=x onerror=alert(1)>')">Img Onerror</button>
          <button (click)="testCommentPayload('<script>steal(cookies)</script>')">Malicious Comment</button>
        </div>

        @if (testResult) {
          <div class="test-result success">
            <strong>Input:</strong> <code>{{ testResult.input }}</code><br>
            <strong>Output:</strong> <code>{{ testResult.output }}</code><br>
            <span class="success-text">XSS attempt neutralized!</span>
          </div>
        }
      </div>

      <div class="code-section">
        <h3>Secure Implementation</h3>
        <pre><code>{{ secureCode }}</code></pre>
      </div>

      <div class="explanation">
        <h3>Security Controls Applied</h3>
        <ul>
          <li><strong>Default interpolation:</strong> {{ '{{}}' }} auto-escapes HTML entities</li>
          <li><strong>Markdown parsing:</strong> Convert markdown to HTML instead of allowing raw HTML</li>
          <li><strong>Allowlist sanitization:</strong> Only permitted tags/attributes in sanitized output</li>
          <li><strong>URL validation:</strong> Links are validated before rendering</li>
          <li><strong>No bypassSecurityTrust:</strong> Angular's sanitization remains active</li>
        </ul>
      </div>
    </div>
  `,
  styles: [`
    .security-demo { max-width: 800px; }
    .header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
    .header h2 { margin: 0; color: #28a745; }
    .badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .badge.success { background: #28a745; color: white; }
    .description { background: #d4edda; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; border-left: 4px solid #28a745; }
    .demo-section { background: #f8f9fa; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; }
    .demo-section h3 { margin-top: 0; }
    .context { color: #666; font-style: italic; }
    .input-group { margin-bottom: 1rem; }
    .input-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
    .input-group textarea, .input-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-family: inherit; }
    .input-group button { margin-top: 0.5rem; padding: 0.5rem 1rem; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
    .format-hint { padding: 0.5rem; background: #e9ecef; border-radius: 4px; font-size: 0.875rem; margin-bottom: 1rem; }
    .comments-list { margin-top: 1rem; }
    .comment { background: white; padding: 1rem; border-radius: 4px; margin-bottom: 0.5rem; border: 1px solid #ddd; }
    .comment-author { font-weight: 600; color: #333; }
    .comment-body { margin: 0.5rem 0; }
    .comment-date { font-size: 0.75rem; color: #888; }
    .search-results { background: white; padding: 1rem; border-radius: 4px; border: 1px solid #ddd; margin-top: 1rem; }
    .no-results { color: #888; font-style: italic; }
    .security-note { margin-top: 1rem; padding: 0.75rem; background: #d4edda; border-radius: 4px; font-size: 0.875rem; }
    .payload-buttons button { background: #6c757d; color: white; border: none; border-radius: 4px; padding: 0.5rem 1rem; cursor: pointer; margin-right: 0.5rem; margin-bottom: 0.5rem; }
    .test-result { margin-top: 1rem; padding: 1rem; border-radius: 4px; }
    .test-result.success { background: #d4edda; }
    .test-result code { background: #c3e6cb; padding: 0.125rem 0.375rem; border-radius: 4px; word-break: break-all; }
    .success-text { color: #155724; font-weight: 600; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #d4edda; padding: 1rem; border-radius: 8px; border-left: 4px solid #28a745; }
    .explanation h3 { margin-top: 0; }
    .explanation ul { margin-bottom: 0; }
  `]
})
export class SecureXssInnerhtmlComponent implements OnInit {
  newComment = '';
  searchQuery = '';
  testResult: { input: string; output: string } | null = null;

  comments: Array<{ author: string; body: string; safeBody: SafeHtml; date: string }> = [];

  secureCode = `
// SECURE: Multiple defenses against innerHTML XSS

// 1. Use interpolation for text content (auto-escaped)
// Template: <span>{{ userInput }}</span>
// Output: &lt;script&gt; instead of <script>

// 2. Parse markdown instead of allowing HTML
parseMarkdown(text: string): string {
  return text
    .replace(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>')  // **bold**
    .replace(/\\*(.+?)\\*/g, '<em>$1</em>')               // *italic*
    .replace(/\\[(.+?)\\]\\((.+?)\\)/g, (_, text, url) => {
      // Validate URL before creating link
      if (this.isValidUrl(url)) {
        return \`<a href="\${this.encodeHtml(url)}">\${this.encodeHtml(text)}</a>\`;
      }
      return text;
    });
}

// 3. HTML-encode text before including in HTML context
encodeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// 4. Validate URLs
isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url, window.location.origin);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

// 5. For search results, ALWAYS use interpolation
// Template: <p>Results for: {{ searchQuery }}</p>
// NOT: <p>Results for: <span [innerHTML]="searchQuery"></span>
  `.trim();

  constructor(
    private route: ActivatedRoute,
    private sanitizer: DomSanitizer
  ) {}

  ngOnInit(): void {
    // SECURE: URL params displayed via interpolation (auto-escaped)
    this.route.queryParams.subscribe(params => {
      if (params['q']) {
        // Just store the value - interpolation handles encoding
        this.searchQuery = params['q'];
      }
    });

    // Initialize with safe sample comments
    this.addSampleComments();
  }

  private addSampleComments(): void {
    const sampleComments = [
      {
        author: 'Alice',
        body: '**Great article!** Really helped me understand the topic.',
        date: '2024-01-10'
      },
      {
        author: 'Bob',
        body: 'Check out [Angular Security Guide](https://angular.io/guide/security)',
        date: '2024-01-11'
      }
    ];

    for (const comment of sampleComments) {
      this.comments.push({
        ...comment,
        safeBody: this.processComment(comment.body)
      });
    }
  }

  addComment(): void {
    if (this.newComment.trim()) {
      const safeBody = this.processComment(this.newComment);

      this.comments.push({
        author: 'You',
        body: this.newComment,
        safeBody,
        date: new Date().toLocaleDateString()
      });

      this.newComment = '';
    }
  }

  private processComment(text: string): SafeHtml {
    // First, HTML-encode everything to neutralize any HTML
    let safe = this.encodeHtml(text);

    // Then parse allowed markdown patterns
    safe = this.parseMarkdown(safe);

    // Angular sanitizes the result again when binding to innerHTML
    return safe;
  }

  private encodeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  private parseMarkdown(text: string): string {
    // Parse **bold**
    text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

    // Parse *italic*
    text = text.replace(/\*(.+?)\*/g, '<em>$1</em>');

    // Parse [text](url) - with URL validation
    text = text.replace(/\[(.+?)\]\((.+?)\)/g, (match, linkText, url) => {
      // Decode HTML entities in URL for validation
      const decodedUrl = this.decodeHtml(url);
      if (this.isValidUrl(decodedUrl)) {
        return `<a href="${url}" rel="noopener noreferrer">${linkText}</a>`;
      }
      // Invalid URL - just show the text
      return linkText;
    });

    return text;
  }

  private decodeHtml(text: string): string {
    const textarea = document.createElement('textarea');
    textarea.innerHTML = text;
    return textarea.value;
  }

  private isValidUrl(url: string): boolean {
    try {
      const parsed = new URL(url, window.location.origin);
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  }

  testSearchPayload(payload: string): void {
    // Show that interpolation properly encodes the payload
    const div = document.createElement('div');
    div.textContent = payload;

    this.testResult = {
      input: payload,
      output: div.innerHTML
    };
  }

  testCommentPayload(payload: string): void {
    const processed = this.encodeHtml(payload);

    this.testResult = {
      input: payload,
      output: processed
    };
  }
}
