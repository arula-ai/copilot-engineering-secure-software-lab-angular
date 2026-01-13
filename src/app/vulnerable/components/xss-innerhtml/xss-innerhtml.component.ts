/**
 * VULNERABLE: XSS via innerHTML binding
 *
 * Security Issues:
 * - A03: Injection (Cross-Site Scripting)
 *
 * This component demonstrates unsafe innerHTML usage patterns.
 * While Angular sanitizes innerHTML by default, the sanitization
 * can be bypassed or incorrectly implemented.
 *
 * DO NOT USE IN PRODUCTION
 */

import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-vulnerable-xss-innerhtml',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="vulnerability-demo">
      <div class="header">
        <h2>VULNERABLE: XSS via innerHTML</h2>
        <span class="badge danger">A03: Injection</span>
      </div>

      <div class="description">
        <p>
          This component demonstrates multiple innerHTML vulnerabilities including
          unsanitized URL parameters and comment rendering.
        </p>
      </div>

      <div class="demo-section">
        <h3>Comment System</h3>
        <p class="context">A "feature-rich" comment system that allows formatting...</p>

        <div class="input-group">
          <label for="comment">Add a comment:</label>
          <textarea
            id="comment"
            [(ngModel)]="newComment"
            rows="3"
            placeholder="Enter your comment (HTML supported)..."
          ></textarea>
          <button (click)="addComment()">Post Comment</button>
        </div>

        <div class="comments-list">
          <h4>Comments ({{ comments.length }})</h4>
          @for (comment of comments; track $index) {
            <div class="comment">
              <div class="comment-author">{{ comment.author }}</div>
              <!-- VULN: innerHTML with user content -->
              <div class="comment-body" [innerHTML]="comment.body"></div>
              <div class="comment-date">{{ comment.date }}</div>
            </div>
          }
        </div>
      </div>

      <div class="demo-section">
        <h3>Search Results (URL Reflection)</h3>
        <p class="context">Search results that reflect the query in the page...</p>

        <div class="input-group">
          <label for="search">Search query:</label>
          <input
            id="search"
            type="text"
            [(ngModel)]="searchQuery"
            placeholder="Enter search term..."
          >
        </div>

        <!-- VULN: Reflecting URL parameters in innerHTML -->
        <div class="search-results">
          <p>Showing results for: <span [innerHTML]="searchQuery"></span></p>
          <p class="no-results">No results found for your query.</p>
        </div>

        <div class="url-hint">
          <strong>Try:</strong> Add <code>?q=&lt;img src=x onerror=alert(1)&gt;</code> to the URL
        </div>
      </div>

      <div class="code-section">
        <h3>Vulnerable Patterns</h3>
        <pre><code>{{ vulnerableCode }}</code></pre>
      </div>

      <div class="explanation">
        <h3>Why This Is Dangerous</h3>
        <ul>
          <li><strong>Event handlers bypass sanitization:</strong> Angular's sanitizer removes &lt;script&gt; but may miss event handlers in some contexts</li>
          <li><strong>URL parameter reflection:</strong> Query strings reflected without encoding enable reflected XSS</li>
          <li><strong>Stored XSS:</strong> Malicious comments are saved and execute for all viewers</li>
          <li><strong>DOM clobbering:</strong> HTML elements can override DOM properties</li>
        </ul>
      </div>
    </div>
  `,
  styles: [`
    .vulnerability-demo { max-width: 800px; }
    .header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
    .header h2 { margin: 0; color: #dc3545; }
    .badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .badge.danger { background: #dc3545; color: white; }
    .description { background: #fff5f5; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; border-left: 4px solid #dc3545; }
    .demo-section { background: #f8f9fa; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; }
    .demo-section h3 { margin-top: 0; }
    .context { color: #666; font-style: italic; }
    .input-group { margin-bottom: 1rem; }
    .input-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
    .input-group textarea, .input-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-family: inherit; }
    .input-group button { margin-top: 0.5rem; padding: 0.5rem 1rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
    .comments-list { margin-top: 1rem; }
    .comment { background: white; padding: 1rem; border-radius: 4px; margin-bottom: 0.5rem; border: 1px solid #ddd; }
    .comment-author { font-weight: 600; color: #333; }
    .comment-body { margin: 0.5rem 0; }
    .comment-date { font-size: 0.75rem; color: #888; }
    .search-results { background: white; padding: 1rem; border-radius: 4px; border: 1px solid #ddd; margin-top: 1rem; }
    .no-results { color: #888; font-style: italic; }
    .url-hint { margin-top: 1rem; padding: 0.75rem; background: #fff3cd; border-radius: 4px; font-size: 0.875rem; }
    .url-hint code { background: #ffe0b2; padding: 0.125rem 0.375rem; border-radius: 4px; }
    .code-section pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .code-section code { font-family: 'Fira Code', monospace; font-size: 0.85rem; }
    .explanation { background: #fff3cd; padding: 1rem; border-radius: 8px; border-left: 4px solid #ffc107; }
    .explanation h3 { margin-top: 0; }
    .explanation ul { margin-bottom: 0; }
  `]
})
export class VulnerableXssInnerhtmlComponent implements OnInit {
  newComment = '';
  searchQuery = '';

  // VULN: Storing user HTML without sanitization
  comments: Array<{ author: string; body: string; date: string }> = [
    {
      author: 'Alice',
      body: '<b>Great article!</b> Really helped me understand the topic.',
      date: '2024-01-10'
    },
    {
      author: 'Attacker',
      // VULN: Stored XSS payload
      body: '<img src="x" onerror="console.log(\'XSS: Cookie stolen -\', document.cookie)">Nice post!',
      date: '2024-01-11'
    }
  ];

  vulnerableCode = `
// VULNERABLE: Multiple innerHTML issues

// 1. Reflecting URL parameters directly
ngOnInit() {
  this.route.queryParams.subscribe(params => {
    this.searchQuery = params['q'] || ''; // No encoding!
  });
}

// Template: <span [innerHTML]="searchQuery"></span>
// Attack: ?q=<img src=x onerror=alert(1)>

// 2. Storing and rendering user HTML
addComment() {
  this.comments.push({
    author: 'User',
    body: this.newComment, // No sanitization!
    date: new Date().toISOString()
  });
}

// Template: <div [innerHTML]="comment.body"></div>
// Attack: <img src=x onerror=alert('Stored XSS!')>
  `.trim();

  constructor(private route: ActivatedRoute) {}

  ngOnInit(): void {
    // VULN: Reflecting URL parameter without encoding
    this.route.queryParams.subscribe(params => {
      if (params['q']) {
        this.searchQuery = params['q'];
      }
    });
  }

  addComment(): void {
    if (this.newComment.trim()) {
      // VULN: No sanitization of user input
      this.comments.push({
        author: 'You',
        body: this.newComment,
        date: new Date().toLocaleDateString()
      });
      this.newComment = '';
    }
  }
}
