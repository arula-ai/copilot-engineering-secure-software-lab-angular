/**
 * SECURE: User Repository
 *
 * Security Patterns Implemented:
 * - A03: Parameterized queries prevent SQL injection
 * - A01: Path traversal prevention
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */

import * as path from 'path';

// SECURE: Simulated database interface with parameterized queries
interface DatabaseClient {
  query(sql: string, params: unknown[]): Promise<any[]>;
}

// SECURE: Allowed directories for file operations
const ALLOWED_UPLOAD_DIRS = ['/uploads/avatars', '/uploads/documents'];
const ALLOWED_EXPORT_DIR = '/exports';

export class SecureUserRepository {
  constructor(private db: DatabaseClient) {}

  // SECURE: Parameterized query prevents SQL injection
  async findByEmail(email: string): Promise<any> {
    // SECURE: Input validation
    if (!email || typeof email !== 'string') {
      throw new Error('Invalid email parameter');
    }

    // SECURE: Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new Error('Invalid email format');
    }

    // SECURE: Parameterized query - user input is NEVER concatenated into SQL
    const query = 'SELECT id, email, role, created_at FROM users WHERE email = $1';
    const params = [email];

    console.log('Executing parameterized query with placeholder');
    const results = await this.db.query(query, params);
    return results[0] || null;
  }

  // SECURE: Parameterized search with input validation
  async searchUsers(searchTerm: string, orderBy: string): Promise<any[]> {
    // SECURE: Input validation
    if (!searchTerm || typeof searchTerm !== 'string') {
      throw new Error('Invalid search term');
    }

    // SECURE: Limit search term length to prevent DoS
    if (searchTerm.length > 100) {
      throw new Error('Search term too long');
    }

    // SECURE: Whitelist allowed ORDER BY columns
    const allowedOrderColumns = ['name', 'email', 'created_at'];
    const sanitizedOrderBy = allowedOrderColumns.includes(orderBy) ? orderBy : 'created_at';

    // SECURE: Parameterized LIKE query
    const query = `SELECT id, email, name, created_at FROM users WHERE name ILIKE $1 ORDER BY ${sanitizedOrderBy}`;
    const params = [`%${searchTerm}%`];

    return this.db.query(query, params);
  }

  // SECURE: Safe query building with strict validation
  async findByQuery(filters: Record<string, unknown>): Promise<any[]> {
    // SECURE: Whitelist allowed filter fields
    const allowedFields = ['id', 'email', 'role', 'status'];
    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIndex = 1;

    for (const [field, value] of Object.entries(filters)) {
      // SECURE: Only allow whitelisted fields
      if (!allowedFields.includes(field)) {
        console.warn(`Blocked disallowed filter field: ${field}`);
        continue;
      }

      // SECURE: Type checking on values
      if (typeof value !== 'string' && typeof value !== 'number') {
        throw new Error(`Invalid value type for field ${field}`);
      }

      conditions.push(`${field} = $${paramIndex}`);
      params.push(value);
      paramIndex++;
    }

    if (conditions.length === 0) {
      throw new Error('No valid filter conditions provided');
    }

    const query = `SELECT id, email, role, created_at FROM users WHERE ${conditions.join(' AND ')}`;
    return this.db.query(query, params);
  }

  // SECURE: Safe file export without command injection
  async exportUsers(exportId: string): Promise<string> {
    // SECURE: Validate export ID format (alphanumeric only)
    if (!/^[a-zA-Z0-9_-]+$/.test(exportId)) {
      throw new Error('Invalid export ID format');
    }

    // SECURE: Generate safe filename
    const timestamp = Date.now();
    const filename = `user_export_${exportId}_${timestamp}.csv`;

    // SECURE: Use allowed directory, not user input
    const exportPath = path.join(ALLOWED_EXPORT_DIR, filename);

    // SECURE: Query data and write file programmatically (no shell commands)
    const users = await this.db.query(
      'SELECT id, email, role, created_at FROM users',
      []
    );

    // In production: Write CSV using proper library
    console.log(`Would export ${users.length} users to ${exportPath}`);

    return exportPath;
  }

  // SECURE: Path traversal prevention for file access
  async getUserAvatar(userId: string, filename: string): Promise<string> {
    // SECURE: Validate userId format
    if (!/^[a-zA-Z0-9_-]+$/.test(userId)) {
      throw new Error('Invalid user ID format');
    }

    // SECURE: Validate filename - no path separators allowed
    if (!filename || filename.includes('/') || filename.includes('\\') || filename.includes('..')) {
      throw new Error('Invalid filename');
    }

    // SECURE: Whitelist allowed file extensions
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const ext = path.extname(filename).toLowerCase();
    if (!allowedExtensions.includes(ext)) {
      throw new Error('Invalid file type');
    }

    // SECURE: Construct path safely
    const basePath = '/uploads/avatars';
    const fullPath = path.join(basePath, userId, filename);

    // SECURE: Verify resolved path is within allowed directory
    const resolvedPath = path.resolve(fullPath);
    const resolvedBase = path.resolve(basePath);

    if (!resolvedPath.startsWith(resolvedBase)) {
      throw new Error('Access denied: path traversal detected');
    }

    return resolvedPath;
  }

  // SECURE: Validate and sanitize all database inputs
  private sanitizeInput(input: string, maxLength: number = 255): string {
    if (typeof input !== 'string') {
      throw new Error('Input must be a string');
    }

    // SECURE: Trim and limit length
    const sanitized = input.trim().slice(0, maxLength);

    // SECURE: Remove null bytes
    return sanitized.replace(/\0/g, '');
  }
}
