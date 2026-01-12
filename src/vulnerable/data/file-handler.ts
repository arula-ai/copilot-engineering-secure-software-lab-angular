/**
 * VULNERABLE: File Handler
 *
 * Security Issues:
 * - A01: Broken Access Control (Path Traversal)
 * - A04: Insecure Design
 * - A08: Software and Data Integrity Failures
 */

import * as fs from 'fs';
import * as path from 'path';

export class FileHandler {
  private uploadDir = '/uploads';

  // VULN: Path traversal vulnerability
  readFile(filename: string): string {
    // No validation - allows ../../../etc/passwd
    const filePath = path.join(this.uploadDir, filename);
    return fs.readFileSync(filePath, 'utf-8');
  }

  // VULN: No file type validation
  async uploadFile(filename: string, content: Buffer): Promise<string> {
    // Accepts any file type including .exe, .php, etc.
    const filePath = path.join(this.uploadDir, filename);
    fs.writeFileSync(filePath, content);
    return filePath;
  }

  // VULN: Arbitrary file deletion
  deleteFile(filename: string): void {
    // Can delete system files with path traversal
    const filePath = path.join(this.uploadDir, filename);
    fs.unlinkSync(filePath);
  }

  // VULN: SSRF vulnerability
  async fetchRemoteFile(url: string): Promise<Buffer> {
    // No URL validation - can access internal services
    const response = await fetch(url);
    return Buffer.from(await response.arrayBuffer());
  }

  // VULN: Zip slip vulnerability
  async extractZip(zipPath: string, destDir: string): Promise<void> {
    // Would extract files with paths like ../../evil.sh
    console.log(`Extracting ${zipPath} to ${destDir}`);
  }
}
