/**
 * VULNERABLE: User Repository
 *
 * Security Issues:
 * - A03: Injection (SQL Injection)
 * - A04: Insecure Design
 */

export class UserRepository {

  // VULN: SQL Injection - string concatenation
  async findByEmail(email: string): Promise<any> {
    // This would be SQL injection if connected to real DB
    const query = `SELECT * FROM users WHERE email = '${email}'`;
    console.log('Executing query:', query);
    // Simulated - in real app this would execute the injection
    return { email };
  }

  // VULN: SQL Injection in search
  async searchUsers(searchTerm: string, orderBy: string): Promise<any[]> {
    const query = `SELECT * FROM users WHERE name LIKE '%${searchTerm}%' ORDER BY ${orderBy}`;
    console.log('Executing query:', query);
    return [];
  }

  // VULN: NoSQL Injection possibility
  async findByQuery(query: any): Promise<any[]> {
    // Directly uses user input as query
    console.log('MongoDB query:', JSON.stringify(query));
    return [];
  }

  // VULN: Command injection
  async exportUsers(filename: string): Promise<void> {
    // User input in command execution
    const command = `mysqldump users > /tmp/${filename}`;
    console.log('Would execute:', command);
  }

  // VULN: Path traversal
  async getUserAvatar(userId: string, filename: string): Promise<string> {
    // No validation - allows ../../../etc/passwd
    return `/uploads/avatars/${userId}/${filename}`;
  }
}
