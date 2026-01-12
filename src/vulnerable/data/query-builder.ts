/**
 * VULNERABLE: Query Builder
 *
 * Security Issues:
 * - A03: Injection vulnerabilities
 */

export class QueryBuilder {
  private table: string = '';
  private conditions: string[] = [];
  private orderByClause: string = '';

  // VULN: Table name from user input
  from(table: string): QueryBuilder {
    this.table = table; // No validation
    return this;
  }

  // VULN: Direct string interpolation
  where(field: string, value: any): QueryBuilder {
    this.conditions.push(`${field} = '${value}'`);
    return this;
  }

  // VULN: Order by injection
  orderBy(field: string, direction: string = 'ASC'): QueryBuilder {
    this.orderByClause = `ORDER BY ${field} ${direction}`;
    return this;
  }

  // VULN: Builds injectable query
  build(): string {
    let query = `SELECT * FROM ${this.table}`;
    if (this.conditions.length > 0) {
      query += ` WHERE ${this.conditions.join(' AND ')}`;
    }
    if (this.orderByClause) {
      query += ` ${this.orderByClause}`;
    }
    return query;
  }
}

// Example vulnerable usage:
// const query = new QueryBuilder()
//   .from(userInput.table)  // Can be "users; DROP TABLE users;--"
//   .where('email', userInput.email)  // Can contain SQL
//   .orderBy(userInput.sortField)  // Can inject SQL
//   .build();
