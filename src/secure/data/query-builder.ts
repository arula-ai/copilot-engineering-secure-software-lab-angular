/**
 * SECURE: Query Builder
 *
 * Security Patterns Implemented:
 * - A03: Parameterized queries with prepared statements
 * - Input validation and whitelisting
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */

// SECURE: Type definitions for query components
interface QueryCondition {
  field: string;
  operator: '=' | '!=' | '<' | '>' | '<=' | '>=' | 'LIKE' | 'ILIKE' | 'IN';
  value: unknown;
}

interface QueryConfig {
  allowedTables: string[];
  allowedFields: string[];
  allowedOrderFields: string[];
  maxLimit: number;
}

// SECURE: Default configuration with restrictive whitelist
const DEFAULT_CONFIG: QueryConfig = {
  allowedTables: ['users', 'orders', 'products'],
  allowedFields: ['id', 'name', 'email', 'status', 'created_at', 'updated_at'],
  allowedOrderFields: ['id', 'name', 'created_at', 'updated_at'],
  maxLimit: 1000,
};

export class SecureQueryBuilder {
  private table: string = '';
  private conditions: QueryCondition[] = [];
  private orderByField: string = '';
  private orderDirection: 'ASC' | 'DESC' = 'ASC';
  private limitValue: number = 100;
  private offsetValue: number = 0;
  private params: unknown[] = [];
  private config: QueryConfig;

  constructor(config: Partial<QueryConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // SECURE: Table name must be in whitelist
  from(table: string): SecureQueryBuilder {
    if (!this.config.allowedTables.includes(table)) {
      throw new Error(`Table '${table}' is not allowed. Allowed: ${this.config.allowedTables.join(', ')}`);
    }
    this.table = table;
    return this;
  }

  // SECURE: Field validation and parameterized value
  where(field: string, value: unknown, operator: QueryCondition['operator'] = '='): SecureQueryBuilder {
    // SECURE: Validate field is in whitelist
    if (!this.config.allowedFields.includes(field)) {
      throw new Error(`Field '${field}' is not allowed in WHERE clause`);
    }

    // SECURE: Validate operator
    const validOperators = ['=', '!=', '<', '>', '<=', '>=', 'LIKE', 'ILIKE', 'IN'];
    if (!validOperators.includes(operator)) {
      throw new Error(`Invalid operator: ${operator}`);
    }

    // SECURE: Type check the value
    if (operator === 'IN') {
      if (!Array.isArray(value)) {
        throw new Error('IN operator requires an array value');
      }
      // SECURE: Validate array items are primitive types
      for (const item of value) {
        if (typeof item !== 'string' && typeof item !== 'number') {
          throw new Error('IN array must contain only strings or numbers');
        }
      }
    } else {
      if (value !== null && typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') {
        throw new Error('Value must be a primitive type');
      }
    }

    this.conditions.push({ field, operator, value });
    return this;
  }

  // SECURE: Order by with whitelist validation
  orderBy(field: string, direction: 'ASC' | 'DESC' = 'ASC'): SecureQueryBuilder {
    if (!this.config.allowedOrderFields.includes(field)) {
      throw new Error(`Field '${field}' is not allowed in ORDER BY clause`);
    }

    // SECURE: Direction is type-checked at compile time
    this.orderByField = field;
    this.orderDirection = direction;
    return this;
  }

  // SECURE: Limit with maximum cap
  limit(value: number): SecureQueryBuilder {
    if (typeof value !== 'number' || value < 0 || !Number.isInteger(value)) {
      throw new Error('Limit must be a positive integer');
    }

    // SECURE: Cap at maximum allowed limit
    this.limitValue = Math.min(value, this.config.maxLimit);
    return this;
  }

  // SECURE: Offset validation
  offset(value: number): SecureQueryBuilder {
    if (typeof value !== 'number' || value < 0 || !Number.isInteger(value)) {
      throw new Error('Offset must be a non-negative integer');
    }
    this.offsetValue = value;
    return this;
  }

  // SECURE: Build parameterized query
  build(): { query: string; params: unknown[] } {
    if (!this.table) {
      throw new Error('Table must be specified using from()');
    }

    this.params = [];
    let paramIndex = 1;

    // SECURE: Build SELECT with explicit field list (not *)
    let query = `SELECT ${this.config.allowedFields.join(', ')} FROM ${this.table}`;

    // SECURE: Build WHERE clause with parameterized values
    if (this.conditions.length > 0) {
      const whereClauses: string[] = [];

      for (const condition of this.conditions) {
        if (condition.operator === 'IN' && Array.isArray(condition.value)) {
          // SECURE: Build IN clause with multiple parameters
          const placeholders = condition.value.map(() => `$${paramIndex++}`);
          whereClauses.push(`${condition.field} IN (${placeholders.join(', ')})`);
          this.params.push(...condition.value);
        } else {
          whereClauses.push(`${condition.field} ${condition.operator} $${paramIndex++}`);
          this.params.push(condition.value);
        }
      }

      query += ` WHERE ${whereClauses.join(' AND ')}`;
    }

    // SECURE: ORDER BY uses validated field name
    if (this.orderByField) {
      query += ` ORDER BY ${this.orderByField} ${this.orderDirection}`;
    }

    // SECURE: LIMIT and OFFSET as parameters
    query += ` LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    this.params.push(this.limitValue, this.offsetValue);

    return { query, params: this.params };
  }

  // SECURE: Reset builder for reuse
  reset(): SecureQueryBuilder {
    this.table = '';
    this.conditions = [];
    this.orderByField = '';
    this.orderDirection = 'ASC';
    this.limitValue = 100;
    this.offsetValue = 0;
    this.params = [];
    return this;
  }
}

// SECURE: Example usage:
// const builder = new SecureQueryBuilder({
//   allowedTables: ['users'],
//   allowedFields: ['id', 'email', 'name', 'status'],
// });
//
// const { query, params } = builder
//   .from('users')
//   .where('status', 'active')
//   .where('email', '%@example.com', 'LIKE')
//   .orderBy('created_at', 'DESC')
//   .limit(50)
//   .build();
//
// // query: "SELECT id, email, name, status FROM users WHERE status = $1 AND email LIKE $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4"
// // params: ['active', '%@example.com', 50, 0]
