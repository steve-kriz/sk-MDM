/**
 * A generic in-memory DynamoDB-shaped fake, shared by the TASK-067 (device
 * History) test files. Every write is validated through
 * `assertValidDynamoExpressions`, so a bare reserved word or an undefined
 * placeholder fails a test the same way DynamoDB would reject it (AC17).
 *
 * No real database connection is ever made: this is the only storage a test
 * importing it touches.
 */
import { assertValidDynamoExpressions } from './dynamoExpressions.js';

function splitTopLevel(text) {
  return text
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
}

function clauseOf(expression, word) {
  const match = expression.match(new RegExp(`${word}\\s+(.+?)(?=\\s+(?:SET|REMOVE|ADD|DELETE)\\s|$)`, 'i'));
  return match ? match[1] : null;
}

export class FakeTable {
  constructor() {
    this.items = new Map();
    this.puts = [];
  }

  keyOf(key) {
    return `${key.pk}|${key.sk}`;
  }

  /** Seed an item directly, bypassing put's bookkeeping. */
  seed(item) {
    this.items.set(this.keyOf(item), { ...item });
    return item;
  }

  all() {
    return [...this.items.values()].map((item) => ({ ...item }));
  }

  async get(key) {
    const item = this.items.get(this.keyOf(key));
    return item === undefined ? undefined : { ...item };
  }

  async put(item, fields) {
    assertValidDynamoExpressions(fields);
    this.items.set(this.keyOf(item), { ...item });
    this.puts.push({ ...item });
  }

  async putIfAbsent(item) {
    const key = this.keyOf(item);
    if (this.items.has(key)) {
      return { written: false };
    }
    this.items.set(key, { ...item });
    return { written: true };
  }

  async update(key, fields) {
    assertValidDynamoExpressions(fields);
    const mapKey = this.keyOf(key);
    const existing = this.items.get(mapKey) ?? { ...key };
    const updated = { ...existing };
    const names = fields?.ExpressionAttributeNames ?? {};
    const values = fields?.ExpressionAttributeValues ?? {};
    const expr = fields?.UpdateExpression ?? '';

    const setClause = clauseOf(expr, 'SET');
    if (setClause) {
      for (const part of splitTopLevel(setClause)) {
        const eq = part.indexOf('=');
        if (eq === -1) continue;
        const left = part.slice(0, eq).trim();
        const right = part.slice(eq + 1).trim();
        const attr = left.startsWith('#') ? names[left] : left;
        const value = right.startsWith(':') ? values[right] : right;
        updated[attr] = value;
      }
    }
    const removeClause = clauseOf(expr, 'REMOVE');
    if (removeClause) {
      for (const part of splitTopLevel(removeClause)) {
        const attr = part.trim();
        const name = attr.startsWith('#') ? names[attr] : attr;
        delete updated[name];
      }
    }
    this.items.set(mapKey, updated);
    return { ...updated };
  }

  async delete(key) {
    this.items.delete(this.keyOf(key));
  }

  async query(request) {
    assertValidDynamoExpressions(request);
    const values = request.ExpressionAttributeValues ?? {};
    const expr = request.KeyConditionExpression ?? '';
    let items = this.all();
    if (request.IndexName === 'gsi1') {
      items = items.filter((item) => item.gsi1pk === values[':gsi1pk']);
      const otherKey = Object.keys(values).find((key) => key !== ':gsi1pk');
      if (otherKey !== undefined) {
        if (expr.includes('begins_with')) {
          items = items.filter((item) => typeof item.gsi1sk === 'string' && item.gsi1sk.startsWith(values[otherKey]));
        } else if (expr.includes('<') && !expr.includes('<=')) {
          items = items.filter((item) => typeof item.gsi1sk === 'string' && item.gsi1sk < values[otherKey]);
        } else if (expr.includes('>=')) {
          items = items.filter((item) => typeof item.gsi1sk === 'string' && item.gsi1sk >= values[otherKey]);
        }
      }
    } else {
      items = items.filter((item) => item.pk === values[':pk']);
      const otherKey = Object.keys(values).find((key) => key !== ':pk');
      if (otherKey !== undefined && expr.includes('begins_with')) {
        items = items.filter((item) => typeof item.sk === 'string' && item.sk.startsWith(values[otherKey]));
      }
    }
    return { items, cursor: null };
  }

  /** Every item whose sort key starts with `prefix`. */
  withSkPrefix(prefix) {
    return this.all().filter((item) => typeof item.sk === 'string' && item.sk.startsWith(prefix));
  }
}

/** A table whose `put` throws for any item whose sort key starts with `skPrefix` (AC3/AC15). */
export class PutFailingTable extends FakeTable {
  constructor(skPrefix) {
    super();
    this.skPrefix = skPrefix;
  }

  async put(item, fields) {
    if (typeof item.sk === 'string' && item.sk.startsWith(this.skPrefix)) {
      throw new Error('simulated put failure');
    }
    return super.put(item, fields);
  }
}

/** Capture every `console.warn` line made during `fn`, restoring it afterwards. */
export async function captureWarnings(fn) {
  const warnings = [];
  const original = console.warn;
  console.warn = (line) => warnings.push(line);
  try {
    await fn();
  } finally {
    console.warn = original;
  }
  return warnings;
}
