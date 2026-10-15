/**
 * An in-memory DynamoDB-shaped document client for TASK-045 tests.
 *
 * Rather than re-implementing TableClient's semantics (cursor pagination,
 * TransactWrite TableName stamping, condition-failure mapping) in every test
 * file, this fake stands in one level lower -- at the `documentClient.send()`
 * boundary `backend/src/db/table.ts` talks to -- so every test wraps it with
 * the REAL `createTableClient`. That means conditional updates, the `ADD`
 * counter, the `TransactWrite` atomic swap and query pagination all run
 * through the production code they are meant to test, with nothing touching a
 * real database.
 *
 * Supports exactly the subset of DynamoDB expression syntax this codebase
 * writes: `SET`/`ADD` update expressions (including one level of nested
 * attribute, e.g. `#payload.#stopOnFailure`), `=`/`<=`/`AND`/`OR`/parentheses/
 * `attribute_not_exists(...)` conditions, and `begins_with` key conditions.
 */
import { createTableClient, CONDITIONAL_CHECK_FAILED, TRANSACTION_CANCELED } from '../../dist/db/table.js';

function keyStr(pk, sk) {
  return `${pk}#${sk}`;
}

function resolveName(names, token) {
  if (names && Object.prototype.hasOwnProperty.call(names, token)) {
    return names[token];
  }
  return token;
}

/** Split `str` on `sep` (a literal substring like ' AND ' or ',') outside parentheses. */
function splitTopLevel(str, sep) {
  const parts = [];
  let depth = 0;
  let current = '';
  let i = 0;
  while (i < str.length) {
    const ch = str[i];
    if (ch === '(') depth += 1;
    if (ch === ')') depth -= 1;
    if (depth === 0 && str.slice(i, i + sep.length) === sep) {
      parts.push(current);
      current = '';
      i += sep.length;
      continue;
    }
    current += ch;
    i += 1;
  }
  parts.push(current);
  return parts.map((p) => p.trim()).filter((p) => p.length > 0);
}

function stripOuterParens(expr) {
  let e = expr.trim();
  while (e.startsWith('(') && e.endsWith(')')) {
    let depth = 0;
    let matches = true;
    for (let i = 0; i < e.length - 1; i += 1) {
      if (e[i] === '(') depth += 1;
      if (e[i] === ')') depth -= 1;
      if (depth === 0) {
        matches = false;
        break;
      }
    }
    if (!matches) break;
    e = e.slice(1, -1).trim();
  }
  return e;
}

/** Evaluate a ConditionExpression (or the condition half of a key expression) against `item`. */
function evaluateExpression(item, expr, names, values) {
  if (!expr) return true;
  return evalExpr(expr);

  function evalExpr(raw) {
    const e = stripOuterParens(raw);
    const orParts = splitTopLevel(e, ' OR ');
    if (orParts.length > 1) {
      return orParts.some((part) => evalExpr(part));
    }
    const andParts = splitTopLevel(e, ' AND ');
    if (andParts.length > 1) {
      return andParts.every((part) => evalExpr(part));
    }
    return evalAtom(stripOuterParens(e));
  }

  function evalAtom(e) {
    let m = e.match(/^attribute_not_exists\(([^)]+)\)$/i);
    if (m) {
      const field = resolveName(names, m[1].trim());
      return item === undefined || item[field] === undefined;
    }
    m = e.match(/^attribute_exists\(([^)]+)\)$/i);
    if (m) {
      const field = resolveName(names, m[1].trim());
      return item !== undefined && item[field] !== undefined;
    }
    m = e.match(/^begins_with\(([^,]+),\s*([^)]+)\)$/i);
    if (m) {
      const field = resolveName(names, m[1].trim());
      const prefix = values[m[2].trim()];
      const actual = item ? item[field] : undefined;
      return typeof actual === 'string' && typeof prefix === 'string' && actual.startsWith(prefix);
    }
    m = e.match(/^(\S+)\s*<=\s*(\S+)$/);
    if (m) {
      const field = resolveName(names, m[1]);
      const val = values[m[2]];
      const actual = item ? item[field] : undefined;
      return actual !== undefined && actual <= val;
    }
    m = e.match(/^(\S+)\s*=\s*(\S+)$/);
    if (m) {
      const field = resolveName(names, m[1]);
      const val = values[m[2]];
      const actual = item ? item[field] : undefined;
      return actual === val;
    }
    // Unknown shape: permissive, so an expression this fake does not model
    // never masks a real failure as a false negative.
    return true;
  }
}

/** Apply a SET/ADD UpdateExpression to a (possibly absent) item, returning the new item. */
function applyUpdate(existing, key, expr, names, values) {
  const item = existing ? JSON.parse(JSON.stringify(existing)) : { ...key };
  if (!expr) return item;

  const setMatch = expr.match(/SET\s+(.+?)(?=\s+ADD\s+|\s+REMOVE\s+|\s+DELETE\s+|$)/is);
  if (setMatch) {
    for (const assignment of splitTopLevel(setMatch[1], ',')) {
      const eq = assignment.indexOf('=');
      if (eq === -1) continue;
      const lhs = assignment.slice(0, eq).trim();
      const rhs = assignment.slice(eq + 1).trim();
      const path = lhs.split('.').map((token) => resolveName(names, token.trim()));
      let target = item;
      for (let i = 0; i < path.length - 1; i += 1) {
        if (typeof target[path[i]] !== 'object' || target[path[i]] === null) {
          target[path[i]] = {};
        }
        target = target[path[i]];
      }
      target[path[path.length - 1]] = values[rhs];
    }
  }

  const addMatch = expr.match(/ADD\s+(.+?)(?=\s+SET\s+|\s+REMOVE\s+|\s+DELETE\s+|$)/is);
  if (addMatch) {
    for (const assignment of splitTopLevel(addMatch[1], ',')) {
      const tokens = assignment.trim().split(/\s+/);
      const field = resolveName(names, tokens[0]);
      const delta = values[tokens[1]];
      item[field] = (typeof item[field] === 'number' ? item[field] : 0) + delta;
    }
  }

  return item;
}

/** Parse a Query's KeyConditionExpression into a predicate over a candidate item. */
function keyPredicate(request) {
  const { KeyConditionExpression, ExpressionAttributeNames: names, ExpressionAttributeValues: values } = request;
  const clauses = splitTopLevel(KeyConditionExpression, ' AND ');
  return (item) => clauses.every((clause) => evaluateExpression(item, clause, names, values));
}

export class FakeDocumentClient {
  constructor() {
    this.items = new Map();
    this.sends = [];
    // When set, caps every Query/Scan page at this many items even when the
    // caller passed no explicit `Limit` -- how a test simulates DynamoDB's
    // own (1 MB response) pagination without a multi-megabyte fixture.
    this.pageSize = undefined;
  }

  /** Test setup helper: seed an item directly, bypassing any condition. */
  seed(item) {
    this.items.set(keyStr(item.pk, item.sk), JSON.parse(JSON.stringify(item)));
  }

  /** Test helper: read an item back by key. */
  peek(pk, sk) {
    const item = this.items.get(keyStr(pk, sk));
    return item ? JSON.parse(JSON.stringify(item)) : undefined;
  }

  async send(command) {
    this.sends.push(command);
    const { operation, input } = command;
    switch (operation) {
      case 'Get':
        return this.handleGet(input);
      case 'Put':
        return this.handlePut(input);
      case 'Update':
        return this.handleUpdate(input);
      case 'Delete':
        return this.handleDelete(input);
      case 'Query':
        return this.handleQuery(input);
      case 'Scan':
        return this.handleQuery(input);
      case 'TransactWrite':
        return this.handleTransactWrite(input);
      default:
        throw new Error(`FakeDocumentClient: unsupported operation ${operation}`);
    }
  }

  handleGet(input) {
    const { pk, sk } = input.Key;
    const item = this.items.get(keyStr(pk, sk));
    return { Item: item ? { ...item } : undefined };
  }

  handlePut(input) {
    const existing = this.items.get(keyStr(input.Item.pk, input.Item.sk));
    if (input.ConditionExpression && !evaluateExpression(existing, input.ConditionExpression, input.ExpressionAttributeNames, input.ExpressionAttributeValues)) {
      const err = new Error(CONDITIONAL_CHECK_FAILED);
      err.name = CONDITIONAL_CHECK_FAILED;
      throw err;
    }
    this.items.set(keyStr(input.Item.pk, input.Item.sk), { ...input.Item });
    return {};
  }

  handleUpdate(input) {
    const { pk, sk } = input.Key;
    const existing = this.items.get(keyStr(pk, sk));
    if (input.ConditionExpression && !evaluateExpression(existing, input.ConditionExpression, input.ExpressionAttributeNames, input.ExpressionAttributeValues)) {
      const err = new Error(CONDITIONAL_CHECK_FAILED);
      err.name = CONDITIONAL_CHECK_FAILED;
      throw err;
    }
    const updated = applyUpdate(existing, { pk, sk }, input.UpdateExpression, input.ExpressionAttributeNames, input.ExpressionAttributeValues);
    this.items.set(keyStr(pk, sk), updated);
    return { Attributes: { ...updated } };
  }

  handleDelete(input) {
    const { pk, sk } = input.Key;
    this.items.delete(keyStr(pk, sk));
    return {};
  }

  handleQuery(input) {
    const usesIndex = typeof input.IndexName === 'string';
    const predicate = input.KeyConditionExpression ? keyPredicate(input) : () => true;
    let matched = [...this.items.values()].filter(predicate);
    const sortField = usesIndex ? 'gsi1sk' : 'sk';
    matched.sort((a, b) => {
      const left = a[sortField] ?? '';
      const right = b[sortField] ?? '';
      return left < right ? -1 : left > right ? 1 : 0;
    });

    let startIndex = 0;
    if (input.ExclusiveStartKey) {
      const startKeyStr = keyStr(input.ExclusiveStartKey.pk, input.ExclusiveStartKey.sk);
      const foundIndex = matched.findIndex((item) => keyStr(item.pk, item.sk) === startKeyStr);
      startIndex = foundIndex === -1 ? 0 : foundIndex + 1;
    }
    let page = matched.slice(startIndex);
    const limit = typeof input.Limit === 'number' ? input.Limit : this.pageSize;
    let lastEvaluatedKey;
    if (typeof limit === 'number' && page.length > limit) {
      page = page.slice(0, limit);
      const last = page[page.length - 1];
      lastEvaluatedKey = { pk: last.pk, sk: last.sk };
    }
    return {
      Items: page.map((item) => ({ ...item })),
      LastEvaluatedKey: lastEvaluatedKey,
    };
  }

  handleTransactWrite(input) {
    const items = input.TransactItems;
    // Every condition is checked before any write is applied, so the
    // transaction is all-or-nothing exactly as DynamoDB promises.
    for (const transactItem of items) {
      const op = transactItem.Update ?? transactItem.Put ?? transactItem.Delete ?? transactItem.ConditionCheck;
      const key = op.Key ?? { pk: op.Item?.pk, sk: op.Item?.sk };
      const existing = this.items.get(keyStr(key.pk, key.sk));
      if (op.ConditionExpression && !evaluateExpression(existing, op.ConditionExpression, op.ExpressionAttributeNames, op.ExpressionAttributeValues)) {
        const err = new Error(TRANSACTION_CANCELED);
        err.name = TRANSACTION_CANCELED;
        throw err;
      }
    }
    for (const transactItem of items) {
      if (transactItem.Update) {
        const op = transactItem.Update;
        const existing = this.items.get(keyStr(op.Key.pk, op.Key.sk));
        const updated = applyUpdate(existing, op.Key, op.UpdateExpression, op.ExpressionAttributeNames, op.ExpressionAttributeValues);
        this.items.set(keyStr(op.Key.pk, op.Key.sk), updated);
      } else if (transactItem.Put) {
        this.items.set(keyStr(transactItem.Put.Item.pk, transactItem.Put.Item.sk), { ...transactItem.Put.Item });
      } else if (transactItem.Delete) {
        this.items.delete(keyStr(transactItem.Delete.Key.pk, transactItem.Delete.Key.sk));
      }
    }
    return {};
  }
}

/** Build a real TableClient (from `dist/db/table.js`) over a fresh FakeDocumentClient. */
export function createFakeTable(tableName = 'mdm-test') {
  const documentClient = new FakeDocumentClient();
  const table = createTableClient({ documentClient, tableName });
  return { table, documentClient };
}
