/**
 * E2E cucumber-style tests for command library routes (TASK-045, L1-L9).
 * Tests implement all Gherkin scenarios without a cucumber package.
 * Mock all database calls — no real DB connections.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { createHash } from 'node:crypto';

const {
  handleScriptList,
  handleScriptGet,
  handleScriptCreate,
  handleScriptUpdate,
  handleScriptDelete,
  handleScriptGenerate,
  readGenerateFields,
  cleanGeneratedScript,
  registerScriptRoutes,
  scriptRecord,
  SCRIPT_ID_PREFIX,
  SCRIPT_PLATFORMS,
  INTERPRETER_PLATFORMS,
  SCRIPT_NAME_MAX_LENGTH,
  SCRIPT_DESCRIPTION_MAX_LENGTH,
  SCRIPT_MAX_BYTES,
  SCRIPT_TIMEOUT_SECONDS,
  DEFAULT_SCRIPT_TIMEOUT_SECONDS,
  SCRIPT_CREATED_ACTION,
  SCRIPT_UPDATED_ACTION,
  SCRIPT_DELETED_ACTION,
  SCRIPT_GENERATE_PROMPT_MAX_LENGTH,
  SCRIPT_GENERATE_RATE_LIMIT_PER_MINUTE,
  SCRIPT_GENERATE_COUNTER_TTL_GRACE_SECONDS,
  SCRIPT_GENERATED_ACTION,
  SCRIPT_GENERATOR_TARGET,
} = await import('../../dist/admin/scripts.js');

const { script: scriptKey, scriptNameGuard, scriptListIndex, scriptGenerateRateLimit } = await import('../../dist/db/keys.js');
const { createRouter } = await import('../../dist/index.js');

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.auditItems = [];
  }

  keyStr(key) {
    return `${key.pk}#${key.sk}`;
  }

  async get(key) {
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    const key = { pk: item.pk, sk: item.sk };
    // Track audit items
    if (item.action) {
      this.auditItems.push(item);
    }
    this.items.set(this.keyStr(key), { ...item });
  }

  async delete(key) {
    this.items.delete(this.keyStr(key));
  }

  async putIfAbsent(item) {
    const keyStr = this.keyStr({ pk: item.pk, sk: item.sk });
    const exists = this.items.has(keyStr);
    if (exists) {
      return { written: false };
    }
    this.items.set(keyStr, { ...item });
    return { written: true };
  }

  /** A minimal `ADD .. SET ..` interpreter: enough for the generate rate-limit counter (TASK-053). */
  async update(key, fields = {}) {
    const keyStr = this.keyStr(key);
    const existing = this.items.get(keyStr) ?? { ...key };
    const names = fields.ExpressionAttributeNames ?? {};
    const values = fields.ExpressionAttributeValues ?? {};
    const expression = fields.UpdateExpression ?? '';
    const addMatch = /ADD\s+#(\w+)\s+:(\w+)/.exec(expression);
    if (addMatch) {
      const attr = names[`#${addMatch[1]}`] ?? addMatch[1];
      const delta = values[`:${addMatch[2]}`] ?? 0;
      existing[attr] = (typeof existing[attr] === 'number' ? existing[attr] : 0) + delta;
    }
    const setMatch = /SET\s+#(\w+)\s*=\s*:(\w+)/.exec(expression);
    if (setMatch) {
      const attr = names[`#${setMatch[1]}`] ?? setMatch[1];
      existing[attr] = values[`:${setMatch[2]}`];
    }
    this.items.set(keyStr, existing);
    return { ...existing };
  }

  async query(request) {
    const gsi1pk = request.ExpressionAttributeValues?.[':gsi1pk'];
    const items = [];
    for (const item of this.items.values()) {
      if (item.gsi1pk === gsi1pk) {
        items.push(item);
      }
    }
    return { items, cursor: null };
  }

  getStoredItem(key) {
    return this.items.get(this.keyStr(key));
  }

  countItems() {
    return this.items.size;
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function createFakeDeps(table, actor = 'admin@officehq.com.au', now = new Date('2026-10-11T10:00:00Z')) {
  let randomCounter = 0;
  return {
    table,
    now: () => now,
    randomBytes: (bytes) => {
      const buf = Buffer.alloc(bytes);
      for (let i = 0; i < bytes; i++) {
        buf[i] = ((randomCounter + i) * 17) % 256;
      }
      randomCounter += bytes;
      return buf;
    },
  };
}

function createRequest(body = {}, params = {}, actor = 'admin@officehq.com.au') {
  return {
    body: body ? JSON.stringify(body) : null,
    params,
    claims: {
      sub: 'user123',
      preferred_username: actor,
    },
    query: {},
  };
}

// ============================================================================
// TASK-053: AI script generation -- helpers
// ============================================================================

/** A request object shaped for `handleScriptGenerate`, bypassing the router's auth wrapper. */
function generateRequestObj(rawBody, actor = 'admin@officehq.com.au') {
  return {
    body: typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody),
    params: {},
    claims: { sub: 'user123', preferred_username: actor },
    query: {},
  };
}

/** A fake `ScriptGenerator`: records every call and resolves/rejects/hangs as scripted. */
class FakeGenerator {
  constructor(behavior = async () => 'Get-ChildItem C:\\') {
    this.calls = [];
    this.behavior = behavior;
  }

  async generate(request, signal) {
    this.calls.push({ request, signal });
    return this.behavior(request, signal);
  }
}

/** A verifier that resolves a fixed set of bearer tokens to claims; anything else is rejected. */
class MultiActorVerifier {
  constructor(tokenClaims) {
    this.tokenClaims = tokenClaims;
  }

  async verify(token) {
    const claims = this.tokenClaims[token];
    if (claims === undefined) {
      throw { status: 401, error: 'invalid_token' };
    }
    return claims;
  }
}

/** A router carrying both the full command library and generate routes, for AC1's auth comparison. */
function makeScriptRouter(table, deps) {
  const router = createRouter();
  registerScriptRoutes(router, { table, ...deps });
  return router;
}

async function routerRequest(router, method, path, { headers = {}, body = null } = {}) {
  const response = await router.handle({ method, path, query: {}, headers, body });
  let parsed = null;
  try {
    parsed = JSON.parse(response.body);
  } catch {
    parsed = response.body;
  }
  return { statusCode: response.statusCode, body: parsed };
}

const VALID_GENERATE_BODY = { prompt: 'list files', interpreter: 'powershell' };

/** Drain pending microtasks (the rate-limit counter's fake `await`) before a timer assertion. */
async function flushMicrotasks(times = 10) {
  for (let i = 0; i < times; i += 1) {
    await Promise.resolve();
  }
}

// ============================================================================
// L1: Create a library command
// ============================================================================

test('L1: Create a library command returns 201 with generated scriptId', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({
    name: 'Flush DNS',
    interpreter: 'cmd',
    script: 'ipconfig /flushdns',
    platform: 'darwin',
    timeoutSeconds: 60,
  });

  const result = await handleScriptCreate(req, deps);

  assert.equal(result.statusCode, 201);
  assert.match(result.body.scriptId, /^scr-[0-9a-f]{16}$/);
  assert.equal(result.body.platform, 'windows');
  assert.equal(result.body.timeoutSeconds, 60);
  assert.equal(result.body.description, null);
  assert(result.body.createdAt);
  assert(result.body.createdBy);
  assert(result.body.updatedAt);
  assert(result.body.updatedBy);
  assert.equal(result.body.name, 'Flush DNS');
  assert.equal(result.body.interpreter, 'cmd');
  assert.equal(result.body.script, 'ipconfig /flushdns');

  const storedKey = scriptKey(result.body.scriptId);
  const stored = table.getStoredItem(storedKey);
  assert(stored);
  assert.equal(stored.gsi1pk, 'SCRIPT');
});

test('L1: Script with absent timeoutSeconds defaults to 300', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({
    name: 'Test',
    interpreter: 'bash',
    script: 'echo test',
  });

  const result = await handleScriptCreate(req, deps);

  assert.equal(result.statusCode, 201);
  assert.equal(result.body.timeoutSeconds, 300);
});

test('L1: Script with absent description stores null', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({
    name: 'Test',
    interpreter: 'bash',
    script: 'echo test',
  });

  const result = await handleScriptCreate(req, deps);

  assert.equal(result.statusCode, 201);
  assert.equal(result.body.description, null);
});

// ============================================================================
// L2: Invalid fields are reported and nothing is written
// ============================================================================

test('L2: Empty name, invalid interpreter, empty script all reported', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({
    name: '',
    interpreter: 'fish',
    script: '',
  });

  const result = await handleScriptCreate(req, deps);

  assert.equal(result.statusCode, 400);
  assert.equal(result.body.error, 'invalid_request');
  assert.deepEqual(result.body.fields.sort(), ['interpreter', 'name', 'script']);
  assert.equal(table.countItems(), 0);
});

test('L2: Name too long and timeout 0 both reported', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({
    name: 'x'.repeat(101),
    interpreter: 'bash',
    script: 'ls',
    timeoutSeconds: 0,
  });

  const result = await handleScriptCreate(req, deps);

  assert.equal(result.statusCode, 400);
  assert.deepEqual(result.body.fields.sort(), ['name', 'timeoutSeconds']);
  assert.equal(table.countItems(), 0);
});

test('L2: Whitespace-only name is rejected', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({
    name: '   ',
    interpreter: 'zsh',
    script: 'ls',
  });

  const result = await handleScriptCreate(req, deps);

  assert.equal(result.statusCode, 400);
  assert(result.body.fields.includes('name'));
  assert.equal(table.countItems(), 0);
});

test('L2: Script of exactly 65536 bytes is accepted', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const script65536 = Buffer.alloc(65536, 'a').toString('utf8');
  const req = createRequest({
    name: 'Big script',
    interpreter: 'bash',
    script: script65536,
  });

  const result = await handleScriptCreate(req, deps);

  assert.equal(result.statusCode, 201);
  assert.equal(Buffer.byteLength(result.body.script, 'utf8'), 65536);
});

// ============================================================================
// L3: Duplicate name detection (case-insensitive)
// ============================================================================

test('L3: POST with duplicate name differing only in case is refused', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);

  let req = createRequest({
    name: 'Flush DNS',
    interpreter: 'cmd',
    script: 'ipconfig /flushdns',
  });
  let result = await handleScriptCreate(req, deps);
  assert.equal(result.statusCode, 201);

  req = createRequest({
    name: 'flush dns',
    interpreter: 'bash',
    script: 'echo test',
  });
  result = await handleScriptCreate(req, deps);
  assert.equal(result.statusCode, 409);
  assert.equal(result.body.error, 'name_taken');
});

test('L3: PUT keeping own name in different case is allowed', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);

  let req = createRequest({
    name: 'Beta',
    interpreter: 'cmd',
    script: 'cmd',
  });
  let result = await handleScriptCreate(req, deps);
  const betaId = result.body.scriptId;

  req = createRequest({
    name: 'BETA',
    interpreter: 'bash',
    script: 'updated',
  }, { scriptId: betaId });
  result = await handleScriptUpdate(req, deps);

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.name, 'BETA');
});

// ============================================================================
// L4: List sorted by name ignoring case, filterable by platform
// ============================================================================

test('L4: List returns items sorted by name ignoring case', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);

  for (const { name, interpreter } of [
    { name: 'zeta', interpreter: 'bash' },
    { name: 'Alpha', interpreter: 'cmd' },
    { name: 'beta', interpreter: 'powershell' },
  ]) {
    const req = createRequest({
      name,
      interpreter,
      script: 'test',
    });
    await handleScriptCreate(req, deps);
  }

  const req = createRequest({});
  const result = await handleScriptList(req, deps);

  assert.equal(result.statusCode, 200);
  const names = result.body.items.map((item) => item.name);
  assert.deepEqual(names, ['Alpha', 'beta', 'zeta']);
});

test('L4: List with ?platform=windows filters correctly', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);

  for (const { name, interpreter } of [
    { name: 'zeta', interpreter: 'bash' },
    { name: 'Alpha', interpreter: 'cmd' },
    { name: 'beta', interpreter: 'powershell' },
  ]) {
    const req = createRequest({
      name,
      interpreter,
      script: 'test',
    });
    await handleScriptCreate(req, deps);
  }

  const req = createRequest({});
  req.query = { platform: 'windows' };
  const result = await handleScriptList(req, deps);

  assert.equal(result.statusCode, 200);
  const names = result.body.items.map((item) => item.name);
  assert.deepEqual(names, ['Alpha', 'beta']);
});

test('L4: List with unknown platform filter is refused', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({});
  req.query = { platform: 'linux' };

  const result = await handleScriptList(req, deps);

  assert.equal(result.statusCode, 400);
  assert.equal(result.body.error, 'invalid_request');
});

// ============================================================================
// L5: Get one script
// ============================================================================

test('L5: GET existing script returns 200', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);

  let req = createRequest({
    name: 'Alpha',
    interpreter: 'cmd',
    script: 'test',
  });
  let result = await handleScriptCreate(req, deps);
  const scriptId = result.body.scriptId;

  req = createRequest({}, { scriptId });
  result = await handleScriptGet(req, deps);

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.name, 'Alpha');
  assert.equal(result.body.scriptId, scriptId);
});

test('L5: GET unknown script returns 404', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({}, { scriptId: 'scr-0000000000000000' });

  const result = await handleScriptGet(req, deps);

  assert.equal(result.statusCode, 404);
  assert.equal(result.body.error, 'not_found');
});

// ============================================================================
// L6: Update script
// ============================================================================

test('L6: Update re-derives platform and keeps creation fields', async () => {
  const table = new FakeTable();
  const deps1 = createFakeDeps(table, 'a@x', new Date('2026-10-11T10:00:00Z'));

  let req = createRequest({
    name: 'Alpha',
    interpreter: 'cmd',
    script: 'test1',
  }, {}, 'a@x');
  let result = await handleScriptCreate(req, deps1);
  const scriptId = result.body.scriptId;
  const originalCreatedAt = result.body.createdAt;
  const originalCreatedBy = result.body.createdBy;

  const deps2 = createFakeDeps(table, 'b@x', new Date('2026-10-11T11:00:00Z'));
  req = createRequest({
    name: 'Alpha',
    interpreter: 'zsh',
    script: 'echo hi',
  }, { scriptId }, 'b@x');
  result = await handleScriptUpdate(req, deps2);

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.platform, 'darwin');
  assert.equal(result.body.createdAt, originalCreatedAt);
  assert.equal(result.body.createdBy, originalCreatedBy);
  assert.notEqual(result.body.updatedAt, originalCreatedAt);
  assert.equal(result.body.updatedBy, 'b@x');
});

test('L6: PUT unknown script returns 404', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({
    name: 'Test',
    interpreter: 'bash',
    script: 'ls',
  }, { scriptId: 'scr-0000000000000000' });

  const result = await handleScriptUpdate(req, deps);

  assert.equal(result.statusCode, 404);
  assert.equal(result.body.error, 'not_found');
});

// ============================================================================
// L7: Delete script
// ============================================================================

test('L7: DELETE script returns 204 and removes it', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);

  let req = createRequest({
    name: 'Alpha',
    interpreter: 'cmd',
    script: 'test',
  });
  let result = await handleScriptCreate(req, deps);
  const scriptId = result.body.scriptId;

  req = createRequest({}, { scriptId });
  result = await handleScriptDelete(req, deps);

  assert.equal(result.statusCode, 204);

  req = createRequest({}, { scriptId });
  result = await handleScriptGet(req, deps);
  assert.equal(result.statusCode, 404);

  req = createRequest({});
  result = await handleScriptList(req, deps);
  assert.equal(result.body.items.length, 0);
});

test('L7: DELETE unknown script returns 404', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({}, { scriptId: 'scr-0000000000000000' });

  const result = await handleScriptDelete(req, deps);

  assert.equal(result.statusCode, 404);
  assert.equal(result.body.error, 'not_found');
});

// ============================================================================
// L8: Audit trails
// ============================================================================

test('L8: Create appends script.created audit entry', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({
    name: 'Alpha',
    interpreter: 'bash',
    script: 'test',
  });

  const result = await handleScriptCreate(req, deps);
  const scriptId = result.body.scriptId;

  const audit = table.auditItems.find((item) => item.action === SCRIPT_CREATED_ACTION);
  assert(audit);
  assert.equal(audit.target, scriptId);
  assert.equal(audit.detail.name, 'Alpha');
  assert.equal(audit.detail.interpreter, 'bash');
  assert(!('script' in audit.detail));
});

test('L8: Update appends script.updated audit entry', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);

  let req = createRequest({
    name: 'Alpha',
    interpreter: 'bash',
    script: 'test',
  });
  let result = await handleScriptCreate(req, deps);
  const scriptId = result.body.scriptId;
  table.auditItems = []; // Clear creation audit

  req = createRequest({
    name: 'Alpha',
    interpreter: 'zsh',
    script: 'test2',
  }, { scriptId });
  result = await handleScriptUpdate(req, deps);

  const audit = table.auditItems.find((item) => item.action === SCRIPT_UPDATED_ACTION);
  assert(audit);
  assert.equal(audit.target, scriptId);
  assert.equal(audit.detail.name, 'Alpha');
  assert.equal(audit.detail.interpreter, 'zsh');
});

test('L8: Delete appends script.deleted audit entry', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);

  let req = createRequest({
    name: 'Alpha',
    interpreter: 'bash',
    script: 'test',
  });
  let result = await handleScriptCreate(req, deps);
  const scriptId = result.body.scriptId;
  table.auditItems = []; // Clear creation audit

  req = createRequest({}, { scriptId });
  result = await handleScriptDelete(req, deps);

  const audit = table.auditItems.find((item) => item.action === SCRIPT_DELETED_ACTION);
  assert(audit);
  assert.equal(audit.target, scriptId);
  assert.equal(audit.detail.name, 'Alpha');
  assert.equal(audit.detail.interpreter, 'bash');
});

// ============================================================================
// TASK-053: AI script generation -- POST /admin/api/v1/scripts/generate
// Mocks: FakeTable (no real DB), FakeGenerator (no real Bedrock/network call).
// ============================================================================

// AC1
test('Scenario: Unauthenticated generate request is refused before the AI is called', async () => {
  const table = new FakeTable();
  const generator = new FakeGenerator();
  const verifier = new MultiActorVerifier({ 'token-a': { preferred_username: 'a@x.com' } });
  const router = makeScriptRouter(table, { verifier, scriptGenerator: generator });

  const generateResp = await routerRequest(router, 'POST', '/admin/api/v1/scripts/generate', {
    body: JSON.stringify({ prompt: 'list files', interpreter: 'powershell' }),
  });
  const createResp = await routerRequest(router, 'POST', '/admin/api/v1/scripts', {
    body: JSON.stringify({ name: 'x', interpreter: 'cmd', script: 'echo hi' }),
  });

  assert.equal(generateResp.statusCode, createResp.statusCode);
  assert.equal(generator.calls.length, 0);
});

// AC2
test('Scenario: Valid request returns the generated script', async () => {
  const table = new FakeTable();
  const generator = new FakeGenerator(async () => 'Get-ChildItem C:\\');
  const deps = createFakeDeps(table);
  deps.scriptGenerator = generator;

  const req = generateRequestObj({ prompt: '  list files  ', interpreter: 'powershell', timeoutSeconds: 120, description: 'd' });
  const result = await handleScriptGenerate(req, deps);

  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body, { script: 'Get-ChildItem C:\\' });
  assert.equal(generator.calls.length, 1);
  assert.deepEqual(generator.calls[0].request, {
    prompt: 'list files',
    interpreter: 'powershell',
    platform: 'windows',
    timeoutSeconds: 120,
    description: 'd',
  });
});

// AC2
test('Scenario: Defaults for timeout and description', async () => {
  const table = new FakeTable();
  const generator = new FakeGenerator(async () => 'echo hi');
  const deps = createFakeDeps(table);
  deps.scriptGenerator = generator;

  const req = generateRequestObj({ prompt: 'list files', interpreter: 'bash', description: '' });
  const result = await handleScriptGenerate(req, deps);

  assert.equal(result.statusCode, 200);
  assert.equal(generator.calls[0].request.timeoutSeconds, 300);
  assert.equal(generator.calls[0].request.description, null);
  assert.equal(generator.calls[0].request.platform, 'darwin');
});

// AC3
for (const [label, prompt] of [
  ['whitespace-only', '   '],
  ['not a string', 42],
  ['longer than 4000 characters after trimming', 'x'.repeat(4001)],
]) {
  test(`Scenario Outline: Invalid prompt is refused -- ${label}`, async () => {
    const table = new FakeTable();
    const generator = new FakeGenerator();
    const deps = createFakeDeps(table);
    deps.scriptGenerator = generator;

    const req = generateRequestObj({ prompt, interpreter: 'cmd' });
    const result = await handleScriptGenerate(req, deps);

    assert.equal(result.statusCode, 400);
    assert.deepEqual(result.body, { error: 'invalid_request', fields: ['prompt'] });
    assert.equal(generator.calls.length, 0);
    assert.equal(table.auditItems.length, 0);
  });
}

// AC3
test('Scenario: Several offending fields are listed in order', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  deps.scriptGenerator = new FakeGenerator();

  const req = generateRequestObj({ prompt: '', description: 'x'.repeat(501), interpreter: 'fish', timeoutSeconds: 0 });
  const result = await handleScriptGenerate(req, deps);

  assert.equal(result.statusCode, 400);
  assert.deepEqual(result.body.fields, ['prompt', 'description', 'interpreter', 'timeoutSeconds']);
});

// AC4
for (const [field, value] of [
  ['interpreter', 'fish'],
  ['timeoutSeconds', 3601],
  ['timeoutSeconds', 1.5],
  ['description', 'x'.repeat(501)],
]) {
  test(`Scenario Outline: Other invalid fields are refused -- ${field}=${JSON.stringify(value)}`, async () => {
    const table = new FakeTable();
    const deps = createFakeDeps(table);
    deps.scriptGenerator = new FakeGenerator();

    const req = generateRequestObj({ ...VALID_GENERATE_BODY, [field]: value });
    const result = await handleScriptGenerate(req, deps);

    assert.equal(result.statusCode, 400);
    assert.deepEqual(result.body.fields, [field]);
  });
}

// AC4
test('Scenario: Non-JSON body', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  deps.scriptGenerator = new FakeGenerator();

  const req = generateRequestObj('not json');
  const result = await handleScriptGenerate(req, deps);

  assert.equal(result.statusCode, 400);
  assert.deepEqual(result.body.fields, ['prompt', 'interpreter']);
});

// AC4 (edge): missing body entirely
test('Unit: a null body answers 400 naming prompt and interpreter', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  deps.scriptGenerator = new FakeGenerator();

  const req = { body: null, params: {}, claims: { preferred_username: 'a@x.com' }, query: {} };
  const result = await handleScriptGenerate(req, deps);

  assert.equal(result.statusCode, 400);
  assert.deepEqual(result.body.fields, ['prompt', 'interpreter']);
});

// AC5
test('Scenario: Generator not configured', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table); // no scriptGenerator

  const req = generateRequestObj({ prompt: 'list files', interpreter: 'cmd' });
  const result = await handleScriptGenerate(req, deps);

  assert.equal(result.statusCode, 503);
  assert.deepEqual(result.body, { error: 'not_configured' });
  assert.equal(table.countItems(), 0, 'no rate-limit counter item should exist');
});

// AC6
test('Scenario: Per-admin rate limit per UTC minute', async () => {
  const table = new FakeTable();
  const generator = new FakeGenerator(async () => 'echo hi');
  let now = new Date('2026-10-11T05:00:10Z');
  const deps = { table, now: () => now, scriptGenerator: generator };

  // 10 valid requests from a@x.com all succeed
  for (let i = 0; i < 10; i += 1) {
    const result = await handleScriptGenerate(generateRequestObj(VALID_GENERATE_BODY, 'a@x.com'), deps);
    assert.equal(result.statusCode, 200, `request ${i + 1} should succeed`);
  }

  // 11th request in the same minute is rate-limited
  const eleventh = await handleScriptGenerate(generateRequestObj(VALID_GENERATE_BODY, 'a@x.com'), deps);
  assert.equal(eleventh.statusCode, 429);
  assert.deepEqual(eleventh.body, { error: 'rate_limited' });
  assert.equal(generator.calls.length, 10, 'the generator was never called for the rate-limited request');

  // A different admin, same minute, succeeds
  const otherAdmin = await handleScriptGenerate(generateRequestObj(VALID_GENERATE_BODY, 'b@x.com'), deps);
  assert.equal(otherAdmin.statusCode, 200);

  // The next UTC minute, the first admin succeeds again
  now = new Date('2026-10-11T05:01:00Z');
  const nextMinute = await handleScriptGenerate(generateRequestObj(VALID_GENERATE_BODY, 'a@x.com'), deps);
  assert.equal(nextMinute.statusCode, 200);

  // The counter item for the first minute (2026-10-11T05:00) carries ttl = epoch seconds of 2026-10-11T05:03:00Z
  const actorKey = createHash('sha256').update('a@x.com'.toLowerCase(), 'utf8').digest('hex');
  const counterItem = table.getStoredItem(scriptGenerateRateLimit(actorKey, '202610110500'));
  const expectedTtl = Math.floor(new Date('2026-10-11T05:03:00Z').getTime() / 1000);
  assert.equal(counterItem.ttl, expectedTtl);
});

// AC7
test('Scenario: Provider failure is not leaked', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  deps.scriptGenerator = new FakeGenerator(async () => {
    throw new Error('AccessDeniedException: secret detail');
  });

  const req = generateRequestObj(VALID_GENERATE_BODY);
  const result = await handleScriptGenerate(req, deps);

  assert.equal(result.statusCode, 502);
  assert.deepEqual(result.body, { error: 'ai_failed' });
  assert.ok(!JSON.stringify(result.body).includes('secret detail'));
});

// AC8
test('Scenario: Provider slower than 20 seconds', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  let capturedSignal;
  deps.scriptGenerator = new FakeGenerator((request, signal) => {
    capturedSignal = signal;
    // Never settles on its own; only the route's own timer should win the race.
    return new Promise(() => {});
  });

  const req = generateRequestObj(VALID_GENERATE_BODY);
  const resultPromise = handleScriptGenerate(req, deps);

  // Let the rate-limit counter's fake `await` settle before the generator is called.
  await flushMicrotasks();
  t.mock.timers.tick(20000);
  assert.equal(capturedSignal.aborted, true, 'the AbortSignal passed to the generator is aborted at 20s');

  const result = await resultPromise;
  assert.equal(result.statusCode, 504);
  assert.deepEqual(result.body, { error: 'ai_timeout' });
});

// AC9
for (const [raw, clean] of [
  ['```powershell\nGet-Date\n```', 'Get-Date'],
  ['  echo hi  \n', 'echo hi'],
  ['echo `date`', 'echo `date`'],
]) {
  test(`Scenario Outline: Output clean-up -- ${JSON.stringify(raw)}`, async () => {
    const table = new FakeTable();
    const deps = createFakeDeps(table);
    deps.scriptGenerator = new FakeGenerator(async () => raw);

    const result = await handleScriptGenerate(generateRequestObj(VALID_GENERATE_BODY), deps);

    assert.equal(result.statusCode, 200);
    assert.equal(result.body.script, clean);
  });
}

test('Unit: cleanGeneratedScript handles fences, whitespace and unrelated backticks', () => {
  assert.equal(cleanGeneratedScript('```powershell\nGet-Date\n```'), 'Get-Date');
  assert.equal(cleanGeneratedScript('  echo hi  \n'), 'echo hi');
  assert.equal(cleanGeneratedScript('echo `date`'), 'echo `date`');
  assert.equal(cleanGeneratedScript('   '), '');
  assert.equal(cleanGeneratedScript('```\n```'), '');
  // A fence-looking first line with no matching closing fence is left alone.
  assert.equal(cleanGeneratedScript('```\necho hi'), '```\necho hi');
});

// AC10
for (const raw of ['   ', '```\n```']) {
  test(`Scenario Outline: Empty result -- ${JSON.stringify(raw)}`, async () => {
    const table = new FakeTable();
    const deps = createFakeDeps(table);
    deps.scriptGenerator = new FakeGenerator(async () => raw);

    const result = await handleScriptGenerate(generateRequestObj(VALID_GENERATE_BODY), deps);

    assert.equal(result.statusCode, 502);
    assert.deepEqual(result.body, { error: 'empty_result' });
  });
}

// AC11
test('Scenario: Oversized result', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  deps.scriptGenerator = new FakeGenerator(async () => 'a'.repeat(65537));

  const result = await handleScriptGenerate(generateRequestObj(VALID_GENERATE_BODY), deps);

  assert.equal(result.statusCode, 502);
  assert.deepEqual(result.body, { error: 'ai_failed' });
});

// AC12
test('Scenario: Success is audited without prompt or script', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  deps.scriptGenerator = new FakeGenerator(async () => 'Get-ChildItem C:\\');

  const req = generateRequestObj({ prompt: 'list files', interpreter: 'powershell', description: 'secret desc' }, 'a@x.com');
  const result = await handleScriptGenerate(req, deps);
  assert.equal(result.statusCode, 200);

  const auditEntries = table.auditItems.filter((item) => item.action === SCRIPT_GENERATED_ACTION);
  assert.equal(auditEntries.length, 1);
  const audit = auditEntries[0];
  assert.equal(audit.actor, 'a@x.com');
  assert.equal(audit.target, SCRIPT_GENERATOR_TARGET);
  assert.deepEqual(audit.detail, { interpreter: 'powershell', promptLength: 10 });

  const serialized = JSON.stringify(table.auditItems);
  assert.ok(!serialized.includes('list files'));
  assert.ok(!serialized.includes('secret desc'));
  assert.ok(!serialized.includes('Get-ChildItem'));
});

// AC12
test('Scenario: Failures are not audited', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  deps.scriptGenerator = new FakeGenerator(async () => {
    throw new Error('boom');
  });

  const result = await handleScriptGenerate(generateRequestObj(VALID_GENERATE_BODY), deps);
  assert.equal(result.statusCode, 502);
  assert.equal(table.auditItems.length, 0);
});

// AC13
test('Scenario: Generate never saves or queues', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  deps.scriptGenerator = new FakeGenerator(async () => 'Get-ChildItem C:\\');

  const result = await handleScriptGenerate(generateRequestObj(VALID_GENERATE_BODY, 'a@x.com'), deps);
  assert.equal(result.statusCode, 200);

  const keys = [...table.items.keys()];
  assert.ok(!keys.some((k) => k.startsWith('SCRIPT#')), 'no SCRIPT# record should be written');
  assert.ok(!keys.some((k) => k.startsWith('UNIQUENAME#')), 'no name guard should be written');
  assert.ok(!keys.some((k) => k.startsWith('DEVICE#')), 'nothing should be queued onto a device');
  assert.equal(table.items.size, 2, 'only the rate-limit counter and the audit entry should be new');
  assert.ok(keys.some((k) => k.startsWith('RATELIMIT#SCRIPTGENERATE#')));
  assert.ok(keys.some((k) => k.startsWith('AUDIT#')));
});

// AC27 (partial; AC16/AC18 cover the rest in other files): this suite never
// constructs a real BedrockRuntimeClient -- every generator here is FakeGenerator.
test('Unit: readGenerateFields rejects a missing body entirely', () => {
  const result = readGenerateFields({});
  assert.deepEqual(result.offending, ['prompt', 'interpreter']);
});

test('Unit: readGenerateFields accepts the maximum boundary values', () => {
  const result = readGenerateFields({
    prompt: 'x'.repeat(SCRIPT_GENERATE_PROMPT_MAX_LENGTH),
    interpreter: 'zsh',
    timeoutSeconds: 3600,
    description: 'y'.repeat(500),
  });
  assert.ok('request' in result);
  assert.equal(result.request.prompt.length, SCRIPT_GENERATE_PROMPT_MAX_LENGTH);
  assert.equal(result.request.timeoutSeconds, 3600);
});
