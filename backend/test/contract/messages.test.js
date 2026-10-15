import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import YAML from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load contract files
const openapi = YAML.parse(readFileSync(join(__dirname, '../../../contract/openapi.yaml'), 'utf-8'));
const messagesDir = join(__dirname, '../../../contract/testdata/messages');

test('OpenAPI defines the five device operations', async (t) => {
  // Given the OpenAPI document
  const paths = Object.keys(openapi.paths);

  // Expected operations
  const expectedOps = [
    'POST /api/v1/enroll',
    'POST /api/v1/devices/{deviceId}/checkin',
    'GET /api/v1/devices/{deviceId}/commands',
    'POST /api/v1/devices/{deviceId}/commands/{commandId}/result',
    'GET /api/v1/devices/{deviceId}/policies',
    // TASK-031
    'GET /api/v1/agent-auth/config',
    'POST /api/v1/devices/{deviceId}/user-session',
    // Amendment A: MDM-brokered agent sign-in
    'POST /api/v1/agent-auth/sessions',
    'GET /api/v1/agent-auth/sessions/{sessionId}',
    'GET /agent/signin/{sessionId}',
    'GET /agent/callback',
    // Amendment B: the user token mints a single-use enrollment token
    'POST /api/v1/agent-auth/enrollment-token',
    // TASK-044: per-device heartbeat
    'POST /api/v1/devices/{deviceId}/heartbeat'
  ];

  // Count operations
  const ops = [];
  for (const path of paths) {
    const pathObj = openapi.paths[path];
    for (const method of ['get', 'post', 'put', 'delete', 'patch']) {
      if (pathObj[method]) {
        ops.push(`${method.toUpperCase()} ${path}`);
      }
    }
  }

  // When I parse contract/openapi.yaml
  // Then exactly the five documented method+path pairs are present
  assert.equal(ops.length, expectedOps.length, 'should have exactly the documented operations');
  for (const expectedOp of expectedOps) {
    assert.ok(ops.includes(expectedOp), `operation ${expectedOp} should be present`);
  }
});

test('Device operations require the four signing headers', async (t) => {
  // Device operations (all except POST /api/v1/enroll)
  const deviceOps = [
    '/api/v1/devices/{deviceId}/checkin',
    '/api/v1/devices/{deviceId}/commands',
    '/api/v1/devices/{deviceId}/commands/{commandId}/result',
    '/api/v1/devices/{deviceId}/policies'
  ];

  const requiredHeaders = ['X-MDM-Device-Id', 'X-MDM-Timestamp', 'X-MDM-Nonce', 'X-MDM-Signature'];

  // When I read the four /api/v1/devices/... operations
  for (const path of deviceOps) {
    const pathObj = openapi.paths[path];

    // Get the operation (POST or GET)
    let operation = null;
    if (path.includes('checkin') || path.includes('result')) {
      operation = pathObj.post;
    } else {
      operation = pathObj.get;
    }

    assert.ok(operation, `operation should exist at ${path}`);

    // Then each requires the four headers
    const headerParams = operation.parameters.filter(p => p.in === 'header');
    const headerNames = headerParams.map(p => p.name);

    for (const header of requiredHeaders) {
      const param = headerParams.find(p => p.name === header);
      assert.ok(param, `${path} should have ${header} header`);
      assert.equal(param.required, true, `${header} should be required on ${path}`);
    }

    // And the X-MDM-Timestamp schema is integer int64 described as "epoch seconds"
    const tsParam = headerParams.find(p => p.name === 'X-MDM-Timestamp');
    assert.ok(tsParam, 'X-MDM-Timestamp should exist');
    assert.equal(tsParam.schema.type, 'integer', 'X-MDM-Timestamp type should be integer');
    assert.equal(tsParam.schema.format, 'int64', 'X-MDM-Timestamp format should be int64');
    assert.ok(tsParam.schema.description.includes('epoch seconds'), 'X-MDM-Timestamp should describe epoch seconds');
  }
});

test('Enroll accepts the enrollment token only, and an optional ownership', async () => {
  const operation = openapi.paths['/api/v1/enroll'].post;

  // Amendment B: the bearer branch is gone; the enrollment token header is
  // the only credential and is required.
  assert.equal(operation.security, undefined, 'enroll declares no security scheme');
  const tokenParam = operation.parameters.find((p) => p.in === 'header' && p.name === 'X-MDM-Enrollment-Token');
  assert.equal(tokenParam.required, true);

  // ownership is optional and limited to the two values.
  const schema = openapi.components.schemas.EnrollRequest;
  assert.deepEqual(schema.properties.ownership.enum, ['officehq', 'byoc']);
  assert.equal(schema.properties.ownership.default, 'officehq');
  assert.ok(!schema.required.includes('ownership'));

  for (const status of ['400', '401', '403']) {
    assert.ok(operation.responses[status], `enroll documents ${status}`);
  }
  assert.equal(operation.responses['503'], undefined, 'no JWKS outage can reach enroll any more');
  assert.ok(!JSON.stringify(operation).includes('invalid_user_token'));
});

test('Agent enrollment-token mint is a public bearer route answering tokenId, token and expiresAt', async () => {
  const operation = openapi.paths['/api/v1/agent-auth/enrollment-token'].post;
  assert.deepEqual(operation.security, [{ bearerAuth: [] }]);
  for (const status of ['201', '401', '500', '503']) {
    assert.ok(operation.responses[status], `mint documents ${status}`);
  }
  const ref = operation.responses['201'].content['application/json'].schema.$ref;
  const schema = openapi.components.schemas[ref.split('/').pop()];
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual([...schema.required].sort(), ['expiresAt', 'token', 'tokenId']);
  assert.deepEqual(Object.keys(schema.properties).sort(), ['expiresAt', 'token', 'tokenId']);
  assert.equal(schema.properties.token.pattern, '^[0-9a-f]{16}\\.[0-9a-f]{64}$');
  const described = JSON.stringify(operation.responses);
  for (const error of ['user_token_missing', 'invalid_user_token', 'jwks_unavailable', 'not_configured']) {
    assert.ok(described.includes(error), `mint documents ${error}`);
  }
});

test('User session is device HMAC only with body {username: string<=256 | null}', async () => {
  const operation = openapi.paths['/api/v1/devices/{deviceId}/user-session'].post;
  assert.equal(operation.security, undefined, 'no bearer on the user-session route');
  const headers = operation.parameters.filter((p) => p.in === 'header').map((p) => p.name);
  for (const header of ['X-MDM-Device-Id', 'X-MDM-Timestamp', 'X-MDM-Nonce', 'X-MDM-Signature']) {
    assert.ok(headers.includes(header), `user-session requires ${header}`);
  }
  assert.ok(!headers.includes('Authorization'));

  const requestRef = operation.requestBody.content['application/json'].schema.$ref;
  const request = openapi.components.schemas[requestRef.split('/').pop()];
  assert.equal(request.additionalProperties, false);
  assert.deepEqual(request.required, ['username']);
  assert.equal(request.properties.username.type, 'string');
  assert.equal(request.properties.username.nullable, true);
  assert.equal(request.properties.username.maxLength, 256);

  const response = openapi.components.schemas.UserSessionResponse;
  assert.deepEqual(response.properties.user.required, ['username']);
  assert.deepEqual(Object.keys(response.properties.user.properties), ['username']);
  assert.ok(operation.responses['400'], 'user-session documents 400');
  assert.equal(operation.responses['503'], undefined);
  assert.ok(!JSON.stringify(operation).includes('user_token'));
});

test('The bearer scheme is documented for the mint route only', async () => {
  const description = openapi.components.securitySchemes.bearerAuth.description;
  assert.ok(description.includes('/api/v1/agent-auth/enrollment-token'));
  const users = [];
  for (const [path, item] of Object.entries(openapi.paths)) {
    for (const [method, operation] of Object.entries(item)) {
      if (JSON.stringify(operation.security ?? []).includes('bearerAuth')) {
        users.push(`${method.toUpperCase()} ${path}`);
      }
    }
  }
  assert.deepEqual(users, ['POST /api/v1/agent-auth/enrollment-token']);
});

test('Enroll declares only the enrollment token header and no HMAC headers', async (t) => {
  // Given the POST /api/v1/enroll operation
  const enrollPath = openapi.paths['/api/v1/enroll'];
  const operation = enrollPath.post;

  // When I read the POST /api/v1/enroll operation
  const headerParams = operation.parameters.filter(p => p.in === 'header');
  const headerNames = headerParams.map(p => p.name);

  // Then its declared header parameters are exactly ["X-MDM-Enrollment-Token"]
  assert.deepEqual(headerNames, ['X-MDM-Enrollment-Token'], 'enroll should have only X-MDM-Enrollment-Token');

  // And that parameter has the correct pattern
  const tokenParam = headerParams[0];
  assert.equal(
    tokenParam.schema.pattern,
    '^[0-9a-f]{16}\\.[0-9a-f]{64}$',
    'enrollment token should have the correct pattern'
  );

  // And no X-MDM-Signature, X-MDM-Nonce, X-MDM-Timestamp or X-MDM-Device-Id parameter is declared on it
  assert.ok(!headerNames.includes('X-MDM-Signature'), 'should not have X-MDM-Signature');
  assert.ok(!headerNames.includes('X-MDM-Nonce'), 'should not have X-MDM-Nonce');
  assert.ok(!headerNames.includes('X-MDM-Timestamp'), 'should not have X-MDM-Timestamp');
  assert.ok(!headerNames.includes('X-MDM-Device-Id'), 'should not have X-MDM-Device-Id');
});

test('Message types compile', async (t) => {
  // When I import the compiled backend contract types
  // Then the import should succeed without errors
  const typesPath = join(__dirname, '../../dist/contract/types.js');
  try {
    await import(`file://${typesPath}`);
  } catch (e) {
    assert.fail(`backend types should compile: ${e.message}`);
  }
});

test('Inventory field names are pinned', async (t) => {
  // Load a sample inventory from a message file
  const checkinPath = join(messagesDir, 'checkin-request.json');
  const checkinMsg = JSON.parse(readFileSync(checkinPath, 'utf-8'));
  const inventory = checkinMsg.inventory;

  // Then hardware declares the required fields
  assert.ok(inventory.hardware, 'inventory should have hardware');
  assert.ok(inventory.hardware.manufacturer, 'hardware should have manufacturer');
  assert.ok(inventory.hardware.model, 'hardware should have model');
  assert.ok(inventory.hardware.serialNumber, 'hardware should have serialNumber');
  assert.ok(inventory.hardware.cpu, 'hardware should have cpu');
  assert.ok(typeof inventory.hardware.ramBytes === 'number', 'hardware should have ramBytes as number');
  assert.ok(typeof inventory.hardware.diskBytes === 'number', 'hardware should have diskBytes as number');

  // And os declares the required fields
  assert.ok(inventory.os, 'inventory should have os');
  assert.ok(inventory.os.name, 'os should have name');
  assert.ok(inventory.os.version, 'os should have version');
  assert.ok(inventory.os.build, 'os should have build');
  assert.ok(inventory.os.architecture, 'os should have architecture');

  // And a software entry declares the required fields
  assert.ok(Array.isArray(inventory.software), 'software should be an array');
  assert.ok(inventory.software.length > 0, 'software array should not be empty');
  const software = inventory.software[0];
  assert.ok(software.name, 'software should have name');
  assert.ok(software.version, 'software should have version');
  assert.ok(software.publisher, 'software should have publisher');
  assert.ok(software.installedAt, 'software should have installedAt');

  // And warnings is optional
  // (in checkin-request.json it has warnings, in checkin-request-no-warnings.json it doesn't)
});

test('Posture field names are pinned', async (t) => {
  // Load a sample posture from a message file
  const checkinPath = join(messagesDir, 'checkin-request.json');
  const checkinMsg = JSON.parse(readFileSync(checkinPath, 'utf-8'));
  const posture = checkinMsg.posture;

  // Then diskEncryption declares enabled and method
  assert.ok(posture.diskEncryption, 'posture should have diskEncryption');
  assert.ok(typeof posture.diskEncryption.enabled === 'boolean', 'diskEncryption.enabled should be boolean');
  assert.ok(['bitlocker', 'filevault'].includes(posture.diskEncryption.method), 'method should be bitlocker or filevault');

  // And firewall declares enabled and no other field
  assert.ok(posture.firewall, 'posture should have firewall');
  assert.ok(typeof posture.firewall.enabled === 'boolean', 'firewall.enabled should be boolean');
  assert.equal(Object.keys(posture.firewall).length, 1, 'firewall should have only one field');

  // And antivirus declares the required fields
  assert.ok(posture.antivirus, 'posture should have antivirus');
  assert.ok(posture.antivirus.name, 'antivirus should have name');
  assert.ok(typeof posture.antivirus.enabled === 'boolean', 'antivirus.enabled should be boolean');
  assert.ok(typeof posture.antivirus.definitionsAgeDays === 'number', 'antivirus.definitionsAgeDays should be number');

  // And osUpdate declares the required fields
  assert.ok(posture.osUpdate, 'posture should have osUpdate');
  assert.ok(posture.osUpdate.lastCheckedAt, 'osUpdate should have lastCheckedAt');
  assert.ok(typeof posture.osUpdate.pendingCount === 'number', 'osUpdate.pendingCount should be number');
  assert.ok(typeof posture.osUpdate.rebootRequired === 'boolean', 'osUpdate.rebootRequired should be boolean');

  // And localAdmins is a string array
  assert.ok(Array.isArray(posture.localAdmins), 'localAdmins should be an array');
  assert.ok(posture.localAdmins.every(a => typeof a === 'string'), 'localAdmins should be strings');

  // And warnings is optional
});

test('Check-in carries the payload types and optional compliance', async (t) => {
  // Load check-in message
  const checkinPath = join(messagesDir, 'checkin-request.json');
  const checkin = JSON.parse(readFileSync(checkinPath, 'utf-8'));

  // When I read the CheckInRequest interface
  // Then it declares collectedAt
  assert.ok(checkin.collectedAt, 'should have collectedAt');

  // And inventory and posture reference the Inventory and Posture types
  assert.ok(checkin.inventory, 'should have inventory');
  assert.ok(checkin.posture, 'should have posture');

  // Load check-in with compliance
  const compliancePath = join(messagesDir, 'checkin-request-with-compliance.json');
  const checkinWithCompliance = JSON.parse(readFileSync(compliancePath, 'utf-8'));

  // And a policyCompliance entry declares the required fields
  assert.ok(Array.isArray(checkinWithCompliance.policyCompliance), 'should have policyCompliance array');
  assert.ok(checkinWithCompliance.policyCompliance.length > 0, 'should have at least one compliance entry');

  const entry = checkinWithCompliance.policyCompliance[0];
  assert.ok(entry.policyId, 'entry should have policyId');
  assert.ok(typeof entry.version === 'number', 'entry should have version');
  assert.ok(typeof entry.compliant === 'boolean', 'entry should have compliant');
  assert.ok(Array.isArray(entry.violations), 'entry should have violations array');
});

test('Policy bundle shape is pinned', async (t) => {
  // Load policy bundle response
  const bundlePath = join(messagesDir, 'policy-bundle-response.json');
  const bundle = JSON.parse(readFileSync(bundlePath, 'utf-8'));

  // When I read the PolicyBundleResponse interface
  // Then its top-level fields are exactly deviceId, generatedAt, policies, effectiveSettings and conflicts
  const topKeys = Object.keys(bundle).sort();
  const expectedKeys = ['conflicts', 'deviceId', 'generatedAt', 'policies', 'effectiveSettings'].sort();
  assert.deepEqual(topKeys, expectedKeys, 'top-level keys should match exactly');

  // And a conflicts entry has the required fields
  assert.ok(Array.isArray(bundle.conflicts), 'conflicts should be an array');
  if (bundle.conflicts.length > 0) {
    const conflict = bundle.conflicts[0];
    assert.ok(conflict.key, 'conflict should have key');
    assert.ok(conflict.winningPolicyId, 'conflict should have winningPolicyId');
    assert.ok(conflict.value !== undefined, 'conflict should have value');
    assert.ok(Array.isArray(conflict.losers), 'conflict should have losers array');

    // And a losers entry has the required fields
    if (conflict.losers.length > 0) {
      const loser = conflict.losers[0];
      assert.ok(loser.policyId, 'loser should have policyId');
      assert.ok(loser.value !== undefined, 'loser should have value');
    }
  }
});

test('Warnings are omitted when empty', async (t) => {
  // Load message without warnings
  const noWarningsPath = join(messagesDir, 'checkin-request-no-warnings.json');
  const msgNoWarnings = JSON.parse(readFileSync(noWarningsPath, 'utf-8'));

  // When checking the message
  // Then inventory should not have warnings key
  assert.ok(!('warnings' in msgNoWarnings.inventory), 'inventory should not have warnings key when omitted');
  assert.ok(!('warnings' in msgNoWarnings.posture), 'posture should not have warnings key when omitted');

  // Load message with warnings
  const withWarningsPath = join(messagesDir, 'checkin-request.json');
  const msgWithWarnings = JSON.parse(readFileSync(withWarningsPath, 'utf-8'));

  // And message with warnings should have them
  assert.ok('warnings' in msgWithWarnings.inventory, 'inventory should have warnings key when present');
  assert.ok(Array.isArray(msgWithWarnings.inventory.warnings), 'warnings should be an array');
  assert.ok('warnings' in msgWithWarnings.posture, 'posture should have warnings key when present');
  assert.ok(Array.isArray(msgWithWarnings.posture.warnings), 'warnings should be an array');
});

test('Absent compliance is omitted from the wire', async (t) => {
  // Load message without compliance
  const noCompliancePath = join(messagesDir, 'checkin-request.json');
  const msgNoCompliance = JSON.parse(readFileSync(noCompliancePath, 'utf-8'));

  // When checking the message
  // Then policyCompliance should be absent
  assert.ok(!('policyCompliance' in msgNoCompliance), 'policyCompliance key should be absent when not reported');
});

test('Check-in request with agent version is valid', async (t) => {
  // Load check-in request with agent version
  const versionPath = join(messagesDir, 'checkin-request-with-agent-version.json');
  const msgWithVersion = JSON.parse(readFileSync(versionPath, 'utf-8'));

  // When checking the message
  // Then agentVersion should be present as top-level field
  assert.ok('agentVersion' in msgWithVersion, 'agentVersion should be present');
  assert.strictEqual(typeof msgWithVersion.agentVersion, 'string', 'agentVersion should be a string');
  assert.ok(msgWithVersion.agentVersion.length > 0, 'agentVersion should not be empty');
});

test('Check-in response with agent release is valid', async (t) => {
  // Load check-in response with agent release
  const releasePath = join(messagesDir, 'checkin-response-with-release.json');
  const msgWithRelease = JSON.parse(readFileSync(releasePath, 'utf-8'));

  // When checking the message
  // Then checkInIntervalSeconds and pendingCommandCount should be present
  assert.ok('checkInIntervalSeconds' in msgWithRelease, 'checkInIntervalSeconds should be present');
  assert.ok('pendingCommandCount' in msgWithRelease, 'pendingCommandCount should be present');

  // And agentRelease should be present with required fields
  assert.ok('agentRelease' in msgWithRelease, 'agentRelease should be present');
  const agentRelease = msgWithRelease.agentRelease;
  assert.ok(agentRelease.version, 'agentRelease should have version');
  assert.ok(agentRelease.url, 'agentRelease should have url');
  assert.ok(agentRelease.sha256, 'agentRelease should have sha256');
  assert.strictEqual(agentRelease.url.substring(0, 8), 'https://', 'agentRelease url should be https');
});

test('Golden messages round-trip in both languages', async (t) => {
  // Given the message files
  const messageFiles = [
    'checkin-request.json',
    'checkin-request-no-warnings.json',
    'checkin-request-with-compliance.json',
    'checkin-request-with-agent-version.json',
    'checkin-request-with-antivirus-findings.json',
    'checkin-request-with-analytics.json',
    'checkin-request-with-analytics-nulls.json',
    'checkin-request-with-antivirus-scan.json',
    'checkin-request-with-antivirus-status.json',
    'checkin-request-with-antivirus-status-darwin.json',
    'checkin-request-with-device-details.json',
    'checkin-request-with-defender-hardening.json',
    'checkin-request-with-agent-errors.json',
    'checkin-request-with-agent-actions.json',
    'policy-bundle-response.json',
    'policy-bundle-response-no-conflicts.json',
    'checkin-response.json',
    'checkin-response-with-release.json',
    'checkin-response-analytics-disabled.json',
    'checkin-response-heartbeat-enabled.json',
    'heartbeat-request.json',
    'heartbeat-request-with-network.json',
    'heartbeat-response.json',
    'heartbeat-response-disabled.json'
  ];

  // When the Node test inspects their keys
  for (const file of messageFiles) {
    const path = join(messagesDir, file);
    const msg = JSON.parse(readFileSync(path, 'utf-8'));

    // Then each object's key set equals the documented field names
    // (i.e., no extra fields, no missing fields)
    if (file.includes('checkin-request')) {
      // CheckInRequest fields
      assert.ok('collectedAt' in msg, `${file} should have collectedAt`);
      assert.ok('inventory' in msg, `${file} should have inventory`);
      assert.ok('posture' in msg, `${file} should have posture`);
    } else if (file.includes('checkin-response')) {
      // CheckInResponse fields
      assert.ok('checkInIntervalSeconds' in msg, `${file} should have checkInIntervalSeconds`);
      assert.ok('pendingCommandCount' in msg, `${file} should have pendingCommandCount`);
    } else if (file.includes('policy')) {
      assert.ok('deviceId' in msg, `${file} should have deviceId`);
      assert.ok('generatedAt' in msg, `${file} should have generatedAt`);
      assert.ok('policies' in msg, `${file} should have policies`);
      assert.ok('effectiveSettings' in msg, `${file} should have effectiveSettings`);
      assert.ok('conflicts' in msg, `${file} should have conflicts`);
    }
  }

  // And checkin-request-with-compliance.json holds two policyCompliance entries
  const compliancePath = join(messagesDir, 'checkin-request-with-compliance.json');
  const checkinMsg = JSON.parse(readFileSync(compliancePath, 'utf-8'));
  assert.ok(Array.isArray(checkinMsg.policyCompliance), 'should have policyCompliance');
  assert.equal(checkinMsg.policyCompliance.length, 2, 'should have two entries');

  // one compliant with violations []
  const compliant = checkinMsg.policyCompliance.find(e => e.compliant);
  assert.ok(compliant, 'should have a compliant entry');
  assert.deepEqual(compliant.violations, [], 'compliant entry should have empty violations');

  // and one not compliant with violations ["firewall_disabled"]
  const nonCompliant = checkinMsg.policyCompliance.find(e => !e.compliant);
  assert.ok(nonCompliant, 'should have a non-compliant entry');
  assert.ok(nonCompliant.violations.includes('firewall_disabled'), 'non-compliant entry should have firewall_disabled');

  // And policy-bundle-response-no-conflicts.json has "conflicts" present and equal to []
  const noConflictsPath = join(messagesDir, 'policy-bundle-response-no-conflicts.json');
  const noConflictsMsg = JSON.parse(readFileSync(noConflictsPath, 'utf-8'));
  assert.ok('conflicts' in noConflictsMsg, 'conflicts should be present');
  assert.deepEqual(noConflictsMsg.conflicts, [], 'conflicts should be an empty array');

  // TASK-040: And checkin-response-analytics-disabled.json holds analyticsEnabled: false
  const analyticsDisabledPath = join(messagesDir, 'checkin-response-analytics-disabled.json');
  const analyticsDisabledMsg = JSON.parse(readFileSync(analyticsDisabledPath, 'utf-8'));
  assert.ok('checkInIntervalSeconds' in analyticsDisabledMsg, 'should have checkInIntervalSeconds');
  assert.ok('pendingCommandCount' in analyticsDisabledMsg, 'should have pendingCommandCount');
  assert.strictEqual(analyticsDisabledMsg.analyticsEnabled, false, 'analyticsEnabled should be false');
});

test('Unknown field is rejected by schema validation', async (t) => {
  // Note: This test is more about documenting the requirement.
  // The Go test uses DisallowUnknownFields in JSON decoder.
  // The Node side validates against OpenAPI schema with additionalProperties: false.

  // Given a test message (we'll construct one with an extra field)
  const testMsg = {
    collectedAt: '2026-10-02T07:15:00Z',
    inventory: {
      hardware: { manufacturer: 'Test', model: 'Test', serialNumber: 'Test', cpu: 'Test', ramBytes: 1, diskBytes: 1 },
      os: { name: 'Test', version: 'Test', build: 'Test', architecture: 'Test' },
      software: []
    },
    posture: {
      diskEncryption: { enabled: true, method: 'bitlocker' },
      firewall: { enabled: true },
      antivirus: { name: 'Test', enabled: true, definitionsAgeDays: 1 },
      osUpdate: { lastCheckedAt: '2026-10-02T07:15:00Z', pendingCount: 0, rebootRequired: false },
      localAdmins: []
    },
    surprise: 'extra field'  // Unknown field
  };

  // The OpenAPI schema has additionalProperties: false
  // So a strict validator would reject this
  const checkInSchema = openapi.components.schemas.CheckInRequest;
  assert.equal(checkInSchema.additionalProperties, false, 'CheckInRequest should forbid additionalProperties');
});

test('TASK-030: Scenario: Contract documents the redefined antivirus.enabled without a shape change', async (t) => {
  // Then Posture.antivirus.enabled is documented as true when Defender or any
  // Security Center registered antivirus is active, or XProtect is present
  const enabledSchema = openapi.components.schemas.Posture.properties.antivirus.properties.enabled;
  assert.ok(enabledSchema.description, 'antivirus.enabled should carry a description');
  assert.match(enabledSchema.description, /Defender/);
  assert.match(enabledSchema.description, /Security Center/);
  assert.match(enabledSchema.description, /XProtect/);

  // And the Posture.antivirus properties and required list are unchanged
  const antivirusSchema = openapi.components.schemas.Posture.properties.antivirus;
  assert.deepEqual(
    Object.keys(antivirusSchema.properties).sort(),
    ['name', 'enabled', 'definitionsAgeDays'].sort(),
  );
  assert.deepEqual(
    [...antivirusSchema.required].sort(),
    ['name', 'enabled', 'definitionsAgeDays'].sort(),
  );
  assert.deepEqual(
    [...openapi.components.schemas.Posture.required].sort(),
    ['diskEncryption', 'firewall', 'antivirus', 'osUpdate', 'localAdmins'].sort(),
  );

  // And the TypeScript contract types carry a doc comment with the same meaning
  const typesTs = readFileSync(join(__dirname, '../../src/contract/types.ts'), 'utf-8');
  const antivirusBlock = typesTs.slice(typesTs.indexOf('antivirus: {'), typesTs.indexOf('osUpdate: {'));
  assert.match(antivirusBlock, /Microsoft Defender/);
  assert.match(antivirusBlock, /Security Center/);
  assert.match(antivirusBlock, /XProtect/);

  // And no posture golden file changed shape: checkin-request.json still
  // round-trips with exactly the unchanged antivirus keys
  const checkinMsg = JSON.parse(readFileSync(join(messagesDir, 'checkin-request.json'), 'utf-8'));
  assert.deepEqual(
    Object.keys(checkinMsg.posture.antivirus).sort(),
    ['name', 'enabled', 'definitionsAgeDays'].sort(),
  );
});

test('Scenario: AC9 - The contract documents real-time protection in antivirus.enabled', async (t) => {
  // When I read the antivirus.enabled description in openapi.yaml
  const enabledSchema = openapi.components.schemas.Posture.properties.antivirus.properties.enabled;
  // Then it mentions real-time protection, Microsoft Defender, Security Center and XProtect
  assert.match(enabledSchema.description, /real-time protection/);
  assert.match(enabledSchema.description, /Microsoft Defender/);
  assert.match(enabledSchema.description, /Security Center/);
  assert.match(enabledSchema.description, /XProtect/);

  // And the TypeScript contract types carry the same meaning
  const typesTs = readFileSync(join(__dirname, '../../src/contract/types.ts'), 'utf-8');
  const antivirusBlock = typesTs.slice(typesTs.indexOf('antivirus: {'), typesTs.indexOf('osUpdate: {'));
  assert.match(antivirusBlock, /real-time protection/);

  // And Posture.antivirus properties and required list are unchanged
  const antivirusSchema = openapi.components.schemas.Posture.properties.antivirus;
  assert.deepEqual(Object.keys(antivirusSchema.properties).sort(), ['name', 'enabled', 'definitionsAgeDays'].sort());
  assert.deepEqual([...antivirusSchema.required].sort(), ['name', 'enabled', 'definitionsAgeDays'].sort());
});

test('Scenario: AC24 - The AntivirusScan schema matches the contract', async (t) => {
  const schema = openapi.components.schemas.AntivirusScan;
  assert.ok(schema, 'expected an AntivirusScan schema');
  assert.strictEqual(schema.additionalProperties, false);
  assert.deepEqual(
    [...schema.required].sort(),
    ['scanType', 'result', 'startedAt', 'completedAt', 'threatsFound'].sort(),
  );
  assert.deepEqual(
    Object.keys(schema.properties).sort(),
    ['scanType', 'result', 'startedAt', 'completedAt', 'threatsFound', 'detail'].sort(),
  );
  assert.deepEqual(schema.properties.scanType.enum, ['quick']);
  assert.deepEqual(
    [...schema.properties.result.enum].sort(),
    ['clean', 'threats_found', 'failed', 'timeout', 'unsupported'].sort(),
  );
  assert.strictEqual(schema.properties.threatsFound.minimum, 0);
  assert.strictEqual(schema.properties.detail.maxLength, 256);
  assert.strictEqual(schema.properties.startedAt.nullable, true);
  assert.strictEqual(schema.properties.completedAt.nullable, true);

  // CheckInRequest carries an optional antivirusScan referencing it
  const checkInSchema = openapi.components.schemas.CheckInRequest;
  assert.ok(checkInSchema.properties.antivirusScan, 'expected CheckInRequest.antivirusScan');
  assert.strictEqual(checkInSchema.properties.antivirusScan.$ref, '#/components/schemas/AntivirusScan');
  assert.ok(
    !checkInSchema.required || !checkInSchema.required.includes('antivirusScan'),
    'antivirusScan should not be required on CheckInRequest',
  );
});

test('Scenario: AC24 - The fixture round-trips through the openapi CheckInRequest schema shape', async (t) => {
  const fixture = JSON.parse(readFileSync(join(messagesDir, 'checkin-request-with-antivirus-scan.json'), 'utf-8'));
  const checkInProps = Object.keys(openapi.components.schemas.CheckInRequest.properties);

  // Every top-level key in the fixture is a documented CheckInRequest property
  // (additionalProperties: false means an unknown key here would be refused).
  for (const key of Object.keys(fixture)) {
    assert.ok(checkInProps.includes(key), `${key} should be a documented CheckInRequest property`);
  }

  // And the antivirusScan sub-object carries exactly the AntivirusScan keys
  const scanProps = Object.keys(openapi.components.schemas.AntivirusScan.properties);
  for (const key of Object.keys(fixture.antivirusScan)) {
    assert.ok(scanProps.includes(key), `${key} should be a documented AntivirusScan property`);
  }
  for (const required of openapi.components.schemas.AntivirusScan.required) {
    assert.ok(required in fixture.antivirusScan, `fixture should carry required field ${required}`);
  }
});

test('TASK-030: Scenario: Contract carries antivirusFindings in all four places', async (t) => {
  // Given the new golden file
  const path = join(messagesDir, 'checkin-request-with-antivirus-findings.json');
  const msg = JSON.parse(readFileSync(path, 'utf-8'));

  // Then it holds at least one finding with exactly the six keys
  assert.ok(Array.isArray(msg.antivirusFindings), 'should have an antivirusFindings array');
  assert.ok(msg.antivirusFindings.length >= 1, 'should hold at least one finding');

  const expectedKeys = ['findingId', 'threatName', 'severity', 'detectedAt', 'resources', 'remediated'].sort();
  for (const finding of msg.antivirusFindings) {
    assert.deepEqual(Object.keys(finding).sort(), expectedKeys, 'finding should have exactly the six keys');
  }

  // And openapi.yaml defines AntivirusFinding with additionalProperties false,
  // all six fields required and the five-value severity enum
  const schema = openapi.components.schemas.AntivirusFinding;
  assert.ok(schema, 'AntivirusFinding schema should be defined');
  assert.equal(schema.additionalProperties, false, 'AntivirusFinding should forbid additionalProperties');
  assert.deepEqual(
    [...schema.required].sort(),
    ['findingId', 'threatName', 'severity', 'detectedAt', 'resources', 'remediated'].sort(),
    'AntivirusFinding should require all six fields',
  );
  assert.deepEqual(
    [...schema.properties.severity.enum].sort(),
    ['unknown', 'low', 'moderate', 'high', 'severe'].sort(),
    'severity enum should hold the five values',
  );

  // And CheckInRequest.antivirusFindings references that schema
  const checkInSchema = openapi.components.schemas.CheckInRequest;
  assert.ok(checkInSchema.properties.antivirusFindings, 'CheckInRequest should carry antivirusFindings');
  assert.equal(
    checkInSchema.properties.antivirusFindings.items.$ref,
    '#/components/schemas/AntivirusFinding',
    'antivirusFindings items should reference AntivirusFinding',
  );
  assert.ok(
    !checkInSchema.required.includes('antivirusFindings'),
    'antivirusFindings should be optional on CheckInRequest',
  );
});

// ============================================================================
// TASK-058 AC15: the contract defines antivirusStatus in Go, TypeScript and
// OpenAPI.
// ============================================================================

test('Scenario: AC15 - The contract defines antivirusStatus in Go, TypeScript and OpenAPI', async (t) => {
  // When contract/openapi.yaml is parsed
  const checkInSchema = openapi.components.schemas.CheckInRequest;

  // Then CheckInRequest.properties.antivirusStatus references AntivirusStatus
  assert.ok(checkInSchema.properties.antivirusStatus, 'CheckInRequest should carry antivirusStatus');
  assert.strictEqual(checkInSchema.properties.antivirusStatus.$ref, '#/components/schemas/AntivirusStatus');
  assert.ok(
    !checkInSchema.required || !checkInSchema.required.includes('antivirusStatus'),
    'antivirusStatus should not be required on CheckInRequest',
  );

  // And AntivirusStatus has additionalProperties false and requires every one of its keys
  const statusSchema = openapi.components.schemas.AntivirusStatus;
  assert.ok(statusSchema, 'AntivirusStatus schema should be defined');
  assert.strictEqual(statusSchema.additionalProperties, false);
  assert.deepEqual(
    [...statusSchema.required].sort(),
    Object.keys(statusSchema.properties).sort(),
    'AntivirusStatus should require every one of its own keys',
  );
  for (const nested of ['AntivirusProtection', 'AntivirusVersions', 'AntivirusSignatures', 'AntivirusScans', 'SecurityCenterProduct']) {
    const nestedSchema = openapi.components.schemas[nested];
    assert.ok(nestedSchema, `${nested} schema should be defined`);
    assert.strictEqual(nestedSchema.additionalProperties, false, `${nested} should forbid additionalProperties`);
  }

  // And AntivirusFinding.required is still the original six
  const findingSchema = openapi.components.schemas.AntivirusFinding;
  assert.deepEqual(
    [...findingSchema.required].sort(),
    ['findingId', 'threatName', 'severity', 'detectedAt', 'resources', 'remediated'].sort(),
    'AntivirusFinding.required should still be the original six',
  );

  // And AntivirusFinding.properties.status.enum lists the twelve mapped statuses
  assert.deepEqual(
    [...findingSchema.properties.status.enum].sort(),
    [
      'unknown', 'detected', 'cleaned', 'quarantined', 'removed', 'allowed', 'blocked',
      'quarantine_failed', 'remove_failed', 'allow_failed', 'abandoned', 'block_failed',
    ].sort(),
    'status enum should hold the twelve mapped values',
  );

  // And the Go CheckInRequest field AntivirusStatus has json tag "antivirusStatus,omitempty"
  const goTypes = readFileSync(join(__dirname, '../../../agent/internal/contract/types.go'), 'utf-8');
  assert.match(goTypes, /AntivirusStatus\s+\*AntivirusStatus\s+`json:"antivirusStatus,omitempty"`/);

  // And the TypeScript contract carries the equivalent optional field and interfaces
  const typesTs = readFileSync(join(__dirname, '../../src/contract/types.ts'), 'utf-8');
  assert.match(typesTs, /antivirusStatus\?:\s*AntivirusStatus/);
  assert.match(typesTs, /export interface AntivirusStatus/);
  for (const name of ['AntivirusProtection', 'AntivirusVersions', 'AntivirusSignatures', 'AntivirusScans']) {
    assert.match(typesTs, new RegExp(`export interface ${name}`));
  }
});

// ============================================================================
// TASK-058 AC16: the new fixtures decode and match the schema.
// ============================================================================

test('Scenario: AC16 - The new fixtures decode and match the schema', async (t) => {
  // When checkin-request-with-antivirus-status.json and the darwin equivalent
  // are validated against the real openapi CheckInRequest schema
  const windowsFixture = JSON.parse(readFileSync(join(messagesDir, 'checkin-request-with-antivirus-status.json'), 'utf-8'));
  const darwinFixture = JSON.parse(readFileSync(join(messagesDir, 'checkin-request-with-antivirus-status-darwin.json'), 'utf-8'));

  // Then both decode without error: every antivirusStatus key at every level
  // (and the extended finding's keys) is a documented property, and every
  // required key is present (validateAgainstSchema throws otherwise).
  assert.doesNotThrow(() => validateAgainstSchema(windowsFixture, openapi.components.schemas.CheckInRequest));
  assert.doesNotThrow(() => validateAgainstSchema(darwinFixture, openapi.components.schemas.CheckInRequest));

  // And every key of the extended finding is a property of AntivirusFinding
  const findingProperties = Object.keys(openapi.components.schemas.AntivirusFinding.properties);
  for (const key of Object.keys(windowsFixture.antivirusFindings[0])) {
    assert.ok(findingProperties.includes(key), `AntivirusFinding should declare ${key}`);
  }
  // All eight new fields are present on that one finding, per AC16.
  for (const key of ['category', 'status', 'action', 'active', 'lastStatusChangeAt', 'remediatedAt', 'processName', 'user']) {
    assert.ok(key in windowsFixture.antivirusFindings[0], `fixture finding should carry ${key}`);
  }
});

test('Scenario: AC16 edge - a malformed antivirusStatus fixture fails schema validation', async (t) => {
  // Given the fixture mutated so an unknown key is added and a required key removed
  const fixture = JSON.parse(readFileSync(join(messagesDir, 'checkin-request-with-antivirus-status.json'), 'utf-8'));

  const withExtra = JSON.parse(JSON.stringify(fixture));
  withExtra.antivirusStatus.evil = 'surprise';
  assert.throws(() => validateAgainstSchema(withExtra, openapi.components.schemas.CheckInRequest));

  const missingRequired = JSON.parse(JSON.stringify(fixture));
  delete missingRequired.antivirusStatus.computerState;
  assert.throws(() => validateAgainstSchema(missingRequired, openapi.components.schemas.CheckInRequest));
});

// ============================================================================
// TASK-059: minimal JSON-Schema validator for openapi.yaml, used to validate
// golden fixtures against the real schema shape rather than hand-picked
// property assertions. No dependency is added: this walks the handful of
// keywords this repo's schemas actually use ($ref, type, properties,
// additionalProperties, required, enum, minimum, maxLength, maxItems, items,
// nullable).
// ============================================================================

/** Resolve a `#/components/schemas/Name` ref against the loaded openapi document. */
function resolveSchemaRef(ref) {
  const name = ref.split('/').pop();
  const schema = openapi.components.schemas[name];
  assert.ok(schema, `unknown schema ref ${ref}`);
  return schema;
}

/**
 * Validate `value` against `schema`, throwing an assertion error naming
 * `path` on the first mismatch. Supports exactly the keywords used in
 * contract/openapi.yaml.
 */
function validateAgainstSchema(value, schema, path = '$') {
  if (schema.$ref) {
    validateAgainstSchema(value, resolveSchemaRef(schema.$ref), path);
    return;
  }
  if (value === null) {
    assert.ok(schema.nullable === true, `${path} is null but schema is not nullable`);
    return;
  }
  if (schema.enum) {
    assert.ok(schema.enum.includes(value), `${path} = ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`);
  }
  if (schema.type === 'object' || (schema.properties && schema.type === undefined)) {
    assert.ok(value !== null && typeof value === 'object' && !Array.isArray(value), `${path} should be an object`);
    const properties = schema.properties ?? {};
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        assert.ok(key in properties, `${path}.${key} is not a documented property (additionalProperties: false)`);
      }
    }
    for (const required of schema.required ?? []) {
      assert.ok(required in value, `${path} is missing required property ${required}`);
    }
    for (const [key, propSchema] of Object.entries(properties)) {
      if (value[key] !== undefined) {
        validateAgainstSchema(value[key], propSchema, `${path}.${key}`);
      }
    }
    return;
  }
  if (schema.type === 'array') {
    assert.ok(Array.isArray(value), `${path} should be an array`);
    if (typeof schema.maxItems === 'number') {
      assert.ok(value.length <= schema.maxItems, `${path} has ${value.length} items, more than maxItems ${schema.maxItems}`);
    }
    if (schema.items) {
      value.forEach((item, index) => validateAgainstSchema(item, schema.items, `${path}[${index}]`));
    }
    return;
  }
  if (schema.type === 'string') {
    assert.strictEqual(typeof value, 'string', `${path} should be a string`);
    if (typeof schema.maxLength === 'number') {
      assert.ok(value.length <= schema.maxLength, `${path} is longer than maxLength ${schema.maxLength}`);
    }
    return;
  }
  if (schema.type === 'integer' || schema.type === 'number') {
    assert.strictEqual(typeof value, 'number', `${path} should be a number`);
    if (schema.type === 'integer') {
      assert.ok(Number.isInteger(value), `${path} = ${value} should be an integer`);
    }
    if (typeof schema.minimum === 'number') {
      assert.ok(value >= schema.minimum, `${path} = ${value} is below minimum ${schema.minimum}`);
    }
    return;
  }
  if (schema.type === 'boolean') {
    assert.strictEqual(typeof value, 'boolean', `${path} should be a boolean`);
    return;
  }
}

test('Scenario: AC14 - the device-details fixture validates against the openapi Inventory schema', async (t) => {
  // Given contract/testdata/messages/checkin-request-with-device-details.json
  const fixture = JSON.parse(readFileSync(join(messagesDir, 'checkin-request-with-device-details.json'), 'utf-8'));

  // When it is validated against the openapi CheckInRequest schema (which
  // carries Inventory through a $ref)
  // Then it validates cleanly: every property is documented, every required
  // field is present, every enum, minimum, maxItems and type constraint holds.
  validateAgainstSchema(fixture, openapi.components.schemas.CheckInRequest);

  // And every new device-detail key is declared under Inventory specifically,
  // each additionalProperties: false.
  const inventorySchema = openapi.components.schemas.Inventory;
  assert.strictEqual(inventorySchema.additionalProperties, false);
  for (const key of ['firmware', 'disks', 'physicalDisks', 'network', 'join']) {
    assert.ok(key in inventorySchema.properties, `Inventory schema should declare ${key}`);
  }
  assert.strictEqual(inventorySchema.properties.firmware.additionalProperties, false);
  assert.strictEqual(inventorySchema.properties.disks.items.additionalProperties, false);
  assert.strictEqual(inventorySchema.properties.physicalDisks.items.additionalProperties, false);
  assert.strictEqual(inventorySchema.properties.network.items.additionalProperties, false);
  assert.strictEqual(inventorySchema.properties.join.additionalProperties, false);

  // None of the new blocks/fields are required: an old-agent inventory with
  // only hardware/os/software must still validate.
  const oldShapeFixture = JSON.parse(readFileSync(join(messagesDir, 'checkin-request.json'), 'utf-8'));
  validateAgainstSchema(oldShapeFixture, openapi.components.schemas.CheckInRequest);
});

test('Scenario: AC14 edge - a malformed device-details fixture fails schema validation', async (t) => {
  // Given the fixture mutated so firmware carries an unknown property and an
  // invalid enum value
  const fixture = JSON.parse(readFileSync(join(messagesDir, 'checkin-request-with-device-details.json'), 'utf-8'));
  const broken = JSON.parse(JSON.stringify(fixture));
  broken.inventory.firmware.type = 'efi'; // not in the uefi|bios enum

  // When it is validated against the openapi schema
  // Then validation throws
  assert.throws(() => validateAgainstSchema(broken, openapi.components.schemas.CheckInRequest));

  // And an unknown property is also rejected (additionalProperties: false)
  const withExtra = JSON.parse(JSON.stringify(fixture));
  withExtra.inventory.firmware.unknownField = 'surprise';
  assert.throws(() => validateAgainstSchema(withExtra, openapi.components.schemas.CheckInRequest));
});

test('Scenario: Contract fixture round-trips (AC11) - validates against the CheckInRequest/AgentError schema', async (t) => {
  // Given contract/testdata/messages/checkin-request-with-agent-errors.json
  const fixture = JSON.parse(readFileSync(join(messagesDir, 'checkin-request-with-agent-errors.json'), 'utf-8'));

  // Then it validates against the CheckInRequest schema in contract/openapi.yaml
  validateAgainstSchema(fixture, openapi.components.schemas.CheckInRequest);

  // And the AgentError schema documents exactly the wire shape
  const agentErrorSchema = openapi.components.schemas.AgentError;
  assert.strictEqual(agentErrorSchema.additionalProperties, false);
  assert.deepStrictEqual(
    [...agentErrorSchema.required].sort(),
    ['level', 'component', 'message', 'fields', 'count', 'firstAt', 'lastAt'].sort(),
  );
  assert.deepStrictEqual(agentErrorSchema.properties.level.enum, ['warn', 'error']);
  assert.strictEqual(agentErrorSchema.properties.count.minimum, 1);
  assert.strictEqual(agentErrorSchema.properties.count.maximum, 1000000);

  // And agentErrors on CheckInRequest is capped at 50 items
  const agentErrorsProperty = openapi.components.schemas.CheckInRequest.properties.agentErrors;
  assert.strictEqual(agentErrorsProperty.maxItems, 50);
});

test('Scenario: AC11 edge - a malformed agentErrors fixture fails schema validation', async (t) => {
  // Given the fixture mutated so the first entry carries a level outside the
  // warn|error enum
  const fixture = JSON.parse(readFileSync(join(messagesDir, 'checkin-request-with-agent-errors.json'), 'utf-8'));
  const broken = JSON.parse(JSON.stringify(fixture));
  broken.agentErrors[0].level = 'info';

  // Then validation throws
  assert.throws(() => validateAgainstSchema(broken, openapi.components.schemas.CheckInRequest));

  // And an unknown property on an entry is also rejected
  // (AgentError additionalProperties: false)
  const withExtra = JSON.parse(JSON.stringify(fixture));
  withExtra.agentErrors[0].surprise = 'nope';
  assert.throws(() => validateAgainstSchema(withExtra, openapi.components.schemas.CheckInRequest));
});

// ============================================================================
// TASK-070: the agentActions fixture round-trips and validates (AC2).
// ============================================================================

test('Scenario: The fixture round-trips and validates (AC2)', async (t) => {
  // Given contract/testdata/messages/checkin-request-with-agent-actions.json
  // with one action of each of the four types
  const fixture = JSON.parse(readFileSync(join(messagesDir, 'checkin-request-with-agent-actions.json'), 'utf-8'));
  assert.strictEqual(fixture.agentActions.length, 4);

  // Then it validates against the CheckInRequest schema in contract/openapi.yaml
  validateAgainstSchema(fixture, openapi.components.schemas.CheckInRequest);

  // And the AgentAction schema documents exactly the wire shape
  const agentActionSchema = openapi.components.schemas.AgentAction;
  assert.strictEqual(agentActionSchema.additionalProperties, false);
  assert.deepStrictEqual([...agentActionSchema.required].sort(), ['type', 'occurredAt', 'details'].sort());
  assert.deepStrictEqual(
    [...agentActionSchema.properties.type.enum].sort(),
    [
      'enforce.firewall_enabled',
      'enforce.antivirus_enabled',
      'enforce.domains_updated',
      'agent.update_rolled_back',
    ].sort(),
  );
  assert.strictEqual(agentActionSchema.properties.occurredAt.format, 'date-time');
  assert.strictEqual(agentActionSchema.properties.details.maxProperties, 8);
  assert.strictEqual(agentActionSchema.properties.details.additionalProperties.maxLength, 256);

  // And agentActions on CheckInRequest is capped at 20 items
  const agentActionsProperty = openapi.components.schemas.CheckInRequest.properties.agentActions;
  assert.strictEqual(agentActionsProperty.maxItems, 20);
});

test('Scenario: A malformed action fails schema validation (AC2)', async (t) => {
  // Given the fixture with an action of type "enforce.firewall_disabled"
  const fixture = JSON.parse(readFileSync(join(messagesDir, 'checkin-request-with-agent-actions.json'), 'utf-8'));
  const badType = JSON.parse(JSON.stringify(fixture));
  badType.agentActions[0].type = 'enforce.firewall_disabled';

  // Then schema validation fails
  assert.throws(() => validateAgainstSchema(badType, openapi.components.schemas.CheckInRequest));

  // And the fixture with an extra property "surprise" on an action fails
  // schema validation
  const withExtra = JSON.parse(JSON.stringify(fixture));
  withExtra.agentActions[0].surprise = 'nope';
  assert.throws(() => validateAgainstSchema(withExtra, openapi.components.schemas.CheckInRequest));
});
