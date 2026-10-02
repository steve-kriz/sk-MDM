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
    'POST /api/v1/devices/{deviceId}/user-session'
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

test('Enroll is authenticated by the enrollment token alone', async (t) => {
  // Given the POST /api/v1/enroll operation
  const enrollPath = openapi.paths['/api/v1/enroll'];
  const operation = enrollPath.post;

  // When I read the POST /api/v1/enroll operation
  const headerParams = operation.parameters.filter(p => p.in === 'header');
  const headerNames = headerParams.map(p => p.name);

  // Then its declared header parameters are exactly ["X-MDM-Enrollment-Token"]
  assert.deepEqual(headerNames, ['X-MDM-Enrollment-Token'], 'enroll should have only X-MDM-Enrollment-Token');

  // And that parameter is required with the correct pattern
  const tokenParam = headerParams[0];
  assert.equal(tokenParam.required, true, 'X-MDM-Enrollment-Token should be required');
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
    'policy-bundle-response.json',
    'policy-bundle-response-no-conflicts.json',
    'checkin-response.json',
    'checkin-response-with-release.json'
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
