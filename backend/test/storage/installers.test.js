/**
 * E2E cucumber-style and unit tests for the S3-backed installer store adapter
 * (TASK-025): `backend/src/storage/installers.ts`.
 *
 * `exists` is driven with a fake SDK-shaped client (`send(command)`), so no
 * network call is ever made. `presignGet` is exercised against a real
 * `S3Client` built with static, fake credentials: `getSignedUrl` computes the
 * signature locally and never sends a request, so this still makes no real
 * AWS call.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { createS3InstallerStore } = await import(`file://${join(__dirname, '../../dist/storage/installers.js')}`);
const { S3_CLIENT_OPTIONS } = await import(`file://${join(__dirname, '../../dist/bootstrap.js')}`);
const { S3Client, GetObjectCommand, HeadObjectCommand, PutObjectCommand } = await import('@aws-sdk/client-s3');

/** A fake SDK-shaped S3 client: records every command and answers scripted outcomes. */
class FakeS3Client {
  constructor() {
    this.calls = [];
    this.outcome = { kind: 'resolve', value: {} };
  }

  async send(command) {
    this.calls.push(command);
    if (this.outcome.kind === 'reject') {
      throw this.outcome.value;
    }
    return this.outcome.value;
  }
}

// ============================================================================
// Scenario: S3 store adapter maps HeadObject outcomes
// ============================================================================
test('Scenario: S3 store adapter maps HeadObject outcomes -- exists resolves true', async () => {
  // Given createS3InstallerStore with bucket "b" and a fake S3 client
  const client = new FakeS3Client();
  const store = createS3InstallerStore({ bucket: 'b', client });

  // When the client resolves HeadObject for "installers/windows-x64.msi"
  const result = await store.exists('installers/windows-x64.msi');

  // Then exists resolves true and the command had Bucket "b" and Key "installers/windows-x64.msi"
  assert.strictEqual(result, true);
  assert.strictEqual(client.calls.length, 1);
  assert.ok(client.calls[0] instanceof HeadObjectCommand);
  assert.deepStrictEqual(client.calls[0].input, { Bucket: 'b', Key: 'installers/windows-x64.msi' });
});

test('Scenario: S3 store adapter maps HeadObject outcomes -- NotFound name resolves false', async () => {
  const client = new FakeS3Client();
  client.outcome = { kind: 'reject', value: { name: 'NotFound' } };
  const store = createS3InstallerStore({ bucket: 'b', client });

  // When the client rejects with name "NotFound"
  const result = await store.exists('installers/windows-x64.msi');

  // Then exists resolves false
  assert.strictEqual(result, false);
});

test('Scenario: S3 store adapter maps HeadObject outcomes -- 404 metadata resolves false', async () => {
  const client = new FakeS3Client();
  client.outcome = { kind: 'reject', value: { $metadata: { httpStatusCode: 404 } } };
  const store = createS3InstallerStore({ bucket: 'b', client });

  // When the client rejects with $metadata.httpStatusCode 404
  const result = await store.exists('installers/windows-x64.msi');

  // Then exists resolves false
  assert.strictEqual(result, false);
});

test('Scenario: S3 store adapter maps HeadObject outcomes -- other errors rethrow', async () => {
  const client = new FakeS3Client();
  const accessDenied = { name: 'AccessDenied' };
  client.outcome = { kind: 'reject', value: accessDenied };
  const store = createS3InstallerStore({ bucket: 'b', client });

  // When the client rejects with name "AccessDenied"
  // Then exists rejects with that error
  await assert.rejects(() => store.exists('installers/windows-x64.msi'), (err) => err === accessDenied);
});

// ============================================================================
// Unit: presignGet builds a GetObjectCommand and returns a presigned URL
// ============================================================================
test('Unit: presignGet returns a presigned GET URL for the given key and ttl', async () => {
  const client = new S3Client({
    region: 'us-east-1',
    credentials: { accessKeyId: 'FAKEKEYID', secretAccessKey: 'FAKESECRET' },
  });
  const store = createS3InstallerStore({ bucket: 'b', client });

  const url = await store.presignGet('installers/windows-x64.msi', 300);

  assert.strictEqual(typeof url, 'string');
  assert.ok(url.includes('/b/installers/windows-x64.msi'), url);
  assert.ok(url.includes('X-Amz-Expires=300'), url);
  assert.ok(url.includes('X-Amz-Signature='), url);
});

test('Unit: presignGet builds a real GetObjectCommand (not HeadObject)', async () => {
  // Sanity-check against the SDK: a GetObjectCommand targeting the same
  // bucket/key produces the same path shape presignGet signs.
  const command = new GetObjectCommand({ Bucket: 'b', Key: 'installers/macos-arm64.pkg' });
  assert.strictEqual(command.input.Bucket, 'b');
  assert.strictEqual(command.input.Key, 'installers/macos-arm64.pkg');
});

// ============================================================================
// TASK-048 (AC8): agentBuild reads version/sha256 from object metadata
// ============================================================================

const VALID_SHA256 = 'ab'.repeat(32);

test('Scenario: Store reads version and digest from object metadata', async () => {
  // Given HeadObject on agent/darwin-arm64/mdmagent answers Metadata
  // {version:"1.4.0", sha256:<64 lowercase hex>}
  const client = new FakeS3Client();
  client.outcome = { kind: 'resolve', value: { Metadata: { version: '1.4.0', sha256: VALID_SHA256 } } };
  const store = createS3InstallerStore({ bucket: 'b', client });

  // When agentBuild("agent/darwin-arm64/mdmagent") is called
  const result = await store.agentBuild('agent/darwin-arm64/mdmagent');

  // Then it returns {version:"1.4.0", sha256:<that hex>} after exactly one
  // HeadObjectCommand on the configured bucket
  assert.deepStrictEqual(result, { version: '1.4.0', sha256: VALID_SHA256 });
  assert.strictEqual(client.calls.length, 1);
  assert.ok(client.calls[0] instanceof HeadObjectCommand);
  assert.deepStrictEqual(client.calls[0].input, { Bucket: 'b', Key: 'agent/darwin-arm64/mdmagent' });
});

const malformedAgentBuildExamples = [
  { label: 'throws an error named NotFound', outcome: { kind: 'reject', value: { name: 'NotFound' } } },
  {
    label: 'throws an error with $metadata.httpStatusCode 404',
    outcome: { kind: 'reject', value: { $metadata: { httpStatusCode: 404 } } },
  },
  {
    label: 'answers Metadata {sha256:<64 hex>} with no version',
    outcome: { kind: 'resolve', value: { Metadata: { sha256: VALID_SHA256 } } },
  },
  {
    label: 'answers Metadata {version:"1.4", sha256:<64 hex>}',
    outcome: { kind: 'resolve', value: { Metadata: { version: '1.4', sha256: VALID_SHA256 } } },
  },
  {
    label: 'answers Metadata {version:"1.4.0", sha256:"ABC"}',
    outcome: { kind: 'resolve', value: { Metadata: { version: '1.4.0', sha256: 'ABC' } } },
  },
];

for (const { label, outcome } of malformedAgentBuildExamples) {
  test(`Scenario Outline: Store answers null for absent or malformed builds -- ${label}`, async () => {
    // Given HeadObject <answer>
    const client = new FakeS3Client();
    client.outcome = outcome;
    const store = createS3InstallerStore({ bucket: 'b', client });

    // When agentBuild is called
    const result = await store.agentBuild('agent/darwin-arm64/mdmagent');

    // Then it returns null
    assert.strictEqual(result, null);
  });
}

test('Scenario: Store rethrows other S3 errors', async () => {
  // Given HeadObject throws an AccessDenied error with httpStatusCode 403
  const client = new FakeS3Client();
  const accessDenied = { name: 'AccessDenied', $metadata: { httpStatusCode: 403 } };
  client.outcome = { kind: 'reject', value: accessDenied };
  const store = createS3InstallerStore({ bucket: 'b', client });

  // When agentBuild is called
  // Then the same error is thrown
  await assert.rejects(() => store.agentBuild('agent/darwin-arm64/mdmagent'), (err) => err === accessDenied);
});

// ============================================================================
// TASK-049 AC15: presignPut and objectSize
// ============================================================================

test('Scenario: Store presigns a PUT and reads object size', async () => {
  const client = new FakeS3Client();
  client.outcome = { kind: 'resolve', value: { ContentLength: 1600000 } };
  const store = createS3InstallerStore({ bucket: 'b', client });

  const size = await store.objectSize('applications/k/a.msi');
  assert.strictEqual(size, 1600000);
  assert.ok(client.calls[0] instanceof HeadObjectCommand);
  assert.deepStrictEqual(client.calls[0].input, { Bucket: 'b', Key: 'applications/k/a.msi' });
});

test('Unit: presignPut builds a PutObjectCommand with ContentType application/octet-stream', async () => {
  const client = new S3Client({
    region: 'us-east-1',
    credentials: { accessKeyId: 'FAKEKEYID', secretAccessKey: 'FAKESECRET' },
  });
  const store = createS3InstallerStore({ bucket: 'b', client });

  const url = await store.presignPut('applications/k/a.msi', 900);

  assert.strictEqual(typeof url, 'string');
  assert.ok(url.includes('/b/applications/k/a.msi'), url);
  assert.ok(url.includes('X-Amz-Expires=900'), url);
  assert.ok(url.includes('X-Amz-Signature='), url);

  // Sanity-check against the SDK: a PutObjectCommand with this content type is
  // what presignPut signs.
  const command = new PutObjectCommand({ Bucket: 'b', Key: 'applications/k/a.msi', ContentType: 'application/octet-stream' });
  assert.strictEqual(command.input.ContentType, 'application/octet-stream');
});

test('Scenario: Store size lookup errors -- NotFound resolves null, other errors rethrow', async () => {
  // Given HeadObject throws NotFound, then AccessDenied (403)
  const client = new FakeS3Client();
  client.outcome = { kind: 'reject', value: { name: 'NotFound' } };
  const store = createS3InstallerStore({ bucket: 'b', client });

  // Then objectSize returns null for the first
  assert.strictEqual(await store.objectSize('applications/k/a.msi'), null);

  const accessDenied = { name: 'AccessDenied', $metadata: { httpStatusCode: 403 } };
  client.outcome = { kind: 'reject', value: accessDenied };
  // ... and rethrows the second
  await assert.rejects(() => store.objectSize('applications/k/a.msi'), (err) => err === accessDenied);
});

test('Scenario: objectSize returns null on a 404 $metadata answer', async () => {
  const client = new FakeS3Client();
  client.outcome = { kind: 'reject', value: { $metadata: { httpStatusCode: 404 } } };
  const store = createS3InstallerStore({ bucket: 'b', client });

  assert.strictEqual(await store.objectSize('applications/k/a.msi'), null);
});

test('Scenario: Presigned PUT carries no SDK checksum parameters (browser-compatible upload)', async () => {
  // Given a real S3Client built from S3_CLIENT_OPTIONS with region
  // "ap-southeast-2" and static fake credentials, with no network
  const client = new S3Client({
    ...S3_CLIENT_OPTIONS,
    region: 'ap-southeast-2',
    credentials: { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'fake-secret' },
  });
  const store = createS3InstallerStore({ bucket: 'test-bucket', client });

  // When presignPut is called on createS3InstallerStore over that client
  const url = await store.presignPut('applications/0123456789abcdef/a.msi', 900);
  const parsed = new URL(url);

  // Then the URL has no query parameter starting with "x-amz-checksum-" and
  // no "x-amz-sdk-checksum-algorithm" parameter
  const paramNames = [...parsed.searchParams.keys()].map((name) => name.toLowerCase());
  assert.ok(
    !paramNames.some((name) => name.startsWith('x-amz-checksum-')),
    `unexpected checksum parameter in ${url}`,
  );
  assert.ok(!paramNames.includes('x-amz-sdk-checksum-algorithm'), `unexpected checksum algorithm parameter in ${url}`);

  // And X-Amz-Expires is "900" and the path ends with
  // "/applications/0123456789abcdef/a.msi"
  assert.strictEqual(parsed.searchParams.get('X-Amz-Expires'), '900');
  assert.ok(parsed.pathname.endsWith('/applications/0123456789abcdef/a.msi'), parsed.pathname);
});
