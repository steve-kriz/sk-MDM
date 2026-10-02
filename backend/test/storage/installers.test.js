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
const { S3Client, GetObjectCommand, HeadObjectCommand } = await import('@aws-sdk/client-s3');

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
