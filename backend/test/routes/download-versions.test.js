/**
 * Tests for `GET /api/v1/downloads` -- the published version of each installer,
 * shown next to its download link on the landing page.
 *
 * The route never constructs an AWS client: the store is a fake, and the S3
 * store's `version` is driven through a fake SDK client.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const {
  DOWNLOAD_PLATFORMS,
  DOWNLOAD_VERSIONS_PATH,
  createDownloadVersionsHandler,
  registerDownloadRoute,
  installerKey,
  versionFromContentDisposition,
} = await import(`file://${join(__dirname, '../../dist/routes/downloads.js')}`);
const { createS3InstallerStore } = await import(`file://${join(__dirname, '../../dist/storage/installers.js')}`);
const { createRouter } = await import(`file://${join(__dirname, '../../dist/http/router.js')}`);

/** A fake InstallerStore answering a scripted version per key. */
function fakeStore(versions) {
  const calls = [];
  return {
    calls,
    async exists() {
      return true;
    },
    async presignGet() {
      return 'https://signed';
    },
    async version(key) {
      calls.push(key);
      return versions[key] ?? null;
    },
  };
}

test('versionFromContentDisposition reads the version from the published file name', () => {
  assert.equal(versionFromContentDisposition('attachment; filename="OfficeHQ-MDM-1.2.3-x64.msi"'), '1.2.3');
  assert.equal(versionFromContentDisposition('attachment; filename="OfficeHQ-MDM-10.0.42-arm64.pkg"'), '10.0.42');
  assert.equal(versionFromContentDisposition('attachment; filename=OfficeHQ-MDM-2.0.0-amd64.pkg'), '2.0.0');
});

test('versionFromContentDisposition is null for anything without a version', () => {
  assert.equal(versionFromContentDisposition(undefined), null);
  assert.equal(versionFromContentDisposition(''), null);
  assert.equal(versionFromContentDisposition('attachment'), null);
  assert.equal(versionFromContentDisposition('attachment; filename="installer.msi"'), null);
});

test('the versions route is public and lives under /api/v1', () => {
  assert.equal(DOWNLOAD_VERSIONS_PATH, '/api/v1/downloads');
});

test('every platform is answered, null where nothing is published', async () => {
  const store = fakeStore({
    [installerKey('windows-x64')]: '1.4.0',
    [installerKey('macos-arm64')]: '1.3.9',
  });
  const handler = createDownloadVersionsHandler({ bucket: 'b', installers: store });

  const result = await handler({ params: {}, headers: {} });

  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body, {
    versions: {
      'windows-x64': '1.4.0',
      'windows-arm64': null,
      'macos-amd64': null,
      'macos-arm64': '1.3.9',
    },
  });
  assert.deepEqual(store.calls.sort(), DOWNLOAD_PLATFORMS.map((p) => installerKey(p)).sort());
  assert.equal(result.headers?.['cache-control'], 'no-store');
});

test('a store without version support answers null for every platform', async () => {
  const handler = createDownloadVersionsHandler({
    bucket: 'b',
    installers: { exists: async () => true, presignGet: async () => '' },
  });

  const result = await handler({ params: {}, headers: {} });

  assert.equal(result.statusCode, 200);
  assert.deepEqual(Object.values(result.body.versions), [null, null, null, null]);
});

test('an unconfigured route answers 500 not_configured', async () => {
  for (const deps of [{ bucket: '', installers: fakeStore({}) }, { bucket: 'b' }, { bucket: undefined }]) {
    const result = await createDownloadVersionsHandler(deps)({ params: {}, headers: {} });
    assert.equal(result.statusCode, 500);
    assert.deepEqual(result.body, { error: 'not_configured' });
  }
});

test('registerDownloadRoute also registers the versions route', async () => {
  const router = createRouter();
  registerDownloadRoute(router, { bucket: 'b', installers: fakeStore({ [installerKey('windows-arm64')]: '9.9.9' }) });

  const result = await router.handle({ method: 'GET', path: DOWNLOAD_VERSIONS_PATH, query: {}, headers: {}, body: null });

  assert.equal(result.statusCode, 200);
  assert.equal(JSON.parse(result.body).versions['windows-arm64'], '9.9.9');
});

test('the S3 store reads the version from the object Content-Disposition', async () => {
  const sent = [];
  const client = {
    async send(command) {
      sent.push(command.input);
      return { ContentDisposition: 'attachment; filename="OfficeHQ-MDM-1.5.2-x64.msi"' };
    },
  };
  const store = createS3InstallerStore({ bucket: 'b', client });

  assert.equal(await store.version('installers/windows-x64.msi'), '1.5.2');
  assert.deepEqual(sent, [{ Bucket: 'b', Key: 'installers/windows-x64.msi' }]);
});

test('the S3 store answers null for an absent object and rethrows anything else', async () => {
  const notFound = Object.assign(new Error('nf'), { name: 'NotFound' });
  const absent = createS3InstallerStore({ bucket: 'b', client: { send: async () => { throw notFound; } } });
  assert.equal(await absent.version('installers/macos-arm64.pkg'), null);

  const broken = createS3InstallerStore({ bucket: 'b', client: { send: async () => { throw new Error('boom'); } } });
  await assert.rejects(broken.version('installers/macos-arm64.pkg'), /boom/);
});
