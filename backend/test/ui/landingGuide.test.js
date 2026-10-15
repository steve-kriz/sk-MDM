/**
 * Tests for the landing page's explanation of the agent and its screenshots:
 * the PNGs are served as binary (base64 through the Function URL), every image
 * the page names was shipped, and the page says what is and is not collected.
 */

import test from 'node:test';
import assert from 'node:assert';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { handler } from '../../dist/index.js';

const { serveAsset, PUBLIC_DIR, SECURITY_HEADERS } = await import('../../dist/ui/index.js');

function get(path, headers = {}) {
  return handler({ requestContext: { http: { method: 'GET', path } }, headers });
}

const landing = (await get('/')).body;
const imageNames = [...landing.matchAll(/src="\/assets\/public\/(guide-[a-z-]+\.png)"/g)].map((m) => m[1]);

test('Scenario: The landing page shows every shipped guide screenshot, each with alt text', () => {
  const shipped = readdirSync(PUBLIC_DIR).filter((name) => /^guide-.*\.png$/.test(name)).sort();
  assert.strictEqual(shipped.length, 7);
  assert.deepStrictEqual([...imageNames].sort(), shipped);
  for (const tag of landing.match(/<img [^>]*>/gs)) {
    assert.match(tag, /alt="[^"]{20,}"/, tag);
    assert.match(tag, /width="\d+" height="\d+"/, tag);
  }
});

test('Scenario: A PNG is served as binary through the Function URL', async () => {
  for (const name of imageNames) {
    const response = await get(`/assets/public/${name}`, { 'accept-encoding': 'gzip' });
    assert.strictEqual(response.statusCode, 200, name);
    assert.strictEqual(response.headers['content-type'], 'image/png', name);
    assert.strictEqual(response.isBase64Encoded, true, name);
    assert.strictEqual(response.headers['content-encoding'], undefined, 'images are never re-gzipped');
    const bytes = Buffer.from(response.body, 'base64');
    assert.ok(bytes.equals(readFileSync(join(PUBLIC_DIR, name))), `${name} bytes round-trip`);
    assert.strictEqual(response.headers['content-security-policy'], SECURITY_HEADERS['content-security-policy']);
  }
});

test('Unit: serveAsset marks only binary assets base64', () => {
  const png = serveAsset(PUBLIC_DIR, 'guide-posture.png');
  assert.strictEqual(png.isBase64Encoded, true);
  assert.strictEqual(png.headers['content-type'], 'image/png');
  const css = serveAsset(PUBLIC_DIR, 'styles.css');
  assert.strictEqual(css.isBase64Encoded, undefined);
  assert.ok(css.rawBody.includes('.explainer'));
  assert.strictEqual(serveAsset(PUBLIC_DIR, 'missing.png').statusCode, 404);
});

test('Scenario: The page explains collection, the never-collected list and BYOD, above the downloads', () => {
  for (const heading of [
    'What this software does',
    'What we collect',
    'What we never collect',
    'OfficeHQ devices and your own device (BYOD)',
    'What we may change on your device',
    "What we don't do",
    'Why we do this',
  ]) {
    assert.ok(landing.includes(heading), heading);
  }
  for (const phrase of ['serial number', 'browsing history', 'keystrokes', 'not monitoring software']) {
    assert.ok(landing.includes(phrase), phrase);
  }
  // The comparison: location, screen lock and remote installs are OfficeHQ-only.
  for (const row of ['Approximate location', 'Lock the screen after a period of inactivity', 'Install software remotely']) {
    assert.match(landing, new RegExp(`${row}[^<]*</th><td>Yes</td><td>No</td>`), row);
  }
  assert.ok(landing.indexOf('What this software does') < landing.indexOf('id="download"'));
});

test('Scenario: The published screenshot carries no real account', () => {
  assert.ok(!landing.includes('steve.k@'), 'no real email in the page');
  const png = readFileSync(join(PUBLIC_DIR, 'guide-machine-details.png'));
  const original = readFileSync(join(PUBLIC_DIR, '../../../../images/machine_details.png'));
  assert.ok(!png.equals(original), 'the redacted copy is shipped, not the original');
});
