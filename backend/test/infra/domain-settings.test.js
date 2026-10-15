/**
 * Tests for `resolveDomainSettings` (TASK-028, AC12).
 *
 * E2E tests implement the Gherkin scenario "Domain settings resolve from env,
 * then context, then defaults". Unit tests cover the remaining precedence and
 * fallback edge cases.
 *
 * No database calls: this module is pure (env record + context lookup in,
 * plain object out), so nothing here opens any connection.
 */

import test from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  CERTIFICATE_ARN_SECRET_KEY,
  DEFAULT_DOMAIN_NAME,
  resolveDomainSettings,
} from '../../dist/infra/domain-settings.js';

const CERT = 'arn:aws:acm:us-east-1:123456789012:certificate/abc-123';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const appTsSource = readFileSync(path.resolve(__dirname, '../../src/infra/app.ts'), 'utf-8');

// ============================================================================
// E2E: Gherkin scenario "Domain settings resolve from env, then context, then defaults"
// ============================================================================

test('E2E: Scenario: Domain settings resolve from env, then context, then defaults', async (t) => {
  // Given env MDM_DOMAIN_NAME is "" and MDM_CERTIFICATE_ARN is CERT
  // And CDK context hostedZoneId is "Z-CTX" and certificateArn is "ignored"
  const env = { MDM_DOMAIN_NAME: '', MDM_CERTIFICATE_ARN: CERT };
  const context = (key) => {
    if (key === 'hostedZoneId') return 'Z-CTX';
    if (key === 'certificateArn') return 'ignored';
    return undefined;
  };

  // When I call resolveDomainSettings
  const settings = resolveDomainSettings({ env, context });

  // Then domainName is "mdm.officehq.cc" which equals DEFAULT_DOMAIN_NAME
  assert.strictEqual(DEFAULT_DOMAIN_NAME, 'mdm.officehq.cc');
  assert.strictEqual(settings.domainName, 'mdm.officehq.cc');
  assert.strictEqual(settings.domainName, DEFAULT_DOMAIN_NAME);

  // And certificateArn is CERT (env wins over context, even though context also has a value)
  assert.strictEqual(settings.certificateArn, CERT);

  // And hostedZoneId is "Z-CTX" (no env var set, so context is used)
  assert.strictEqual(settings.hostedZoneId, 'Z-CTX');

  // When env and context are both empty
  const empty = resolveDomainSettings({ env: {}, context: () => undefined });

  // Then certificateArn and hostedZoneId are undefined
  assert.strictEqual(empty.certificateArn, undefined);
  assert.strictEqual(empty.hostedZoneId, undefined);
  // And domainName still falls back to the default
  assert.strictEqual(empty.domainName, DEFAULT_DOMAIN_NAME);
});

// ============================================================================
// Unit: precedence and edge cases
// ============================================================================

test('Unit: env MDM_DOMAIN_NAME wins over context domainName', async (t) => {
  const settings = resolveDomainSettings({
    env: { MDM_DOMAIN_NAME: 'from-env.example.com' },
    context: (key) => (key === 'domainName' ? 'from-context.example.com' : undefined),
  });
  assert.strictEqual(settings.domainName, 'from-env.example.com');
});

test('Unit: context domainName is used when env is unset', async (t) => {
  const settings = resolveDomainSettings({
    env: {},
    context: (key) => (key === 'domainName' ? 'from-context.example.com' : undefined),
  });
  assert.strictEqual(settings.domainName, 'from-context.example.com');
});

test('Unit: an empty string env var counts as unset and falls through to context', async (t) => {
  const settings = resolveDomainSettings({
    env: { MDM_CERTIFICATE_ARN: '' },
    context: (key) => (key === 'certificateArn' ? CERT : undefined),
  });
  assert.strictEqual(settings.certificateArn, CERT);
});

test('Unit: a non-string context value is ignored, falling back to undefined', async (t) => {
  const settings = resolveDomainSettings({
    env: {},
    context: (key) => (key === 'hostedZoneId' ? 42 : undefined),
  });
  assert.strictEqual(settings.hostedZoneId, undefined);
});

test('Unit: an empty-string context value is ignored, falling back to undefined', async (t) => {
  const settings = resolveDomainSettings({
    env: {},
    context: (key) => (key === 'hostedZoneId' ? '' : undefined),
  });
  assert.strictEqual(settings.hostedZoneId, undefined);
});

test('Unit: domainName falls back to DEFAULT_DOMAIN_NAME when neither env nor context set it', async (t) => {
  const settings = resolveDomainSettings({ env: {}, context: () => undefined });
  assert.strictEqual(settings.domainName, DEFAULT_DOMAIN_NAME);
});

// ============================================================================
// E2E: Gherkin scenario "app.ts wires the resolved domain settings into the stack"
// ============================================================================

test('E2E: Scenario: app.ts wires the resolved domain settings into the stack', async (t) => {
  // Given the source of backend/src/infra/app.ts

  // Then MdmStack receives domainName, certificateArn and hostedZoneId from resolveDomainSettings
  assert.match(appTsSource, /import\s*\{\s*resolveDomainSettings\s*\}\s*from\s*'\.\/domain-settings\.js';/);
  assert.match(
    appTsSource,
    /new MdmStack\(app, 'MdmStack', \{[\s\S]*\.\.\.resolveDomainSettings\(\{\s*env:\s*process\.env,\s*context:\s*\(k\)\s*=>\s*app\.node\.tryGetContext\(k\),\s*secret\s*\}\)[\s\S]*\}\);/,
    'MdmStack construction should spread resolveDomainSettings(...) with the loaded deploy secret into its props'
  );

  // And the Entra and ENTRA_ADMIN_GROUP_ID lookups are unchanged
  assert.match(appTsSource, /entraTenantId,\s*\n\s*entraClientId,/);
  assert.match(appTsSource, /entraAdminGroupId:\s*setting\('ENTRA_ADMIN_GROUP_ID',\s*'entraAdminGroupId'\)/);
});

// ============================================================================
// Certificate ARN from the deploy secret prod/sk-mdm
// ============================================================================

/** A DeploySecrets-shaped fake over a plain map. */
function fakeSecret(values) {
  return { secretId: 'prod/sk-mdm', get: (key) => values[key] };
}

test('Unit: certificateArn falls back to MDM_CERTIFICATE_ARN in the deploy secret', async (t) => {
  const settings = resolveDomainSettings({
    env: {},
    context: () => undefined,
    secret: fakeSecret({ MDM_CERTIFICATE_ARN: `  ${CERT}\n` }),
  });
  assert.strictEqual(settings.certificateArn, CERT);
  assert.strictEqual(CERTIFICATE_ARN_SECRET_KEY, 'MDM_CERTIFICATE_ARN');
});

test('Unit: env and context certificateArn win over the deploy secret', async (t) => {
  const secret = fakeSecret({ MDM_CERTIFICATE_ARN: 'from-secret' });
  const fromEnv = resolveDomainSettings({ env: { MDM_CERTIFICATE_ARN: CERT }, context: () => 'from-context', secret });
  assert.strictEqual(fromEnv.certificateArn, CERT);
  const fromContext = resolveDomainSettings({
    env: {},
    context: (key) => (key === 'certificateArn' ? 'from-context' : undefined),
    secret,
  });
  assert.strictEqual(fromContext.certificateArn, 'from-context');
});

test('Unit: an absent, empty or whitespace secret certificateArn resolves to undefined', async (t) => {
  for (const values of [{}, { MDM_CERTIFICATE_ARN: '' }, { MDM_CERTIFICATE_ARN: '  ' }]) {
    const settings = resolveDomainSettings({ env: {}, context: () => undefined, secret: fakeSecret(values) });
    assert.strictEqual(settings.certificateArn, undefined);
  }
});

test('Unit: the deploy secret supplies only the certificate ARN', async (t) => {
  const settings = resolveDomainSettings({
    env: {},
    context: () => undefined,
    secret: fakeSecret({ MDM_DOMAIN_NAME: 'other.example.com', MDM_HOSTED_ZONE_ID: 'ZSECRET' }),
  });
  assert.strictEqual(settings.domainName, DEFAULT_DOMAIN_NAME);
  assert.strictEqual(settings.hostedZoneId, undefined);
});

test('Unit: all three values can be fully resolved from env', async (t) => {
  const settings = resolveDomainSettings({
    env: {
      MDM_DOMAIN_NAME: 'mdm.officehq.cc',
      MDM_CERTIFICATE_ARN: CERT,
      MDM_HOSTED_ZONE_ID: 'Z0123456789ABC',
    },
    context: () => undefined,
  });
  assert.deepStrictEqual(settings, {
    domainName: 'mdm.officehq.cc',
    certificateArn: CERT,
    hostedZoneId: 'Z0123456789ABC',
  });
});
