/**
 * E2E cucumber-style and unit tests for the URL hasher Lambda's CDK
 * definition (TASK-050, AC17-AC18): `backend/src/infra/mdm-stack.ts` and
 * `backend/scripts/bundle-lambda.mjs`.
 *
 * Infra tests synthesise the stack in-process with `aws-cdk-lib/assertions`:
 * no real AWS call or database connection is made. The bundle test only
 * checks files on disk left by `npm run build`.
 */

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { MdmStack, HASHER_CODE_PATH } from '../../dist/infra/mdm-stack.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(__dirname, '../..');

function createTestStack(props = {}) {
  const app = new App();
  const stack = new MdmStack(app, 'MdmStack', {
    entraTenantId: props.entraTenantId || 'test-tenant',
    entraClientId: props.entraClientId || 'test-client',
    entraAdminGroupId: props.entraAdminGroupId,
    domainName: props.domainName,
    certificateArn: props.certificateArn,
    hostedZoneId: props.hostedZoneId,
  });
  const template = Template.fromStack(stack);
  return { app, stack, template };
}

function actionsOf(statement) {
  const actions = statement.Action;
  return Array.isArray(actions) ? actions : [actions];
}

function resourcesOf(statement) {
  const resources = statement.Resource;
  return Array.isArray(resources) ? resources : [resources];
}

function policyStatements(template, roleLogicalId) {
  const policies = template.findResources('AWS::IAM::Policy');
  const statements = [];
  for (const policy of Object.values(policies)) {
    const attachedTo = (policy.Properties.Roles ?? []).some((role) => role.Ref === roleLogicalId);
    if (!attachedTo) continue;
    statements.push(...policy.Properties.PolicyDocument.Statement);
  }
  return statements;
}

// ============================================================================
// AC18
// ============================================================================

test('Scenario: Stack deploys the hasher with least privilege', async () => {
  // When I synthesise MdmStack
  const { template } = createTestStack();

  // Then there are exactly two AWS::Lambda::Function resources
  const functions = template.findResources('AWS::Lambda::Function');
  assert.strictEqual(Object.keys(functions).length, 2);

  // And the hasher has Runtime nodejs22.x, Handler index.handler, Timeout 900,
  // MemorySize 512 and environment exactly {TABLE_NAME}
  const hasherEntry = Object.entries(functions).find(([, resource]) => resource.Properties.Timeout === 900);
  assert.ok(hasherEntry, 'expected a function with Timeout 900');
  const [hasherLogicalId, hasherResource] = hasherEntry;
  assert.strictEqual(hasherResource.Properties.Runtime, 'nodejs22.x');
  assert.strictEqual(hasherResource.Properties.Handler, 'index.handler');
  assert.strictEqual(hasherResource.Properties.MemorySize, 512);
  const envKeys = Object.keys(hasherResource.Properties.Environment?.Variables ?? {});
  assert.deepStrictEqual(envKeys, ['TABLE_NAME']);

  // And an EventInvokeConfig for the hasher has MaximumRetryAttempts 0
  const invokeConfigs = Object.values(template.findResources('AWS::Lambda::EventInvokeConfig'));
  const hasherInvokeConfig = invokeConfigs.find((resource) => {
    const ref = resource.Properties.FunctionName;
    return ref?.Ref === hasherLogicalId || (ref?.['Fn::GetAtt']?.[0] === hasherLogicalId);
  });
  assert.ok(hasherInvokeConfig, 'expected an EventInvokeConfig naming the hasher function');
  assert.strictEqual(hasherInvokeConfig.Properties.MaximumRetryAttempts, 0);

  // And the hasher role's inline policy has exactly one statement:
  // dynamodb:UpdateItem on the table ARN
  const hasherRoleLogicalId = hasherResource.Properties.Role['Fn::GetAtt'][0];
  const hasherStatements = policyStatements(template, hasherRoleLogicalId);
  assert.strictEqual(hasherStatements.length, 1, 'the hasher role should have exactly one inline statement');
  assert.deepStrictEqual(actionsOf(hasherStatements[0]), ['dynamodb:UpdateItem']);
  const tables = template.findResources('AWS::DynamoDB::Table');
  const tableLogicalId = Object.keys(tables)[0];
  const hasherResources = resourcesOf(hasherStatements[0]);
  assert.strictEqual(hasherResources.length, 1);
  assert.strictEqual(hasherResources[0]['Fn::GetAtt']?.[0], tableLogicalId);

  // And the API function has Timeout 30, MemorySize 512, env
  // HASHER_FUNCTION_NAME and a statement granting exactly lambda:InvokeFunction
  // on exactly the hasher ARN
  const [apiLogicalId, apiResource] = Object.entries(functions).find(([id]) => id !== hasherLogicalId);
  assert.strictEqual(apiResource.Properties.Timeout, 30);
  assert.strictEqual(apiResource.Properties.MemorySize, 512);
  const apiEnvKeys = Object.keys(apiResource.Properties.Environment?.Variables ?? {});
  assert.ok(apiEnvKeys.includes('HASHER_FUNCTION_NAME'));

  const apiRoleLogicalId = apiResource.Properties.Role['Fn::GetAtt'][0];
  const apiStatements = policyStatements(template, apiRoleLogicalId);
  const invokeStatements = apiStatements.filter((s) => actionsOf(s).length === 1 && actionsOf(s)[0] === 'lambda:InvokeFunction');
  assert.strictEqual(invokeStatements.length, 1, 'exactly one lambda:InvokeFunction statement');
  const invokeResources = resourcesOf(invokeStatements[0]);
  assert.strictEqual(invokeResources.length, 1);
  assert.strictEqual(invokeResources[0]['Fn::GetAtt']?.[0], hasherLogicalId);
});

test('Scenario (edge): Hasher has no broader table access', async () => {
  // When I synthesise MdmStack
  const { template } = createTestStack();
  const functions = template.findResources('AWS::Lambda::Function');
  const hasherEntry = Object.entries(functions).find(([, resource]) => resource.Properties.Timeout === 900);
  const [, hasherResource] = hasherEntry;
  const hasherRoleLogicalId = hasherResource.Properties.Role['Fn::GetAtt'][0];
  const hasherStatements = policyStatements(template, hasherRoleLogicalId);

  // Then no statement attached to the hasher role grants dynamodb:GetItem,
  // dynamodb:PutItem, dynamodb:DeleteItem, dynamodb:Query or dynamodb:Scan
  const forbidden = ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:DeleteItem', 'dynamodb:Query', 'dynamodb:Scan'];
  for (const statement of hasherStatements) {
    const actions = actionsOf(statement);
    for (const action of forbidden) {
      assert.ok(!actions.includes(action), `the hasher role must not have ${action}`);
    }
  }
});

test('Unit: HASHER_CODE_PATH resolves to backend/dist-hasher', () => {
  assert.strictEqual(path.resolve(HASHER_CODE_PATH), path.resolve(backendDir, 'dist-hasher'));
});

// ============================================================================
// AC17
// ============================================================================

test('Scenario: Hasher bundle is built', () => {
  // When npm run build completes in backend (already run before the suite)
  // Then backend/dist-hasher/index.mjs exists and exports handler
  const bundlePath = path.join(backendDir, 'dist-hasher', 'index.mjs');
  assert.ok(fs.existsSync(bundlePath), `${bundlePath} should exist`);
});

test('Scenario: Hasher bundle is built -- exports handler', async () => {
  const bundlePath = path.join(backendDir, 'dist-hasher', 'index.mjs');
  const mod = await import(pathToFileURL(bundlePath).href);
  assert.strictEqual(typeof mod.handler, 'function');
  assert.strictEqual(typeof mod.createHasherHandler, 'function');
});

test('Scenario: Hasher bundle is built -- no public or views directory', () => {
  // And backend/dist-hasher contains no public or views directory
  const hasherDir = path.join(backendDir, 'dist-hasher');
  assert.ok(!fs.existsSync(path.join(hasherDir, 'public')));
  assert.ok(!fs.existsSync(path.join(hasherDir, 'views')));
});
