/**
 * E2E cucumber-style tests for TASK-044's CloudWatch Logs infrastructure in
 * the synthesized `MdmStack` template: the retained 30-day heartbeat log
 * group, its `HEARTBEAT_LOG_GROUP` Lambda environment variable, its output,
 * and the Lambda's scoped IAM statement. Models `backend/test/infra/mdm-stack.test.js`.
 */

import test from 'node:test';
import assert from 'node:assert';
import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { MdmStack } from '../../dist/infra/mdm-stack.js';

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

// ============================================================================
// Scenario: The stack creates a retained 30-day heartbeat log group wired
// into the Lambda (AC6)
// ============================================================================

test('Scenario: Exactly one heartbeat log group, retained, 30-day retention', () => {
  const { template } = createTestStack();

  const logGroups = template.findResources('AWS::Logs::LogGroup');
  const ids = Object.keys(logGroups);
  assert.strictEqual(ids.length, 1, 'exactly one AWS::Logs::LogGroup');

  const resource = logGroups[ids[0]];
  assert.strictEqual(resource.Properties.RetentionInDays, 30);
  assert.strictEqual(resource.DeletionPolicy, 'Retain');
});

test('Scenario: The Lambda environment HEARTBEAT_LOG_GROUP is a Ref to that log group', () => {
  const { template } = createTestStack();

  const logGroups = template.findResources('AWS::Logs::LogGroup');
  const logGroupId = Object.keys(logGroups)[0];

  const functions = template.findResources('AWS::Lambda::Function');
  const fnId = Object.keys(functions)[0];
  const env = functions[fnId].Properties.Environment.Variables;

  assert.deepStrictEqual(env.HEARTBEAT_LOG_GROUP, { Ref: logGroupId });
});

test('Scenario: An output "HeartbeatLogGroupName" exists', () => {
  const { template } = createTestStack();
  template.hasOutput('HeartbeatLogGroupName', {});
});

// ============================================================================
// Scenario: The Lambda gets only the three log actions on that group (AC7)
// ============================================================================

test('Scenario: Exactly one role statement has the three log actions, scoped to the log group ARN', () => {
  const { template } = createTestStack();

  const logGroups = template.findResources('AWS::Logs::LogGroup');
  const logGroupId = Object.keys(logGroups)[0];

  const policies = template.findResources('AWS::IAM::Policy');
  const logStatements = [];
  for (const policy of Object.values(policies)) {
    const statements = policy.Properties.PolicyDocument.Statement;
    for (const statement of statements) {
      const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
      if (actions.some((a) => typeof a === 'string' && a.startsWith('logs:'))) {
        logStatements.push(statement);
      }
    }
  }

  assert.strictEqual(logStatements.length, 1, 'exactly one statement touches logs: actions');
  const statement = logStatements[0];
  const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
  assert.deepStrictEqual([...actions].sort(), ['logs:CreateLogStream', 'logs:GetLogEvents', 'logs:PutLogEvents'].sort());

  const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
  assert.strictEqual(resources.length, 1);
  assert.deepStrictEqual(resources[0], { 'Fn::GetAtt': [logGroupId, 'Arn'] });
});

test('Scenario: No IAM statement anywhere in the stack uses Resource "*"', () => {
  const { template } = createTestStack();
  const policies = template.findResources('AWS::IAM::Policy');
  for (const policy of Object.values(policies)) {
    for (const statement of policy.Properties.PolicyDocument.Statement) {
      const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
      assert.ok(!resources.includes('*'), `statement ${JSON.stringify(statement)} must not use Resource "*"`);
    }
  }
});
