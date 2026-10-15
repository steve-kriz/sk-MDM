/**
 * E2E test for TASK-056: the CloudFront distribution's origin request policy
 * stays `ALL_VIEWER_EXCEPT_HOST_HEADER` (the AWS-managed policy forwarding
 * every CloudFront viewer geolocation header to the Function URL origin).
 * No infrastructure change is required for this ticket; this test only
 * verifies none was made.
 */

import test from 'node:test';
import assert from 'node:assert';
import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { MdmStack } from '../../dist/infra/mdm-stack.js';

// The fixed managed-policy id CDK uses for
// cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER.
const ALL_VIEWER_EXCEPT_HOST_HEADER_ID = 'b689b0a8-53d0-40ab-baf2-68738e2966ac';

const CERT = 'arn:aws:acm:us-east-1:123456789012:certificate/abc-123';
const DOMAIN = 'mdm.officehq.cc';

function createDomainStack() {
  const app = new App();
  const stack = new MdmStack(app, 'MdmStack', {
    entraTenantId: 'test-tenant',
    entraClientId: 'test-client',
    domainName: DOMAIN,
    certificateArn: CERT,
  });
  return { template: Template.fromStack(stack) };
}

test('Scenario: Infrastructure is unchanged - the origin request policy is the managed AllViewerExceptHostHeader policy', () => {
  // Given the CDK stack is synthesised with a custom domain
  const { template } = createDomainStack();

  // Then the distribution's origin request policy is the managed
  // AllViewerExceptHostHeader policy
  const distributions = template.findResources('AWS::CloudFront::Distribution');
  const distConfig = Object.values(distributions)[0].Properties.DistributionConfig;
  const behavior = distConfig.DefaultCacheBehavior;
  assert.strictEqual(behavior.OriginRequestPolicyId, ALL_VIEWER_EXCEPT_HOST_HEADER_ID);
});
