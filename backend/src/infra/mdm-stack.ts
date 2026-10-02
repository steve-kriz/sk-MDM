/**
 * CDK stack for SK-MDM.
 *
 * One single-table DynamoDB store, the Secrets Manager secret holding the
 * pepper used to encrypt device secrets, the Node.js Lambda that serves both
 * the agent collection endpoints and the admin UI, and the Function URL that
 * installers point at.
 *
 * The Function URL is created with `AuthType` `NONE` on purpose: agents
 * authenticate with the enrollment token (enroll) or the device HMAC scheme
 * (every other device endpoint) in the application layer, so AWS IAM signing
 * at the edge would reject every legitimate agent request.
 *
 * When `domainName` is set, a CloudFront distribution serves that domain in
 * front of the Function URL, with an out-of-band us-east-1 ACM certificate
 * (`certificateArn`) and, when `hostedZoneId` is set, Route 53 A/AAAA alias
 * records. The Function URL stays public so already-installed agents keep
 * working.
 */
import { fileURLToPath } from 'node:url';

import { CfnOutput, Duration, RemovalPolicy, Stack, type StackProps } from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as targets from 'aws-cdk-lib/aws-route53-targets';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import type { Construct } from 'constructs';

export interface MdmStackProps extends StackProps {
  /** Entra ID (Azure AD) tenant the admin UI authenticates against. Required. */
  readonly entraTenantId: string;
  /** Entra ID application (client) id of the admin UI. Required. */
  readonly entraClientId: string;
  /** Object id of the Entra group whose members are admins. Optional. */
  readonly entraAdminGroupId?: string;
  /** Name of the secret holding the Graph client secret, read at runtime. Defaults to `prod/sk-mdm`. */
  readonly graphSecretName?: string;
  /** JSON key of the Graph client secret inside that secret. Defaults to `ENTRA_CLIENT_SECRET`. */
  readonly graphSecretKey?: string;
  /** Public host name served through CloudFront, e.g. `mdm.officehq.cc`. Optional. */
  readonly domainName?: string;
  /** ARN of the ACM certificate (us-east-1) for `domainName`. Required with `domainName`. */
  readonly certificateArn?: string;
  /** Route 53 hosted zone for `domainName` minus its first label. Optional: no DNS records without it. */
  readonly hostedZoneId?: string;
}

const DOMAIN_NAME_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const CERTIFICATE_ARN_PATTERN = /^arn:aws:acm:us-east-1:\d{12}:certificate\/[A-Za-z0-9-]+$/;

interface DomainConfig {
  readonly domainName: string;
  readonly certificateArn: string;
  readonly hostedZoneId: string | undefined;
}

/** Validate the custom-domain props; `undefined` when no domain is configured. */
function domainConfig(props: MdmStackProps | undefined): DomainConfig | undefined {
  const domainName = props?.domainName ?? '';
  const certificateArn = props?.certificateArn ?? '';
  const hostedZoneId = props?.hostedZoneId ?? '';
  if (domainName === '') {
    if (certificateArn !== '' || hostedZoneId !== '') {
      throw new Error('domainName is required when certificateArn or hostedZoneId is set');
    }
    return undefined;
  }
  if (!DOMAIN_NAME_PATTERN.test(domainName)) {
    throw new Error('domainName must be a lower-case host name such as mdm.officehq.cc');
  }
  if (certificateArn === '') {
    throw new Error('certificateArn is required when domainName is set');
  }
  if (!CERTIFICATE_ARN_PATTERN.test(certificateArn)) {
    throw new Error('certificateArn must be an ACM certificate in us-east-1');
  }
  return { domainName, certificateArn, hostedZoneId: hostedZoneId === '' ? undefined : hostedZoneId };
}

/** The secret the Lambda reads the Graph client secret from, when none is named. */
export const DEFAULT_GRAPH_SECRET_NAME = 'prod/sk-mdm';

/** The JSON key of the Graph client secret, when none is named. */
export const DEFAULT_GRAPH_SECRET_KEY = 'ENTRA_CLIENT_SECRET';

/**
 * Directory handed to the Lambda as its code asset: the self-contained esbuild
 * bundle written by `scripts/bundle-lambda.mjs` (`backend/dist-lambda`, two
 * levels up from this module once built in `dist/infra`). It holds the
 * `index.mjs` named by the `index.handler` handler, with the AWS SDK inside it,
 * because the asset ships no `node_modules`.
 */
export const LAMBDA_CODE_PATH = fileURLToPath(new URL('../../dist-lambda/', import.meta.url));

function required(value: string | undefined, name: string): string {
  if (value === undefined || value === '') {
    throw new Error(`${name} is required`);
  }
  return value;
}

export class MdmStack extends Stack {
  /** The single-table DynamoDB store. */
  public readonly table: dynamodb.Table;
  /** The secret holding the pepper used to encrypt device secrets. */
  public readonly pepperSecret: secretsmanager.Secret;
  /** The Lambda serving the agent endpoints and the admin UI. */
  public readonly fn: lambda.Function;
  /** The public Function URL installers point at. */
  public readonly functionUrl: lambda.FunctionUrl;
  /** The private bucket the agent installers are published to. */
  public readonly installerBucket: s3.Bucket;
  /** The CloudFront distribution serving `domainName`, when one is configured. */
  public readonly distribution?: cloudfront.Distribution;

  constructor(scope: Construct, id: string, props?: MdmStackProps) {
    super(scope, id, props);

    // Fail during construction, before synth produces a template.
    const entraTenantId = required(props?.entraTenantId, 'entraTenantId');
    const entraClientId = required(props?.entraClientId, 'entraClientId');
    // Optional: CDK drops `undefined` from the environment map, which would
    // leave the Lambda reading `undefined`, so fall back to the empty string.
    const entraAdminGroupId = props?.entraAdminGroupId ?? '';
    const domain = domainConfig(props);
    const graphSecretName = props?.graphSecretName || DEFAULT_GRAPH_SECRET_NAME;
    const graphSecretKey = props?.graphSecretKey || DEFAULT_GRAPH_SECRET_KEY;

    this.table = new dynamodb.Table(this, 'Table', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      timeToLiveAttribute: 'ttl',
    });

    this.table.addGlobalSecondaryIndex({
      indexName: 'gsi1',
      partitionKey: { name: 'gsi1pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'gsi1sk', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Generated by CloudFormation: the pepper itself never appears in the
    // template, in source control or in a deploy log.
    this.pepperSecret = new secretsmanager.Secret(this, 'PepperSecret', {
      description: 'Pepper used to encrypt device secrets',
      generateSecretString: {
        passwordLength: 64,
        excludePunctuation: true,
      },
    });

    // Private, TLS-only, versioned and retained. No `autoDeleteObjects`: that
    // would add a custom-resource Lambda, and the installers outlive the stack.
    this.installerBucket = new s3.Bucket(this, 'InstallerBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.fn = new lambda.Function(this, 'ApiFunction', {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(LAMBDA_CODE_PATH),
      timeout: Duration.seconds(30),
      memorySize: 512,
      environment: {
        TABLE_NAME: this.table.tableName,
        ENTRA_TENANT_ID: entraTenantId,
        ENTRA_CLIENT_ID: entraClientId,
        ENTRA_ADMIN_GROUP_ID: entraAdminGroupId,
        PEPPER_SECRET_ARN: this.pepperSecret.secretArn,
        INSTALLER_BUCKET: this.installerBucket.bucketName,
        // Literals, not distribution tokens: a token would make the Lambda
        // depend on the distribution, which depends on the Function URL.
        ...(domain
          ? { PUBLIC_HOST: domain.domainName, COLLECTION_URL: `https://${domain.domainName}/` }
          : {}),
        GRAPH_SECRET_ID: graphSecretName,
        GRAPH_SECRET_KEY: graphSecretKey,
      },
    });

    // Scoped to the table and its indexes.
    this.table.grantReadWriteData(this.fn);

    // Written out by hand rather than with `pepperSecret.grantRead()`: the
    // grant helper widens the statement to DescribeSecret (and to KMS when the
    // secret is encrypted with a customer key). The Lambda only ever reads the
    // one secret's value. The same statement covers the secret holding the
    // Graph client secret (TASK-027), named rather than created here; the
    // `-??????` suffix matches the random characters Secrets Manager appends.
    this.fn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['secretsmanager:GetSecretValue'],
        resources: [
          this.pepperSecret.secretArn,
          `arn:${this.partition}:secretsmanager:${this.region}:${this.account}:secret:${graphSecretName}-??????`,
        ],
      }),
    );

    // Written by hand rather than with `installerBucket.grantRead()`, which adds
    // broader actions. GetObject is limited to the installers/ prefix; ListBucket
    // lets S3 answer a missing key with 404 rather than 403.
    this.fn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['s3:GetObject'],
        resources: [this.installerBucket.arnForObjects('installers/*')],
      }),
    );
    this.fn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['s3:ListBucket'],
        resources: [this.installerBucket.bucketArn],
      }),
    );

    this.functionUrl = this.fn.addFunctionUrl({
      authType: lambda.FunctionUrlAuthType.NONE,
    });

    if (domain) {
      // No OAC (`withOriginAccessControl`): it needs IAM-signed origin requests,
      // which would break HMAC agents. The Function URL rejects a forwarded
      // viewer Host header, hence AllViewerExceptHostHeader; the Lambda learns
      // its public host from PUBLIC_HOST instead.
      this.distribution = new cloudfront.Distribution(this, 'Distribution', {
        defaultBehavior: {
          origin: new origins.FunctionUrlOrigin(this.functionUrl),
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        },
        domainNames: [domain.domainName],
        certificate: acm.Certificate.fromCertificateArn(this, 'Certificate', domain.certificateArn),
        minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      });

      if (domain.hostedZoneId !== undefined) {
        // Attributes rather than `fromLookup`, so synth needs no account context.
        const zone = route53.HostedZone.fromHostedZoneAttributes(this, 'HostedZone', {
          hostedZoneId: domain.hostedZoneId,
          zoneName: domain.domainName.split('.').slice(1).join('.'),
        });
        const target = route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(this.distribution));
        new route53.ARecord(this, 'AliasRecord', { zone, recordName: domain.domainName, target });
        new route53.AaaaRecord(this, 'AliasRecordIpv6', { zone, recordName: domain.domainName, target });
      }

      new CfnOutput(this, 'DistributionDomainName', {
        description: 'CloudFront domain to point the custom domain CNAME at when DNS is external',
        value: this.distribution.distributionDomainName,
      });
    }

    new CfnOutput(this, 'CollectionUrl', {
      description: 'Collection URL the agent installers point at',
      value: domain ? `https://${domain.domainName}/` : this.functionUrl.url,
    });

    new CfnOutput(this, 'FunctionUrl', {
      description: 'Raw Lambda Function URL, kept for agents installed against it',
      value: this.functionUrl.url,
    });

    new CfnOutput(this, 'InstallerBucketName', {
      description: 'Bucket scripts/publish-installers.mjs uploads the agent installers to',
      value: this.installerBucket.bucketName,
    });
  }
}
