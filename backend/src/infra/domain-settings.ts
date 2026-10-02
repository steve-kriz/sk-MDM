/**
 * Resolves the custom-domain settings `MdmStack` is built with.
 *
 * Per value, a non-empty environment variable wins (`MDM_DOMAIN_NAME`,
 * `MDM_CERTIFICATE_ARN`, `MDM_HOSTED_ZONE_ID`), then a non-empty string CDK
 * context value (`domainName`, `certificateArn`, `hostedZoneId`). `domainName`
 * falls back to `DEFAULT_DOMAIN_NAME`; the other two fall back to `undefined`.
 *
 * Pure: the environment and the context lookup are passed in, so the
 * precedence can be tested without an `App`.
 */

/** The main public domain SK-MDM is served on. */
export const DEFAULT_DOMAIN_NAME = 'mdm.officehq.cc';

export interface DomainSettingsInput {
  /** `process.env`, or a fake in a test. */
  readonly env: Record<string, string | undefined>;
  /** CDK context lookup, e.g. `(k) => app.node.tryGetContext(k)`. */
  readonly context: (key: string) => unknown;
}

export interface DomainSettings {
  readonly domainName: string;
  readonly certificateArn: string | undefined;
  readonly hostedZoneId: string | undefined;
}

function resolve(input: DomainSettingsInput, envName: string, contextKey: string): string | undefined {
  const fromEnv = input.env[envName];
  if (fromEnv !== undefined && fromEnv !== '') {
    return fromEnv;
  }
  const fromContext = input.context(contextKey);
  return typeof fromContext === 'string' && fromContext !== '' ? fromContext : undefined;
}

export function resolveDomainSettings(input: DomainSettingsInput): DomainSettings {
  return {
    domainName: resolve(input, 'MDM_DOMAIN_NAME', 'domainName') ?? DEFAULT_DOMAIN_NAME,
    certificateArn: resolve(input, 'MDM_CERTIFICATE_ARN', 'certificateArn'),
    hostedZoneId: resolve(input, 'MDM_HOSTED_ZONE_ID', 'hostedZoneId'),
  };
}
