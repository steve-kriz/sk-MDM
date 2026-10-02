/**
 * The one deployment value the settings screen shows: the URL installers point
 * at.
 *
 *   collectionUrl(process.env) -> 'https://abc.lambda-url.ap-southeast-2.on.aws/'
 *
 * `COLLECTION_URL` wins when it is set -- it is how a deployment names a custom
 * domain in front of the Function URL -- and the Function URL Lambda publishes
 * to its own environment is the fallback, so a stock deployment needs no
 * configuration at all.
 */

/** The environment this module reads: `process.env`, or a fake in a test. */
export type SettingsEnv = Record<string, string | undefined>;

/** The URL to give installers, or `undefined` when neither variable is set. */
export function collectionUrl(env: SettingsEnv): string | undefined {
  const configured = env.COLLECTION_URL;
  if (typeof configured === 'string' && configured.length > 0) {
    return configured;
  }
  return env.AWS_LAMBDA_FUNCTION_URL;
}
