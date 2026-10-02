/**
 * The S3-backed installer store the download route reads through.
 *
 * Wraps an SDK-shaped S3 client (`send(command)` taking an AWS SDK v3
 * Command), the same factory-plus-adapter shape bootstrap uses for DynamoDB
 * and Secrets Manager: the client is built by the injected `createS3Client`
 * factory, never here.
 *
 *   exists(key)          -> HeadObject; true, or false on a not-found answer
 *   presignGet(key, ttl) -> a presigned GetObject URL valid for `ttl` seconds
 */
import { GetObjectCommand, HeadObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import type { InstallerStore } from '../routes/downloads.js';

export interface S3InstallerStoreOptions {
  /** The installer bucket's name. */
  bucket: string;
  /** The SDK-shaped S3 client. */
  client: S3Client;
}

/** True when a thrown value is S3's answer for a key that does not exist. */
function isNotFound(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) {
    return false;
  }
  const candidate = error as { name?: unknown; $metadata?: { httpStatusCode?: unknown } };
  return candidate.name === 'NotFound' || candidate.$metadata?.httpStatusCode === 404;
}

export function createS3InstallerStore({ bucket, client }: S3InstallerStoreOptions): InstallerStore {
  return {
    async exists(key: string): Promise<boolean> {
      try {
        await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
        return true;
      } catch (error) {
        if (isNotFound(error)) {
          return false;
        }
        throw error;
      }
    },

    presignGet(key: string, ttlSeconds: number): Promise<string> {
      return getSignedUrl(client, new GetObjectCommand({ Bucket: bucket, Key: key }), { expiresIn: ttlSeconds });
    },
  };
}
