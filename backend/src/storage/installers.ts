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
 *   presignPut(key, ttl) -> a presigned PutObject URL valid for `ttl` seconds
 *   objectSize(key)      -> HeadObject; ContentLength, or null on a not-found answer
 *   version(key)         -> HeadObject; the version in its Content-Disposition, or null
 *   agentBuild(key)      -> HeadObject; {version, sha256} from its user metadata, or null
 */
import { GetObjectCommand, HeadObjectCommand, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { versionFromContentDisposition, type InstallerStore } from '../routes/downloads.js';

export interface S3InstallerStoreOptions {
  /** The installer bucket's name. */
  bucket: string;
  /** The SDK-shaped S3 client. */
  client: S3Client;
}

/** A published agent build's `version` metadata: exactly major.minor.patch. */
const AGENT_BUILD_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+$/;

/** A published agent build's `sha256` metadata: 64 lowercase hex digits. */
const AGENT_BUILD_SHA256 = /^[0-9a-f]{64}$/;

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

    presignPut(key: string, ttlSeconds: number): Promise<string> {
      // ContentType only sets the stored object's content type; the presigner
      // does not sign it, so it is not a security control.
      return getSignedUrl(
        client,
        new PutObjectCommand({ Bucket: bucket, Key: key, ContentType: 'application/octet-stream' }),
        { expiresIn: ttlSeconds },
      );
    },

    async objectSize(key: string): Promise<number | null> {
      try {
        const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
        return typeof head.ContentLength === 'number' ? head.ContentLength : null;
      } catch (error) {
        if (isNotFound(error)) {
          return null;
        }
        throw error;
      }
    },

    async version(key: string): Promise<string | null> {
      try {
        const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
        return versionFromContentDisposition(head.ContentDisposition);
      } catch (error) {
        if (isNotFound(error)) {
          return null;
        }
        throw error;
      }
    },

    async agentBuild(key: string): Promise<{ version: string; sha256: string } | null> {
      let metadata: Record<string, string> | undefined;
      try {
        const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
        metadata = head.Metadata;
      } catch (error) {
        if (isNotFound(error)) {
          return null;
        }
        throw error;
      }
      const version = metadata?.version;
      const sha256 = metadata?.sha256;
      if (typeof version !== 'string' || !AGENT_BUILD_VERSION.test(version)) {
        return null;
      }
      if (typeof sha256 !== 'string' || !AGENT_BUILD_SHA256.test(sha256)) {
        return null;
      }
      return { version, sha256 };
    },
  };
}
