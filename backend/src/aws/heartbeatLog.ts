/**
 * The CloudWatch Logs-backed heartbeat store the heartbeat routes write to and
 * read from.
 *
 * Wraps an SDK-shaped CloudWatch Logs client (`send(command)` taking an AWS
 * SDK v3 Command), the same factory-plus-adapter shape bootstrap uses for S3:
 * the client is built by the injected `createLogsClient` factory, never here.
 * Each device has its own log stream, named by its device id (device ids are
 * `DEVICE_ID_PREFIX` + hex, so they are valid stream names).
 *
 *   write(deviceId, event) -> PutLogEvents; on a missing stream, CreateLogStream
 *                             (a concurrent create is ignored) and one retried put
 *   read(deviceId, limit)  -> GetLogEvents from the tail; parsed messages newest
 *                             first, `[]` when the stream does not exist yet
 */
import {
  CreateLogStreamCommand,
  GetLogEventsCommand,
  PutLogEventsCommand,
  type CloudWatchLogsClient,
} from '@aws-sdk/client-cloudwatch-logs';
import type { HeartbeatEvent, HeartbeatLog } from '../routes/heartbeat.js';

export interface CloudWatchHeartbeatLogOptions {
  /** The SDK-shaped CloudWatch Logs client. */
  client: Pick<CloudWatchLogsClient, 'send'>;
  /** The heartbeat log group's name (`HEARTBEAT_LOG_GROUP`). */
  logGroupName: string;
}

/** True when a thrown value carries the given AWS error name. */
function isNamed(error: unknown, name: string): boolean {
  return typeof error === 'object' && error !== null && (error as { name?: unknown }).name === name;
}

/** The message as a JSON object, or `undefined` when it is not JSON object text. */
function parseMessage(message: unknown): Record<string, unknown> | undefined {
  if (typeof message !== 'string') {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(message);
  } catch {
    return undefined;
  }
  return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : undefined;
}

export function createCloudWatchHeartbeatLog({ client, logGroupName }: CloudWatchHeartbeatLogOptions): HeartbeatLog {
  return {
    async write(deviceId: string, event: HeartbeatEvent): Promise<void> {
      const put = (): PutLogEventsCommand =>
        new PutLogEventsCommand({
          logGroupName,
          logStreamName: deviceId,
          logEvents: [{ timestamp: Date.parse(event.receivedAt), message: JSON.stringify(event) }],
        });
      try {
        await client.send(put());
        return;
      } catch (error) {
        if (!isNamed(error, 'ResourceNotFoundException')) {
          throw error;
        }
      }
      // The device's first heartbeat: create its stream, then put once more.
      try {
        await client.send(new CreateLogStreamCommand({ logGroupName, logStreamName: deviceId }));
      } catch (error) {
        if (!isNamed(error, 'ResourceAlreadyExistsException')) {
          throw error;
        }
      }
      await client.send(put());
    },

    async read(deviceId: string, limit: number): Promise<Record<string, unknown>[]> {
      let output: { events?: { timestamp?: number; message?: string }[] };
      try {
        output = (await client.send(
          new GetLogEventsCommand({ logGroupName, logStreamName: deviceId, limit, startFromHead: false }),
        )) as { events?: { timestamp?: number; message?: string }[] };
      } catch (error) {
        if (isNamed(error, 'ResourceNotFoundException')) {
          return [];
        }
        throw error;
      }
      const events = Array.isArray(output?.events) ? [...output.events] : [];
      events.sort((a, b) => (b.timestamp ?? 0) - (a.timestamp ?? 0));
      const items: Record<string, unknown>[] = [];
      for (const event of events) {
        const parsed = parseMessage(event.message);
        if (parsed !== undefined) {
          items.push(parsed);
        }
      }
      return items;
    },
  };
}
