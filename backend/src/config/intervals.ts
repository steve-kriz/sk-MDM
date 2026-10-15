/**
 * Timing constants shared by the backend, the agent and the installers.
 *
 * The check-in interval is published to the agent in the enroll response
 * (`EnrollResponse.checkInIntervalSeconds`), so it is written once here and
 * imported everywhere else: a route that wants the default must never spell
 * the number out again.
 */

/** Seconds an agent waits between check-ins unless told otherwise. */
export const DEFAULT_CHECKIN_INTERVAL_SECONDS = 900;

/** The heartbeat frequencies an admin may pick, in seconds: 1, 5, 15, 30 and 60 minutes. */
export const HEARTBEAT_INTERVAL_OPTIONS_SECONDS: readonly number[] = [60, 300, 900, 1800, 3600];

/** The heartbeat frequency preselected when none is stored, in seconds. */
export const HEARTBEAT_DEFAULT_INTERVAL_SECONDS = 300;
