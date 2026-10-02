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
