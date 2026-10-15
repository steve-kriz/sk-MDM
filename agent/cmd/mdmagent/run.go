package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/agentactions"
	"github.com/officehq/sk-mdm/agent/internal/agenterrors"
	"github.com/officehq/sk-mdm/agent/internal/analytics"
	"github.com/officehq/sk-mdm/agent/internal/antivirus"
	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/enforce"
	"github.com/officehq/sk-mdm/agent/internal/executor"
	"github.com/officehq/sk-mdm/agent/internal/heartbeat"
	"github.com/officehq/sk-mdm/agent/internal/inventory"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/policy"
	"github.com/officehq/sk-mdm/agent/internal/posture"
	"github.com/officehq/sk-mdm/agent/internal/scheduler"
	"github.com/officehq/sk-mdm/agent/internal/service"
	"github.com/officehq/sk-mdm/agent/internal/signin"
	"github.com/officehq/sk-mdm/agent/internal/state"
	"github.com/officehq/sk-mdm/agent/internal/update"
	"github.com/officehq/sk-mdm/agent/internal/version"
)

// requestTimeout covers a whole exchange with the collection endpoint, so a
// stalled check-in cannot wedge the agent.
const requestTimeout = 60 * time.Second

// The host the agent is assembled from, as variables rather than calls, so a
// test exercises `mdmagent run` and the verbs that follow it with the fakes in
// agent/internal/platform/fake and without a console, a network or a signal.
var (
	// newRunner is what every external command is run through.
	newRunner = func() platform.CommandRunner { return platform.ExecRunner{} }

	// newClock is what every interval is timed on.
	newClock = func() platform.Clock { return platform.SystemClock{} }

	// newDoer is what every request is sent through.
	newDoer = func() platform.HTTPDoer { return platform.NewHTTPClient(requestTimeout) }

	// hostName is the machine name sent at enrollment.
	hostName = os.Hostname

	// executablePath is this binary, which is what the service managers are
	// pointed at when no path is given.
	executablePath = os.Executable

	// managed reports whether the Windows service control manager started
	// this process.
	managed = service.Managed

	// dispatch hosts the agent under the Windows service control manager.
	dispatch = service.Dispatch

	// signalContext returns a context cancelled by a SIGINT, a CTRL_BREAK or
	// a SIGTERM: the three ways a foreground agent is asked to stop.
	signalContext = func(parent context.Context) (context.Context, context.CancelFunc) {
		return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	}
)

// agentLogPath is the agent's own log file, inside the directory the
// collect_logs command archives, so support asking for the logs gets this.
func agentLogPath(goos string) string {
	if goos == "windows" {
		return executor.WindowsLogDir + `\agent.log`
	}
	return executor.DarwinLogDir + "/agent.log"
}

// agentEnv is everything the agent is assembled from. Every field is an
// interface or a path, so newAgent is the production wiring and is still run in
// a test with no disk, no network and no probes.
type agentEnv struct {
	// FS is the config, the state, the spool, the command store and the log.
	FS platform.FileSystem

	// Runner runs the inventory and posture probes and the leased commands.
	Runner platform.CommandRunner

	// Clock stamps every record and times every interval.
	Clock platform.Clock

	// Doer sends every request to the collection endpoint.
	Doer platform.HTTPDoer

	// GOOS selects the probe set and every default path.
	GOOS string

	// ConfigPath and StatePath are the two files the installer creates.
	ConfigPath string
	StatePath  string

	// Hostname is the machine name sent at enrollment.
	Hostname string

	// BinaryPath is this executable: the file a self-update replaces. Empty
	// means the agent cannot update itself, and an advertised release is
	// left alone.
	BinaryPath string
}

// agent is the assembled agent: the dependencies one check-in cycle runs from,
// the logger the service hooks report through, and the self-update the process
// settles before the loop starts.
type agent struct {
	deps    *scheduler.Deps
	logger  *logging.Logger
	clock   platform.Clock
	updates *update.Deps
	// signin is the brokered sign-in the service runs alongside the loop.
	signin *signin.Broker
	// heartbeat is the per-device performance heartbeat loop run alongside
	// the scheduler; nil runs no heartbeat.
	heartbeat *heartbeat.Deps
	// fs and goos locate the leftovers of earlier versions removed at start.
	fs   platform.FileSystem
	goos string
	// restartPending is set by settleUpdate when a rollback put the old
	// binary back: Start then returns service.ErrRestartRequired without
	// running anything, so the service manager restarts the agent onto it.
	restartPending bool
	// actions is the buffer of agent actions carried on the next check-in;
	// settleUpdate records a rollback an earlier process performed into it.
	actions *agentactions.Buffer
}

// newAgent assembles the production agent: the config and the state the
// installer left, the log, the signed transport, the collectors, the policy
// evaluator and the command executor, wired into the scheduler dependencies the
// loop runs from.
//
// This is the one place the agent's pieces are put together. Everything it
// builds is reachable from the returned value, so the run verb starts a loop
// rather than knowing how one is made.
func newAgent(env agentEnv) (*agent, error) {
	cfg, err := config.Load(env.FS, env.ConfigPath)
	if err != nil {
		return nil, err
	}

	store := state.NewStore(env.FS, env.StatePath)
	logger := logging.New(env.FS, env.Clock, agentLogPath(env.GOOS),
		logging.ParseLevel(cfg.LogLevel), "agent")
	// Every warn and error record, from this logger and every one made from
	// it, is buffered for the next check-in. Attached before any With call.
	agentErrors := agenterrors.New()
	logger.SetSink(agentErrors)
	// The actions the agent performs on the device (TASK-070) are buffered
	// for the next check-in, the same way.
	agentActions := agentactions.New(env.Clock)

	transport := client.New(cfg, store, env.Doer, env.Clock)
	transport.Logger = logger.With("client")
	transport.Host = client.HostFacts{
		Hostname:     env.Hostname,
		Platform:     client.PlatformName(env.GOOS),
		AgentVersion: version.Version,
	}

	// The enrollment token is read from the config file at every enrollment,
	// because the sign-in writes it there while the agent runs, and a
	// rejected one is removed from there.
	transport.EnrollmentToken = func() string {
		token, err := config.ReadEnrollmentToken(env.FS, env.ConfigPath)
		if err != nil {
			return ""
		}
		return token
	}

	// The brokered browser sign-in mints that token and wakes the loop, so
	// an enrollment waiting for a user happens straight away.
	signInWake := make(chan struct{}, 1)
	signInBroker := newSignInBroker(cfg, env.GOOS, env.ConfigPath, transport, store, env.FS, env.Doer, env.Clock,
		logger.With("signin"), signInWake)

	// Who is logged in to the operating system is reported after every
	// check-in.
	users := &userReporter{
		transport: transport,
		runner:    env.Runner,
		goos:      env.GOOS,
		logger:    logger.With("usersession"),
	}

	commands := &executor.Deps{
		Runner: env.Runner,
		FS:     env.FS,
		Clock:  env.Clock,
		Logger: logger.With("executor"),
		GOOS:   env.GOOS,
		Client: transport,
		Store:  executor.NewStore(env.FS, executor.StorePath(env.GOOS)),
		// Application installers (TASK-049) are fetched with a plain GET from
		// a presigned or registered URL, on their own long-timeout client; the
		// signed requests keep env.Doer and its short timeout.
		Downloader: platform.NewHTTPClient(executor.ApplicationDownloadTimeout),
	}

	// The self-update: how a replaced binary is installed, and the restart
	// that makes it the one running. It is wired only when this executable's
	// path is known, because an update with nothing to replace is one that
	// would leave the agent in two minds about which binary is current.
	var updates *update.Deps
	if env.BinaryPath != "" {
		updates = &update.Deps{
			FS:     env.FS,
			Doer:   env.Doer,
			Logger: logger.With("update"),
			Path:   env.BinaryPath,
			Clock:  env.Clock,
			Restart: func(ctx context.Context) error {
				return service.Restart(ctx, service.Config{
					FS:         env.FS,
					Runner:     env.Runner,
					GOOS:       env.GOOS,
					BinaryPath: env.BinaryPath,
				})
			},
		}
	}

	// One scanner per agent: its in-flight guard and last record must
	// survive from one cycle to the next, so it is not rebuilt in Enforce.
	scanner := antivirus.NewScanner(env.Runner, env.Clock, env.FS, env.GOOS,
		logger.With("enforce"), antivirus.ScanStatePath(env.GOOS))
	// One Defender hardener per agent, for the same reason: its last block and
	// signature update retry window live across cycles.
	hardener := antivirus.NewHardener(env.Runner, env.Clock, env.GOOS)

	deps := &scheduler.Deps{
		Client:          transport,
		Store:           store,
		FS:              env.FS,
		Clock:           env.Clock,
		Runner:          env.Runner,
		Logger:          logger.With("scheduler"),
		GOOS:            env.GOOS,
		IntervalSeconds: cfg.CheckInIntervalSeconds,
		CollectInventory: func() (contract.Inventory, error) {
			inv, err := inventory.Collect(env.Runner, env.Clock, env.GOOS)
			if err == nil {
				// An enrollment that follows a rejected credential
				// describes the machine from what the last collection
				// saw, rather than with an empty description.
				transport.Host.OSVersion = inv.OS.Version
				transport.Host.HardwareUUID = inv.Hardware.SerialNumber
			}
			return inv, err
		},
		// The first enrollment comes before the first collection, so the
		// machine is described here first; once known it is not re-collected.
		BeforeEnroll: func() {
			if transport.Host.OSVersion != "" && transport.Host.HardwareUUID != "" {
				return
			}
			inv, err := inventory.Collect(env.Runner, env.Clock, env.GOOS)
			if err != nil {
				logger.With("scheduler").Warn("could not describe the device before enrolling",
					logging.F("error", err.Error()))
				return
			}
			transport.Host.OSVersion = inv.OS.Version
			transport.Host.HardwareUUID = inv.Hardware.SerialNumber
		},
		CollectPosture: func() (contract.Posture, error) {
			return posture.Collect(env.Runner, env.Clock, env.GOOS)
		},
		// Endpoint analytics report crashes from the watermark onwards; the
		// watermark has its own file, so clearing the credential keeps it.
		CollectAnalytics: func(since time.Time) (contract.Analytics, time.Time, error) {
			return analytics.Collect(env.Runner, env.Clock, env.GOOS, since)
		},
		AnalyticsWatermark: analytics.NewWatermarkStore(env.FS, analytics.WatermarkPath(env.GOOS)),
		// The last scheduled scan's result rides on every check-in.
		CollectAntivirusScan: scanner.Last,
		// The hardener's block from this cycle's Enforce rides on the same
		// check-in, and its failures become policy violations.
		CollectDefenderHardening: hardener.Last,
		// The agent's own warn and error records ride on the next check-in.
		CollectAgentErrors: agentErrors.Collect,
		// The actions the agent performed ride on the same check-in.
		CollectAgentActions: agentActions.Collect,
		Evaluate:            policy.Evaluate,
		// The settings the bundle asks for are made true on the machine
		// after they have been evaluated, so this cycle reports the posture
		// as found and the next one reports the result.
		Enforce: func(ctx context.Context, effective map[string]any, pst contract.Posture) {
			enforceLogger := logger.With("enforce")
			// The antivirus enforcer needs the clock, which Defaults does not
			// take, so it follows the default list rather than joining it.
			// The Defender hardener follows it. The scanner comes last and
			// only ever starts a background scan.
			// The firewall, domains and antivirus enforcers record what they
			// turned on into the action buffer.
			antivirusEnforcer := antivirus.NewEnforcer(env.Runner, env.Clock, env.GOOS)
			antivirusEnforcer.Actions = agentActions.Record
			enforcers := append(enforce.DefaultsWithActions(env.Runner, env.FS, env.GOOS, enforceLogger, agentActions.Record),
				antivirusEnforcer,
				hardener,
				scanner)
			enforce.Run(ctx, enforcers, effective, pst, enforceLogger)
		},
	}

	// Commands are leased at the end of each cycle, once the check-in has
	// been accepted: the device id a lease is addressed to is the one
	// enrollment has just confirmed, and a result that could not be
	// delivered last cycle is retried here before anything new is run.
	deps.AfterCheckIn = func(ctx context.Context, _ contract.CheckInResponse) error {
		st, err := store.Load()
		if err != nil {
			return err
		}
		// The console user is reported first; whatever comes of it, the
		// command poll still runs this cycle.
		users.report(ctx, st.DeviceID)
		commands.DeviceID = st.DeviceID
		return executor.Poll(ctx, commands)
	}

	if updates != nil {
		deps.ApplyUpdate = func(ctx context.Context, rel contract.AgentRelease) error {
			return update.Apply(ctx, rel, updates)
		}
	}

	// The per-device heartbeat (TASK-044): its own loop on the same transport,
	// store and clock, told the interval by every decoded check-in response.
	beat := &heartbeat.Deps{
		Client: transport,
		Store:  store,
		Clock:  env.Clock,
		Logger: logger.With("heartbeat"),
		Collect: func() (contract.AnalyticsPerformance, []string) {
			return analytics.CollectPerformance(env.Runner, env.Clock, env.GOOS)
		},
		CollectNetwork: func() ([]contract.HeartbeatNetworkAdapter, []string) {
			return analytics.CollectNetwork(env.Runner, env.Clock, env.GOOS)
		},
	}
	deps.OnHeartbeatInterval = beat.SetInterval

	deps.SignInWake = signInWake
	// A rejected enrollment token is removed from the config, so the
	// sign-in asks for a new one.
	deps.ClearEnrollmentToken = func() error {
		return config.ClearEnrollmentToken(env.FS, env.ConfigPath)
	}

	return &agent{deps: deps, logger: logger, clock: env.Clock, updates: updates, signin: signInBroker,
		heartbeat: beat, fs: env.FS, goos: env.GOOS, actions: agentActions}, nil
}

// settleUpdate finishes whatever the previous process started: an update that
// is running is confirmed and its leftovers cleared, and one that is not is
// rolled back onto the binary it replaced.
//
// It runs once, before the scheduler, because the question it answers is "is
// the build that just started the build that was installed" and nothing else
// may happen until it is settled.
func (a *agent) settleUpdate() {
	if a.updates == nil {
		return
	}
	err := update.RollbackIfUnhealthy(a.updates)
	switch {
	case err == nil:
	case errors.Is(err, service.ErrRestartRequired):
		// The old binary is back in place; the process must exit so the
		// service manager starts it. Not a failure.
		a.restartPending = true
	default:
		a.log("update could not be settled: " + err.Error())
	}

	// A rollback an earlier process performed is reported by this one. The
	// process that has just rolled back leaves its record for the next one.
	if a.restartPending {
		return
	}
	rec, ok := update.TakeRollbackRecord(a.updates)
	if !ok || a.actions == nil {
		return
	}
	a.actions.RecordAt(contract.ActionAgentUpdateRolledBack, map[string]string{
		"installedVersion": rec.InstalledVersion,
		"runningVersion":   rec.RunningVersion,
	}, rec.OccurredAt)
}

// hooks is the agent as the service state machine drives it: the scheduler loop
// to start, and the two ways it is asked to stop.
func (a *agent) hooks() service.Hooks {
	return service.Hooks{
		Start: func(ctx context.Context) error {
			if a.logger != nil {
				// The version says which build is running, so a stale
				// reinstall or an auto-update shows in the log.
				_ = a.logger.Log(logging.LevelInfo, "agent started", logging.F("version", version.Version))
			}
			if a.restartPending {
				// A rollback restored the previous build: nothing runs
				// on this one, the service manager restarts onto it.
				return service.ErrRestartRequired
			}
			if a.fs != nil {
				// Earlier versions kept the user's Entra tokens; none
				// is kept any more.
				removeLegacyVault(a.fs, a.goos, a.logger)
			}
			if a.signin != nil {
				// The sign-in polls for as long as the loop runs, and
				// does nothing once the device is enrolled.
				go a.signin.Run(ctx)
			}
			if a.heartbeat != nil {
				// The heartbeat idles until a check-in turns it on.
				go func() { _ = heartbeat.Run(ctx, a.heartbeat) }()
			}
			return scheduler.Run(ctx, a.deps)
		},
		Stop: func() {
			a.log("stop requested, finishing the in-flight check-in")
		},
		Shutdown: func() {
			a.log("system shutting down, finishing the in-flight check-in")
		},
		Report: func(state service.State) {
			a.log("service " + state.String())
		},
		Clock: a.clock,
	}
}

// log records one line. A log that cannot be written is dropped: the agent has
// nowhere better to report it, and a full disk must not stop a check-in.
func (a *agent) log(msg string) {
	if a.logger != nil {
		_ = a.logger.Log(logging.LevelInfo, msg)
	}
}

// runAgent is `mdmagent run`: the scheduler loop, in the foreground.
//
// It is the same verb the Windows service is registered with and the macOS
// LaunchDaemon starts. Under the Windows service control manager the loop is
// driven by the control manager's own requests; anywhere else it runs until a
// SIGINT, a CTRL_BREAK or a SIGTERM asks it to stop, and exits 0 once the
// in-flight cycle has been let go of.
func runAgent(fsys platform.FileSystem, goos string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mdmagent run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", config.Path(goos), "path to the agent config file")
	statePath := flags.String("state", state.StatePath(goos), "path to the agent state file")
	if err := flags.Parse(args); err != nil {
		return exitError
	}

	name, err := hostName()
	if err != nil {
		// A machine that will not say its name is still managed; the
		// backend is told what the inventory finds instead.
		name = ""
	}

	// A host that will not say where this executable is is still manageable;
	// it just cannot replace itself.
	binary, err := executablePath()
	if err != nil {
		binary = ""
	}

	runner := newRunner()
	agent, err := newAgent(agentEnv{
		FS:         fsys,
		Runner:     runner,
		Clock:      newClock(),
		Doer:       newDoer(),
		GOOS:       goos,
		ConfigPath: *configPath,
		StatePath:  *statePath,
		Hostname:   name,
		BinaryPath: binary,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		if errors.Is(err, config.ErrCollectionURL) {
			return exitInvalidURL
		}
		return exitError
	}

	// Settle the previous process's update before anything else runs, so the
	// loop that starts is the one this build was meant to be.
	agent.settleUpdate()

	hooks := agent.hooks()

	if managed() {
		if goos == "windows" {
			// Re-applied at every managed start, so a service registered
			// by an older installer gets the recovery actions that
			// restart it after an update. A failure costs one warning.
			if err := service.EnsureRecovery(context.Background(), service.Config{
				Runner: runner,
				GOOS:   goos,
			}); err != nil && agent.logger != nil {
				_ = agent.logger.Log(logging.LevelWarn, "service recovery could not be configured",
					logging.F("error", err.Error()))
			}
		}
		if err := dispatch(context.Background(), hooks); err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		return exitOK
	}

	ctx, stop := signalContext(context.Background())
	defer stop()

	fmt.Fprintf(stdout, "mdmagent %s running\n", version.Version)
	if err := service.Run(ctx, hooks); err != nil {
		if errors.Is(err, service.ErrRestartRequired) {
			// Under launchd, KeepAlive restarts the job; in a console
			// nothing does, and the operator is told why it ended.
			fmt.Fprintln(stdout, "mdmagent restarting to apply an update")
			return exitRestart
		}
		fmt.Fprintln(stderr, err)
		return exitError
	}

	fmt.Fprintln(stdout, "mdmagent stopped")
	return exitOK
}
