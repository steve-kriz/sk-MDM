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

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/enforce"
	"github.com/officehq/sk-mdm/agent/internal/executor"
	"github.com/officehq/sk-mdm/agent/internal/inventory"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/policy"
	"github.com/officehq/sk-mdm/agent/internal/posture"
	"github.com/officehq/sk-mdm/agent/internal/scheduler"
	"github.com/officehq/sk-mdm/agent/internal/service"
	"github.com/officehq/sk-mdm/agent/internal/state"
	"github.com/officehq/sk-mdm/agent/internal/update"
	"github.com/officehq/sk-mdm/agent/internal/userauth"
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

	// Protector decrypts the user token vault. Nil means the host's
	// platform.SecretProtector.
	Protector platform.SecretProtector
}

// agent is the assembled agent: the dependencies one check-in cycle runs from,
// the logger the service hooks report through, and the self-update the process
// settles before the loop starts.
type agent struct {
	deps    *scheduler.Deps
	logger  *logging.Logger
	clock   platform.Clock
	updates *update.Deps
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

	transport := client.New(cfg, store, env.Doer, env.Clock)
	transport.Logger = logger.With("client")
	transport.Host = client.HostFacts{
		Hostname:     env.Hostname,
		Platform:     client.PlatformName(env.GOOS),
		AgentVersion: version.Version,
	}

	// The signed-in user's token rides on every signed request while one is
	// held. The vault is the one `mdmagent login` writes; it is read per call.
	protector := env.Protector
	if protector == nil {
		protector = newProtector()
	}
	userSession := userauth.NewSession(
		userauth.NewVault(env.FS, protector, userauth.VaultPath(env.GOOS)),
		env.Doer, env.Clock, logger.With("userauth"))
	transport.Bearer = userSession

	commands := &executor.Deps{
		Runner: env.Runner,
		FS:     env.FS,
		Clock:  env.Clock,
		Logger: logger.With("executor"),
		GOOS:   env.GOOS,
		Client: transport,
		Store:  executor.NewStore(env.FS, executor.StorePath(env.GOOS)),
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
		CollectPosture: func() (contract.Posture, error) {
			return posture.Collect(env.Runner, env.Clock, env.GOOS)
		},
		Evaluate: policy.Evaluate,
		// The settings the bundle asks for are made true on the machine
		// after they have been evaluated, so this cycle reports the posture
		// as found and the next one reports the result.
		Enforce: func(ctx context.Context, effective map[string]any, pst contract.Posture) {
			enforceLogger := logger.With("enforce")
			enforce.Run(ctx, enforce.Defaults(env.Runner, env.FS, env.GOOS, enforceLogger), effective, pst, enforceLogger)
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
		// The signed-in user is reported first; whatever comes of it, the
		// command poll still runs this cycle.
		reportUserSession(ctx, transport, userSession, st.DeviceID, logger.With("userauth"))
		commands.DeviceID = st.DeviceID
		return executor.Poll(ctx, commands)
	}

	if updates != nil {
		deps.ApplyUpdate = func(ctx context.Context, rel contract.AgentRelease) error {
			return update.Apply(ctx, rel, updates)
		}
	}

	return &agent{deps: deps, logger: logger, clock: env.Clock, updates: updates}, nil
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
	if err := update.RollbackIfUnhealthy(a.updates); err != nil {
		a.log("update could not be settled: " + err.Error())
	}
}

// hooks is the agent as the service state machine drives it: the scheduler loop
// to start, and the two ways it is asked to stop.
func (a *agent) hooks() service.Hooks {
	return service.Hooks{
		Start: func(ctx context.Context) error {
			a.log("agent started")
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

	agent, err := newAgent(agentEnv{
		FS:         fsys,
		Runner:     newRunner(),
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
		fmt.Fprintln(stderr, err)
		return exitError
	}

	fmt.Fprintln(stdout, "mdmagent stopped")
	return exitOK
}
