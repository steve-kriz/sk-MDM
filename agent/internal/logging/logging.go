// Package logging writes the agent's log: one JSON object per line, dropped
// below the configured level, rotated once the file passes 5 MB.
//
// One line per record and one file of bounded size is the whole design: the
// agent runs unattended on a user's machine, so the log must be greppable by
// support, parseable by a tool, and incapable of filling a disk.
package logging

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// FileSystem and Clock are the platform interfaces, aliased for readable
// signatures.
type (
	FileSystem = platform.FileSystem
	Clock      = platform.Clock
)

// Level is the severity of a record.
type Level int

// The levels, in increasing severity. A record below the logger's level is
// dropped before anything is written.
const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// MaxFileBytes is the size the log file may reach before it is rotated.
const MaxFileBytes int64 = 5 << 20 // 5 MB

// FileMode is the mode the log file is created with.
const FileMode = 0o600

// timeFormat is ISO-8601 UTC with milliseconds, e.g.
// "2026-10-02T07:15:00.000Z", matching the timestamps on the wire contract.
const timeFormat = "2006-01-02T15:04:05.000Z07:00"

// reserved keys cannot be overwritten by a caller's field.
var reserved = map[string]bool{"ts": true, "level": true, "msg": true, "component": true}

// String is the value written in the "level" key.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}

// ParseLevel turns a config file logLevel into a Level. An unrecognised or
// empty value is "info": a typo in the config must not silence the agent.
func ParseLevel(name string) Level {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// Field is one extra key on a record, beyond the four every record carries.
type Field struct {
	Key   string
	Value any
}

// F builds a Field.
func F(key string, value any) Field { return Field{Key: key, Value: value} }

// Sink receives every record a logger writes at LevelWarn or above: its
// level, component, message, fields (in call order, without empty, reserved or
// repeated keys, exactly as they appear on the line) and the timestamp the
// line carries. It is called whether or not the line could be appended to the
// file, and may be called from several goroutines at once.
type Sink interface {
	Record(level Level, component, msg string, fields []Field, at time.Time)
}

// sinkHolder is shared by a logger and every logger made from it by With, so
// a sink attached to any of them reaches all of them.
type sinkHolder struct {
	mu   sync.RWMutex
	sink Sink
}

func (h *sinkHolder) get() Sink {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sink
}

// Logger writes records to one file.
//
// Loggers made by With share the file, the level, the lock and the sink with
// their parent; only the component differs, so two components cannot
// interleave a half-written line.
type Logger struct {
	fsys      FileSystem
	clock     Clock
	path      string
	level     Level
	component string
	maxBytes  int64
	mu        *sync.Mutex
	sinks     *sinkHolder
}

// New returns a logger writing to path at level, tagging records with
// component. Nothing is opened or created until the first record is written.
func New(fsys FileSystem, clock Clock, path string, level Level, component string) *Logger {
	return &Logger{
		fsys:      fsys,
		clock:     clock,
		path:      path,
		level:     level,
		component: component,
		maxBytes:  MaxFileBytes,
		mu:        &sync.Mutex{},
		sinks:     &sinkHolder{},
	}
}

// SetSink attaches sink to this logger and to every logger that shares its
// file through With, made before or after this call. A nil sink detaches.
func (l *Logger) SetSink(sink Sink) {
	if l.sinks == nil {
		return
	}
	l.sinks.mu.Lock()
	defer l.sinks.mu.Unlock()
	l.sinks.sink = sink
}

// With returns a logger for another component, sharing this one's file.
func (l *Logger) With(component string) *Logger {
	child := *l
	child.component = component
	return &child
}

// Level is the lowest level this logger writes.
func (l *Logger) Level() Level { return l.level }

// Path is the file this logger writes to.
func (l *Logger) Path() string { return l.path }

// Debug writes a debug record.
func (l *Logger) Debug(msg string, fields ...Field) error {
	return l.Log(LevelDebug, msg, fields...)
}

// Info writes an info record.
func (l *Logger) Info(msg string, fields ...Field) error {
	return l.Log(LevelInfo, msg, fields...)
}

// Warn writes a warn record.
func (l *Logger) Warn(msg string, fields ...Field) error {
	return l.Log(LevelWarn, msg, fields...)
}

// Error writes an error record.
func (l *Logger) Error(msg string, fields ...Field) error {
	return l.Log(LevelError, msg, fields...)
}

// Log writes one record, or nothing at all when level is below the logger's
// level. The returned error is the write failure, if any; callers that have
// nowhere better to report it may ignore it.
func (l *Logger) Log(level Level, msg string, fields ...Field) error {
	if level < l.level {
		return nil
	}

	now := l.clock.Now().UTC()
	line, err := l.encode(now, level, msg, fields)
	if err != nil {
		return err
	}
	writeErr := l.write(line)

	// The sink sees the record even when the file append failed: a device
	// whose log cannot be written is exactly one an admin needs to hear from.
	if level >= LevelWarn && l.sinks != nil {
		if sink := l.sinks.get(); sink != nil {
			sink.Record(level, l.component, msg, written(fields), now)
		}
	}
	return writeErr
}

// written is the fields as encode puts them on the line: empty, reserved and
// repeated keys left out, call order kept.
func written(fields []Field) []Field {
	out := make([]Field, 0, len(fields))
	seen := map[string]bool{}
	for _, f := range fields {
		if f.Key == "" || reserved[f.Key] || seen[f.Key] {
			continue
		}
		seen[f.Key] = true
		out = append(out, f)
	}
	return out
}

// encode renders the record as a single line of JSON, ts first so a log read
// by eye is chronological at the left margin.
func (l *Logger) encode(now time.Time, level Level, msg string, fields []Field) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')

	if err := appendField(&buf, "ts", now.Format(timeFormat)); err != nil {
		return nil, err
	}
	buf.WriteByte(',')
	if err := appendField(&buf, "level", level.String()); err != nil {
		return nil, err
	}
	buf.WriteByte(',')
	if err := appendField(&buf, "msg", msg); err != nil {
		return nil, err
	}
	buf.WriteByte(',')
	if err := appendField(&buf, "component", l.component); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	for _, f := range fields {
		if f.Key == "" || reserved[f.Key] || seen[f.Key] {
			continue
		}
		seen[f.Key] = true

		buf.WriteByte(',')
		if err := appendField(&buf, f.Key, f.Value); err != nil {
			return nil, err
		}
	}

	buf.WriteString("}\n")
	return buf.Bytes(), nil
}

func appendField(buf *bytes.Buffer, key string, value any) error {
	encodedKey, err := json.Marshal(key)
	if err != nil {
		return err
	}
	encodedValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	buf.Write(encodedKey)
	buf.WriteByte(':')
	buf.Write(encodedValue)
	return nil
}

// write appends the line, rotating first when the file has already passed the
// size limit. Rotation is a rename to "<name>.1", replacing any previous one:
// the agent keeps the live file and exactly one generation behind it.
func (l *Logger) write(line []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if info, err := l.fsys.Stat(l.path); err == nil && info.Size() > l.maxBytes {
		if err := l.fsys.Rename(l.path, l.path+".1"); err != nil {
			return err
		}
	}

	err := l.fsys.AppendFile(l.path, line, FileMode)
	if err == nil {
		return nil
	}

	// The log directory may not exist yet on a first run; create it and retry
	// once rather than losing the first records of the agent's life.
	dir := filepath.Dir(l.path)
	if dir == "" || dir == "." {
		return err
	}
	if mkErr := l.fsys.MkdirAll(dir, 0o700); mkErr != nil {
		return err
	}
	return l.fsys.AppendFile(l.path, line, FileMode)
}
