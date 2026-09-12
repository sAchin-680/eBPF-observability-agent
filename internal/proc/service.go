package proc

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// genericExecutables are programs whose name identifies a runtime rather than a
// service. Three Python services all report "python3", so the executable name
// alone cannot distinguish them.
var genericExecutables = map[string]bool{
	"python": true, "python2": true, "python3": true,
	"node": true, "nodejs": true, "deno": true, "bun": true,
	"java": true, "ruby": true, "php": true, "perl": true,
	"dotnet": true, "mono": true,
	"sh": true, "bash": true, "dash": true, "zsh": true,
	"uwsgi": true, "gunicorn": true, "uvicorn": true,
}

// genericScriptNames are entry-point filenames chosen by convention rather than
// to describe the service. A directory full of services will contain many files
// called main or app, so these names carry no information on their own.
var genericScriptNames = map[string]bool{
	"main": true, "app": true, "server": true, "index": true,
	"application": true, "run": true, "start": true, "wsgi": true,
	"asgi": true, "manage": true, "__main__": true,
}

// ServiceName infers a name for the service a process implements.
//
// Nothing in the kernel records what a service is called, and the agent is
// deliberately not told. The name must therefore be derived from what the
// process is, and every available signal is imperfect:
//
//	executable name    identifies the runtime for interpreted languages
//	script name        often a convention like main.py or server.js
//	command line       may contain an entire argument list
//	listening port     stable but meaningless to a person
//
// The strategy is to take the most specific signal that is not generic, and to
// fall back rather than guess. Within a container or a Kubernetes pod the
// authoritative answer comes from labels instead, which supersedes this.
//
// The result is the identity every dashboard groups by, so a wrong answer here
// makes the telemetry unusable no matter how accurate the measurements are.
func ServiceName(pid int) string {
	if name := fromExecutable(pid); name != "" {
		return name
	}
	if name := fromCommandLine(pid); name != "" {
		return name
	}
	if comm := readComm(pid); comm != "" {
		return comm
	}
	return "unknown"
}

// fromExecutable uses the executable's own name, unless it names a runtime.
func fromExecutable(pid int) string {
	target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	// A replaced or unlinked binary keeps its path with this suffix appended.
	base := filepath.Base(strings.TrimSuffix(target, " (deleted)"))
	if base == "" || genericExecutables[stripVersion(base)] {
		return ""
	}
	return base
}

// fromCommandLine derives a name from the entry point an interpreter was given.
//
// When the entry point is itself a conventional name, the directory containing
// it is used instead: a service in samples/python-flask/app.py is far better
// described by its directory than by "app".
func fromCommandLine(pid int) string {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return ""
	}

	// Arguments are NUL-separated, with a trailing NUL.
	args := strings.Split(string(bytes.TrimRight(raw, "\x00")), "\x00")

	for _, arg := range args[1:] {
		// Skip flags and their obvious values; the entry point is a path.
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		if !looksLikeScript(arg) {
			continue
		}

		name := strings.TrimSuffix(filepath.Base(arg), filepath.Ext(arg))
		if !genericScriptNames[name] {
			return name
		}
		if dir := filepath.Base(filepath.Dir(absPath(pid, arg))); dir != "" && dir != "." && dir != "/" {
			return dir
		}
		return name
	}
	return ""
}

// looksLikeScript reports whether an argument is plausibly an entry point
// rather than a flag value or a bare module name.
func looksLikeScript(arg string) bool {
	switch filepath.Ext(arg) {
	case ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".php", ".pl", ".jar":
		return true
	}
	return strings.ContainsRune(arg, '/')
}

// absPath resolves a relative entry point against the process's own working
// directory, since a service is usually started from its own directory and its
// command line therefore carries a bare filename.
func absPath(pid int, arg string) string {
	if filepath.IsAbs(arg) {
		return arg
	}
	cwd, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "cwd"))
	if err != nil {
		return arg
	}
	return filepath.Join(cwd, arg)
}

func readComm(pid int) string {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// stripVersion reduces names like python3.12 to python3, so that a versioned
// interpreter is still recognised as an interpreter.
func stripVersion(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		return name[:i]
	}
	return name
}
