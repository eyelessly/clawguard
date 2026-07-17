package version

import "fmt"

// Set via -ldflags at build time.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
	Edition   = "oss"
)

// String returns a single-line identity for logs.
func String() string {
	return fmt.Sprintf("version=%s commit=%s edition=%s build_time=%s", Version, Commit, Edition, BuildTime)
}

// Info is a JSON-friendly snapshot.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	Edition   string `json:"edition"`
}

func Snapshot() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildTime: BuildTime,
		Edition:   Edition,
	}
}
