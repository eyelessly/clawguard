# ClawGuard plugin contract

Host loads executables from `plugin_dir` (`CLAWGUARD_PLUGIN_DIR`).
Config: YAML via `CLAWGUARD_CONFIG` (default `/etc/clawguard/config.yaml`).

## Reference example: file sink

**Start here:** [`cmd/clawguard-sink-file`](../cmd/clawguard-sink-file) is the canonical sink plugin.

It shows the full lifecycle:

1. `pluginsdk.MaybeVersionFlag` + `pluginsdk.Serve`
2. `Info()` / `Configure(settings)` / `Emit(*event.CaptureEvent)` / `Close()`
3. Embedding `pluginsdk.SinkOnly` so unused `Process` is a no-op
4. Reading `settings.path` from config
5. Writing records that already carry `clawguard_version` / `plugins[]` from the host

Build and drop next to other plugins:

```bash
go build -o clawguard-sink-file ./cmd/clawguard-sink-file
# place into CLAWGUARD_PLUGIN_DIR, enable in config:
```

```yaml
sinks:
  - name: file
    settings:
      path: /var/log/clawguard/plaintext.jsonl
```

Executable name must be `clawguard-sink-file` (or set `path:` on the entry).

SDK entrypoint: [`pkg/pluginsdk`](../pkg/pluginsdk). Wire protocol: [`api/plugin/v1`](../api/plugin/v1).

## Binary naming

| Kind | Name in config | Executable |
|------|----------------|------------|
| sink | `file` | `clawguard-sink-file` (example) |
| sink | `clickhouse` | `clawguard-sink-clickhouse` |
| processor | `detect` | `clawguard-processor-detect` |
| processor | `mask` | `clawguard-processor-mask` |

Override with `path:` on the entry if needed.

## RPC

Length-prefixed JSON on **stdin/stdout** (logs go to **stderr**).

Methods: `info`, `configure`, `process` (processors), `emit` (sinks), `close`.  
`api_version` must be `"1"`.

## Processor `mode`

- `async` — observational; queued; must not be required for sink correctness.
- `sync` — runs before sink fan-out.

Defaults if omitted: `detect` → async, `mask` → sync, others → sync.

## Versions

Build with ldflags on `clawguard/internal/version` (`Version`, `Commit`, `BuildTime`, `Edition`).  
Host injects `clawguard_*` + `plugins[]` into each `CaptureEvent` before sinks.

## Custom sink checklist

1. Copy [`cmd/clawguard-sink-file`](../cmd/clawguard-sink-file) as a template.
2. Change `FillInfo("yourname", "sink")` and binary name `clawguard-sink-yourname`.
3. Implement `Emit` (batching / remote IO belongs here; do not block longer than needed — host already queues).
4. Ship the binary into `plugin_dir` and add a `sinks:` entry; `SIGHUP` or restart the host.
