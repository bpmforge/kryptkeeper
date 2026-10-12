# Writing a delivery plugin

A delivery plugin installs renewed certificates on a device Kryptkeeper
has no built-in support for. The design and the rules it runs under are in
[`docs/design/DELIVERY_PLUGINS.md`](../design/DELIVERY_PLUGINS.md).

## 1. Start from the example

Copy [`plugins/example`](../../plugins/example). It is a complete plugin for
a simple HTTPS device API: `main.go`, `manifest.json` and `go.mod`.

## 2. Implement three operations

```go
func init() { delivery.Register(myDevice{}) }

func (myDevice) Validate(h *delivery.Host, req abi.ValidateRequest) error
func (myDevice) Push(h *delivery.Host, req abi.PushRequest) (abi.PushResult, error)
func (myDevice) Rollback(h *delivery.Host, req abi.RollbackRequest) (abi.RollbackResult, error)
```

### Validate

Checks reachability and permissions without changing anything.

### Push

Uploads and binds the certificate.
- **Outcome:** report one of the outcomes in `abi` (`installed`,
  `write_failed`, `binding_failed`, ...).
- **RollbackHandle:** return what Rollback needs to restore the previous
  state, for example the previous certificate's name.
- **Verified:** you cannot set it. The hub checks what the device serves.

### Rollback

Restores the state that the RollbackHandle describes. Set `RolledBack`
only if the device really is back. The operator is told exactly what you
report.

## 3. Reach the device through the Host only

| Call | Needs |
|---|---|
| `h.HTTP` | `network` in the manifest. HTTPS only, to the credential's host or listed hosts. |
| `h.Run`, `h.WriteFile`, `h.ReadFile`, `h.Exists` | `remote_exec`, plus `file_write` paths. Escalation also needs `elevated_exec` (see below). |
| `h.Logf` | Nothing. Lines are capped, PEM blocks are withheld, and credential secrets are redacted. |

Without `elevated_exec`, `h.Run` refuses (a) privilege-escalation programs
by basename, however the path is spelled: `sudo`, `doas`, `su`, `pkexec`,
`runuser`, `setpriv`, `chroot`, `nsenter`; (b) shells and interpreters given an
inline command (`sh -c`, `bash -lc`, `python3 -c`, `perl -e`, `ruby -e`,
`node -e`, `cmd /c`, `powershell -Command`); and (c) wrappers that launch
either (`env sudo ...`, `busybox sh -c ...`, `nohup`, `timeout`, `xargs`, ...).
Exec a concrete program with an argv (`nginx -t`, `systemctl reload nginx`), or
declare `elevated_exec` so the operator approves it.

The plugin has no filesystem, environment or sockets of its own. Anything
the manifest does not declare is refused, and the operator sees every
capability before approving the plugin.

## 4. Build and test

```bash
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm .
```

Then grade the plugin with the conformance kit:

1. Write a mock of your device that implements `conformance.Device`.
2. Run `conformance.Suite` against it. See
   `tests/plugins/conformance/exampledevice_test.go`.

The suite checks verified delivery, rollback on a verify mismatch, honest
reporting of a failed rollback, and that upload and bind failures leave the
device unchanged.

## 5. Publish

Set `artifact.sha256` in `manifest.json` to the SHA-256 of the built
`plugin.wasm`. The hub refuses a module that does not match.
