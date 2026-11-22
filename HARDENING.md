# Hardening in this fork

This fork of [bashdi/i400](https://github.com/bashdi/i400) (MIT, forked at `b9306773`) changes the driver so that it can be used for money-handling workloads against a server it does not fully trust. Everything below is pinned by tests in this repository. **No test here connects to a real IBM i, PUB400 or Db2**: the unit tests use fake hosts, `net.Pipe` and hand-built payloads, and the env-gated integration tests are skipped without credentials.

| Area | Upstream | This fork | Pinned by |
| --- | --- | --- | --- |
| DECIMAL / NUMERIC read | exact string, but zero padded to the full precision (`00078`), `-000.00`, an empty value read as `0`, a value longer than the column silently losing its high digits | canonical exact string (`78`, `0.00`), never a float; negative zero is zero; a row whose byte length, precision or scale does not match the column is an error | `exact_numeric_test.go`, `FuzzDecodeColumnValue` |
| DECFLOAT read | string | string (unchanged); fuzzed | `exact_numeric_test.go`, `FuzzDecfloatDecoders` |
| DECIMAL / NUMERIC bind | `float64` and `bool` accepted; fraction digits beyond the scale silently truncated; a non-zero value that underflows stored as 0; the bound text echoed in the error | `float64` and `bool` refused (bind a string or integer); a value that would lose a non-zero digit is an error (trailing zeros are fine); errors never contain the value | `exact_numeric_test.go`, `FuzzDecimalBindRoundTrip` |
| DECFLOAT bind | `float64` accepted | `float64` and `bool` refused. Excess significant digits are still rounded half-even, which is IEEE 754 DECFLOAT conversion, not a bug | `exact_numeric_test.go` |
| Packet length | cap 1 GiB, buffer allocated from the announced length | default cap 64 MiB, configurable with `maxPacketBytes` (1 KiB to 1 GiB); packets over 256 KiB are read in growing steps so memory follows the bytes really received | `limits_test.go`, `packet_limit_config_test.go` |
| Counts in describe, fetch and format payloads | allocated from the announced count (up to 4G columns; `rows x columns` and `rows x row size` unchecked and able to overflow) | counts are checked against a hard cap (32767 columns, 16M cells) and against the bytes actually received before any allocation; a null bitmap is only allocated when indicators exist | `limits_test.go`, all `FuzzParse*` |
| Fetch block vs. description | a block whose column count differed from the description could index out of range | refused with an error | `limits_test.go` |
| Context and deadlines | requests honour their context; `Close`, `Rollback` after the transaction's context ended, statement close and the legacy `Prepare`/`Begin`/`Exec` could block for ever on a stalled server, and a cancelled begin context cancelled the rollback | those operations are bounded by `OperationTimeout` (default 30 s); a rollback gets its own bound and is sent even when the begin context is already cancelled; the TLS handshake honours the context | `operation_timeout_test.go` |
| TLS | `Config.TLSConfig` accepted any `*tls.Config`, including `InsecureSkipVerify` | the field is gone; only `TLSRootCAs` (trusted CAs) and `TLSServerName` exist; DSN `tlsCAFile` and `tlsServerName`; TLS 1.2 is the minimum; options that look like a verification switch (`insecureSkipVerify`, `tlsInsecure`, ...) are rejected, not ignored | `tls_test.go` |
| Credentials | `Config` printed with its password; `ParseDSN` errors quoted the whole DSN; `Config.DSN` kept the password | `Config`, `Connector` and `Conn` format without the password (every verb, and `log/slog`); `ParseDSN` errors never quote the DSN; `Config.DSN` is redacted; secret-looking query options are redacted when formatted; `NewConnector(Config)` builds a connector with no DSN string at all | `credentials_test.go` |
| Static checks | `go vet` clean, `staticcheck` 59 findings | `go vet`, `staticcheck ./...` and `go test -race ./...` clean (`internal/bidi`, a line-by-line JTOpen port, has its own `staticcheck.conf` for the unwired options and Java idioms it keeps for diffability) | CI commands below |
| Integration tests | env gated, plaintext `as400://` | still env gated and skipped without credentials; the default DSN built from the environment is now TLS (`as400s://`), `I400_TEST_PLAINTEXT=1` opts out | `integration_helpers_test.go` |
| Fuzzing | none | go1.18 fuzz targets for every wire decoder, seeded from the JTOpen vectors in `testdata/` and `internal/ccsid/testdata/` plus small well-formed payloads; each case also fails if it allocates more than 64 MiB for an input of at most 1 MiB | `fuzz_test.go` |

## Commands

```sh
go vet ./...
staticcheck ./...
go test -race ./...
go test -run '^$' -fuzz FuzzParseFetchPayload -fuzztime 60s .   # any Fuzz* target
```

The fuzz targets were run for 15 to 25 seconds each when this change was made. That finds the shallow problems, not all of them; run longer in CI before relying on the result.

## Not verified here

Everything that needs a real host is still open (the owner has not approved a connection): what a CAST of a DECIMAL renders, CCSID translation on the real server, isolation levels in force, TLS against the host's real certificate, the journaling catalogue query. See the platform's task 2.6.
