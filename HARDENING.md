# Hardening in this fork

This fork of [bashdi/i400](https://github.com/bashdi/i400) (MIT, forked at commit `b9306773`) changes the driver so it can be used for money-handling workloads against a server it does not fully trust. Each row below says what the code does today and names the test that pins it. **No test here connects to a real IBM i, PUB400 or Db2.** Unit tests use fake hosts, `net.Pipe`, local listeners and hand-built payloads; the upstream integration tests are env-gated, skipped without credentials, and were not run.

## What changed

| Area | Upstream | This fork | Pinned by |
| --- | --- | --- | --- |
| DECIMAL / NUMERIC read | Zero-padded text (`-00123.45`); an empty value read as `0`; a value longer than the column silently lost its high digits | Canonical exact string, never a float; negative zero is zero; a row whose length, precision or scale does not match its column is an error | `exact_numeric_test.go`, `FuzzDecodeColumnValue` |
| DECIMAL / NUMERIC bind | `float64` and `bool` accepted; extra fraction digits silently truncated; the value echoed in errors | `float64` and `bool` refused; a bind that would drop a non-zero digit is an error (trailing zeros are fine); errors never contain the value | `exact_numeric_test.go`, `FuzzDecimalBindRoundTrip` |
| DECFLOAT bind | `float64` accepted; digits beyond the precision rounded half-even; a value below the smallest exponent stored as zero; a huge exponent allocated `10^exponent` | `float64` and `bool` refused; any bind that would change the value (digits beyond the precision, underflow, overflow) is an error and exponents are range-checked before any big-number work; trailing zeros beyond the precision are accepted. Zero with any exponent is accepted | `decfloat_canonical_test.go`, `FuzzDecfloatBindNeverChangesTheValue` |
| DECFLOAT read | `0E+300` became 300 zeros; negative zero as `-0`; NaN and infinities as plain strings | Canonical text: zero is `0` whatever its exponent and sign, no leading zeros. NaN, SNaN and infinities are a typed error, `*DecfloatSpecialError` (matches `ErrDecfloatNotFinite`), never a string that could be parsed as a number; `CAST` the column to a character type in SQL to read them | `decfloat_canonical_test.go`, `FuzzDecfloatReadIsCanonical` |
| Lengths on the wire | Counts and sizes allocated as announced | Packet cap 64 MiB (`maxPacketBytes`, up to 1 GiB), read in growing steps; column and fetch-block counts checked against a hard cap and the bytes received before any allocation; a block whose column count differs from the description is an error | `limits_test.go`, `packet_limit_config_test.go`, all `FuzzParse*` |
| Parameter marker formats | Field `Length` (uint32), record size and count trusted; a null bind allocated `Length` bytes | Validated when parsed: field count at most 32767, each field at most 16 MiB, the record at most 32 MiB, otherwise an error. Binding also refuses a field whose length is negative or above 16 MiB, and an inline LOB whose declared maximum is above that, before allocating. A LOB column's declared maximum (up to 2 GiB) is not rejected at parse time because it is a property of the column; it only matters, and is only checked, when an inline value is bound. Worst case for one bind is about twice the record limit (a null and a value buffer per field) | `hostile_format_test.go`, `FuzzBindAgainstHostileField`, `FuzzParseFormatThenBind` |
| Lying lengths | A VARBINARY value or LOB data announcing more bytes than it carries was clamped | An error | `hostile_format_test.go` |
| Context and deadlines | Request paths honour the context. `Close`, rollback after the transaction's context ended, statement close and the legacy entry points could block for ever | Bounded by `OperationTimeout` (30 s). `Close` waits for an in-flight operation for that long, then closes the socket anyway, which ends it. Every read is bounded by `socketTimeout` (default 10 minutes; `socketTimeout=0` in the DSN disables it, `-1` does so for `NewConnector`). `ResolvePort` honours cancellation. The TLS handshake honours the context | `operation_timeout_test.go`, `hardening2_test.go` |
| TLS | Any `*tls.Config`, skip-verify included | Only a trusted CA pool and a server name; TLS 1.2 minimum; `insecureSkipVerify` and similar DSN options are rejected, not ignored | `tls_test.go` |
| Plaintext | `tls=false` on an `as400s://` DSN silently gave a plaintext connection with the password in clear | That is an error. Plaintext needs the `as400://` scheme, or `allowPlaintext=true` to override a TLS scheme | `hardening2_test.go` |
| Credentials | `Config` printed its password; `json.Marshal` and the slog JSON handler printed it; `Config.DSN` and query options kept secrets; `%+v`/`%#v` of a dereferenced connector or connection printed it through reflection; `ParseDSN` errors quoted the DSN | `Config` formats, marshals (JSON) and logs (slog) without the password, and with secret-looking query options redacted; `Config.DSN` keeps no password and no query string; a connector or connection keeps its password behind a pointer, so reflection prints an address; DSN errors never quote the DSN; `NewConnector(Config)` builds a connector with no DSN string | `credentials_test.go`, `credentials2_test.go` |
| Client seed | Derived from the clock | `crypto/rand` | `seed_test.go` |
| Password level | Chosen by the server | `minPasswordLevel` (0 to 4): a server announcing a lower level is refused before any password material is sent. Without it, a hostile or misconfigured host can steer the client to the DES or SHA-1 substitutes (level 0 to 2). Set 3 or 4 for a modern IBM i | `hardening2_test.go` |
| SQL literal expansion | Dead code formatted `float64` into SQL text | Deleted | `hardening2_test.go` |
| Checks | `go vet` clean, `staticcheck` 59 findings | `go vet`, `staticcheck ./...` and `go test -race ./...` clean (`internal/bidi`, a line-by-line JTOpen port, has its own `staticcheck.conf` for the unwired options and Java idioms it keeps so it stays diffable against JTOpen) | commands below |
| Integration tests | env-gated, plaintext `as400://` | still env-gated and not run; the DSN they build is TLS by default (`I400_TEST_PLAINTEXT=1` opts out) | `integration_helpers_test.go` |
| Fuzzing | none | 20 fuzz targets, see below | `fuzz_test.go`, `fuzz_bind_test.go` |

## The port mapper

Unless a port is given (`port=` in the DSN, or `Config.Port`), the driver asks the IBM i **port mapper on port 449 in plaintext** for the database server's port, and falls back to the default if it does not answer. On an untrusted network that lookup can be steered: it can send the client to another port, though not around TLS verification (the certificate and name are still checked on whatever port it ends up on). Set the port explicitly (9471 for TLS) to skip the mapper entirely.

## Server-driven password level

The signon exchange announces the password level and the client follows it. See `minPasswordLevel` above.

## Commands

```sh
go vet ./...
staticcheck ./...
go test -race ./...
go test -run '^$' -fuzz '^FuzzParseFetchPayload$' -fuzztime 120s .   # any Fuzz* target
```

## How long the fuzzers ran

Before the tag, each of the 20 targets ran for **120 seconds** (wall clock, `-parallel 3`, five targets at a time on a 16-core machine) against the final code, with no crash left. An earlier pass, before the last fix, had found a decimal-oracle bug in the test itself (a very long exponent could not be compared with `big.Rat`) and a worst-case allocation of 64 MiB for one bind against a hostile parameter format, which is why the record limit exists. Two minutes finds shallow problems; it is not a proof. Run longer, for hours, in CI before relying on the result.

## Not verified

Everything that needs a real host: what a `CAST` of a DECIMAL renders, CCSID translation on the real server, isolation levels in force, TLS against the host's real certificate, the signon exchange on the wire (the fork dials the signon server on port 9476 before the database server on 9471). The fork has no job-CCSID override, and DECFLOAT NaN and infinities are readable only through a `CAST`.
