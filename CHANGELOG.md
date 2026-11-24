# Changelog

## Unreleased (v0.1.3)

Not tagged or published. Releasing needs the owner's approval.

### Fixed

- BINARY(n) bind: a value longer than the column is refused with `parameter value too long` instead of being cut
  silently (F01). The cut value stored wrong data and made a longer `WHERE B = ?` key match it. A shorter value is
  still zero-padded.
- Fetch: every negative null indicator is NULL, not only -1 (F02). A host NULL raised by a data mapping error
  (warning +331) was returned as an empty string. PUB400 round 4 measured it: -2 (`FFFE`) with
  +331 (also on a NOT NULL column), -1 (`FFFF`) for a stored NULL. Both read as NULL.

### Added

- `ErrParameterTooLong`: every "parameter value too long" refusal (BINARY, VARBINARY, CHAR, VARCHAR, graphic) wraps it,
  so callers can use `errors.Is` (F05). The message text is unchanged.
- The +331 of a fetch is already in `Conn.Warnings()`, so a mapping NULL (-2, warned) can be told from a stored NULL
  (-1, no warning). No per-row flag was added.
- Tests pinned to the PUB400 measurements: the indicators, BINARY(4) reports 4 and VARBINARY(4) reports 6, 4 bytes
  round-trip and 5 are refused on the client (A51, F07). No code change.

### Documentation

- Corrections to the PUB400 runs, the CCSID counts and the DECFLOAT encode comment (5ec173a, carried from `docs/v0.1.3`).
- `HARDENING.md`: two new rows for the changes above.
