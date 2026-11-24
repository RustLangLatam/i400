# Changelog

## Unreleased (v0.1.3)

Not tagged or published. Releasing needs the owner's approval.

### Fixed

- BINARY(n) bind: a value longer than the column is refused with `parameter value too long` instead of being cut
  silently (F01). The cut value stored wrong data and made a longer `WHERE B = ?` key match it. A shorter value is
  still zero-padded.
- Fetch: every negative null indicator is NULL, not only -1 (F02). A host NULL raised by a data mapping error
  (warning +331) was returned as an empty string. The indicator value the host sends for +331 is assumed to be -2 and
  was not captured on a real host.

### Documentation

- Corrections to the PUB400 runs, the CCSID counts and the DECFLOAT encode comment (5ec173a, carried from `docs/v0.1.3`).
- `HARDENING.md`: two new rows for the changes above.
