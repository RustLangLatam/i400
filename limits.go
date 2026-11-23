package i400

import "fmt"

// Limits on counts and sizes read from the wire. Each is checked before the
// matching allocation or loop, against both a hard cap and the bytes the peer
// actually sent, so a hostile server cannot cost the client more memory or CPU
// than the data it really transmits.

const (
	// maxColumns bounds the columns or parameter markers of one statement. Db2
	// for i allows at most 8000 columns in a table; this leaves headroom.
	maxColumns = 32767

	// maxBlockCells bounds rows x columns of one fetch block. A legitimate block
	// is at most 16000 KB and every cell needs at least one byte.
	maxBlockCells = 1 << 24

	// maxFieldBytes bounds the size of one parameter marker field (and of an inline LOB
	// value): an inline LOB is at most 15 MiB (maxLOBThreshold), so 16 MiB leaves room.
	maxFieldBytes = 16 << 20

	// maxRecordBytes bounds the parameter record of one statement (the sum of its field
	// lengths). Binding allocates a null and a value buffer per field, so the worst case
	// for one bind is about twice this. A legitimate record is a row (at most 32766 bytes)
	// plus inline LOBs (at most 15 MiB each, rarely more than one or two).
	maxRecordBytes = 32 << 20

	// Smallest encodings, used to prove that a declared count fits the payload.
	extendedColumnDescriptorBytes = 16 // updateable, searchable, bitmap, offset, length, reserved
	superExtendedFieldBytes       = 48
)

// checkCount verifies that count entries of at least entryBytes each fit in
// remaining bytes and do not exceed max.
func checkCount(what string, count uint64, entryBytes, remaining, max int) error {
	if count > uint64(max) {
		return fmt.Errorf("%s: count %d exceeds the limit of %d", what, count, max)
	}
	if entryBytes > 0 && count > uint64(remaining/entryBytes) {
		return fmt.Errorf("%s: count %d does not fit the %d bytes received", what, count, remaining)
	}
	return nil
}

// checkResultBlockShape validates the header of a fetch block against the bytes
// that follow it before anything is allocated.
func checkResultBlockShape(remaining, rowCount, columnCount, indicatorSize, rowSize int) error {
	if rowCount < 0 || columnCount < 0 || indicatorSize < 0 || rowSize < 0 {
		return fmt.Errorf("result data block has a negative size")
	}
	if columnCount > maxColumns {
		return fmt.Errorf("result data block: %d columns exceeds the limit of %d", columnCount, maxColumns)
	}
	cells := uint64(rowCount) * uint64(columnCount)
	if cells > maxBlockCells || uint64(rowCount) > maxBlockCells {
		return fmt.Errorf("result data block: %d rows x %d columns exceeds the limit", rowCount, columnCount)
	}
	if indicatorSize > 0 && cells > uint64(remaining/indicatorSize) {
		return fmt.Errorf("result data block: indicators for %d cells do not fit the %d bytes received", cells, remaining)
	}
	indicatorBytes := cells * uint64(indicatorSize)
	if rowSize > 0 && uint64(rowCount) > uint64(remaining)/uint64(rowSize) {
		return fmt.Errorf("result data block: %d rows of %d bytes do not fit the %d bytes received", rowCount, rowSize, remaining)
	}
	if indicatorBytes+uint64(rowCount)*uint64(rowSize) > uint64(remaining) {
		return fmt.Errorf("result data block: %d rows do not fit the %d bytes received", rowCount, remaining)
	}
	return nil
}

// checkMarkerFormat validates a parameter marker format a server sent, before anything
// is sized from it: the field count, every field's length, and the record size, which
// must also fit one packet together. A lying size is an error, never clamped.
func checkMarkerFormat(fields []parameterMarkerField, recordSize int) error {
	if len(fields) > maxColumns {
		return fmt.Errorf("parameter marker format: %d fields exceeds the limit of %d", len(fields), maxColumns)
	}
	if recordSize < 0 || recordSize > maxRecordBytes {
		return fmt.Errorf("parameter marker format: record size %d is outside 0..%d", recordSize, maxRecordBytes)
	}
	total := 0
	for i, f := range fields {
		if f.Length < 0 || f.Length > maxFieldBytes {
			return fmt.Errorf("parameter marker format: field %d length %d is outside 0..%d", i+1, f.Length, maxFieldBytes)
		}
		total += f.Length
		if total > maxRecordBytes {
			return fmt.Errorf("parameter marker format: the fields together exceed %d bytes", maxRecordBytes)
		}
	}
	return nil
}

// checkBindField refuses to size a buffer from a field description that lies.
func checkBindField(field parameterMarkerField) error {
	if field.Length < 0 || field.Length > maxFieldBytes {
		return fmt.Errorf("parameter field length %d is outside 0..%d", field.Length, maxFieldBytes)
	}
	return nil
}
