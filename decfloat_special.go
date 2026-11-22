package i400

import (
	"errors"
	"strings"
)

// ErrDecfloatNotFinite is matched (errors.Is) by the error a read returns for a DECFLOAT
// that is NaN, SNaN or an infinity.
var ErrDecfloatNotFinite = errors.New("i400: DECFLOAT value is not a finite number")

// DecfloatSpecialError is returned when a DECFLOAT column holds NaN, SNaN or an infinity.
// These are not numbers: the driver refuses to hand them over as text a caller could
// mistake for one. Kind is "NaN", "SNaN" or "Infinity". To read them, CAST the column to
// a character type in the SQL.
type DecfloatSpecialError struct{ Kind string }

func (e *DecfloatSpecialError) Error() string {
	return "i400: DECFLOAT value is " + e.Kind + ", not a finite number"
}

func (e *DecfloatSpecialError) Is(target error) bool { return target == ErrDecfloatNotFinite }

func decfloatSpecialKind(text string) string {
	t := strings.TrimPrefix(text, "-")
	switch t {
	case "NaN", "SNaN", "Infinity":
		return t
	}
	return ""
}
