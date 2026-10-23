// Package httpx holds the HTTP conventions every handler shares (TRD 9.1):
// strict JSON decoding, If-Match versions, and a handler adapter that sets
// Retry-After on rate-limited errors.
package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/biairmal/go-sdk/lib/errorz"

	"github.com/biairmal/go-identity/internal/platform/apierr"
)

// MaxBodyBytes is the request body limit (1 MiB).
const MaxBodyBytes = 1 << 20

// DecodeJSON decodes r's JSON body into dst. Unknown fields, trailing data,
// an empty or oversized body and type mismatches are 400s with meta.fields
// naming the field where one is known.
func DecodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, MaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return decodeError(err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return badBody("body must contain a single JSON object")
	}
	return nil
}

// decodeError turns a json decoding error into a 400.
func decodeError(err error) error {
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	var maxErr *http.MaxBytesError
	switch {
	case errors.Is(err, io.EOF):
		return badBody("request body is required")
	case errors.As(err, &maxErr):
		return badBody(fmt.Sprintf("request body must not exceed %d bytes", maxErr.Limit))
	case errors.As(err, &syntaxErr), errors.Is(err, io.ErrUnexpectedEOF):
		return badBody("request body is not valid JSON")
	case errors.As(err, &typeErr):
		field := typeErr.Field
		if field == "" {
			return badBody("request body has the wrong JSON type")
		}
		return badField(field, "must be a "+typeErr.Type.String())
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		field, unquoteErr := strconv.Unquote(strings.TrimPrefix(err.Error(), "json: unknown field "))
		if unquoteErr != nil {
			return badBody("request body has an unknown field")
		}
		return badField(field, "unknown field")
	default:
		return badBody("request body could not be decoded")
	}
}

func badBody(msg string) error { return errorz.BadRequest().WithMessage(msg) }

func badField(field, msg string) error {
	return errorz.BadRequest().WithMessage(field+": "+msg).
		WithMeta(apierr.MetaFields, map[string]string{field: msg})
}
