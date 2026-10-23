// Package listquery provides a shared allow-list-based parser for HTTP list-endpoint
// query parameters (pagination, sorting, and simple equality filters), so a
// feature only needs to declare its allow-lists instead of reimplementing parsing.
//
// Every error is an errorz BadRequest (HTTP 400) with the offending query
// parameter under meta.fields.
package listquery

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	common "github.com/biairmal/go-sdk/lib/common/dto"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/repository"
)

// TenantField is never accepted as a sort or filter field: the tenant always
// comes from the token (see internal/platform/scope).
const TenantField = "tenant_id"

// reservedParams are the query keys ParseListParams handles itself.
var reservedParams = map[string]bool{"page": true, "size": true, "sort": true}

// badParam builds the 400 for one query parameter.
func badParam(field, msg string) error {
	return errorz.BadRequest().WithMessage(fmt.Sprintf("invalid query parameter %s: %s", field, msg)).
		WithMeta("fields", map[string]string{field: msg})
}

// Default pagination values applied when a ListParseConfig leaves the
// corresponding field unset (zero value).
const (
	DefaultPage    = 1
	DefaultSize    = 20
	DefaultMaxSize = 100
)

// supportedFilterOperators whitelists which repository.FilterOperator values
// a filter value's ";operator" suffix (see FilterValue) may select. Kept
// intentionally short — eq (the default) and like are all any feature needs
// today; add another go-sdk FilterOperator here (gt, in, ...) when a feature
// actually needs it, not speculatively.
var supportedFilterOperators = map[repository.FilterOperator]bool{
	repository.FilterOperatorEq:   true,
	repository.FilterOperatorLike: true,
}

// ListParseConfig configures allow-listed sort/filter fields and pagination
// bounds for ParseListParams. A feature typically only needs to set
// AllowedSortFields and AllowedFilterFields; DefaultPage, DefaultSize, and
// MaxSize fall back to the package-level defaults above when left zero.
//
// AllowedParams lists other query keys the endpoint reads itself (e.g.
// "search", "force"); any key that is neither reserved, a filter nor listed
// there is rejected, so a typo or a forbidden filter never silently widens a
// list.
type ListParseConfig struct {
	DefaultPage         int
	DefaultSize         int
	MaxSize             int
	AllowedSortFields   []string
	AllowedFilterFields []string
	AllowedParams       []string
}

// withDefaults returns a copy of c with zero-valued pagination fields filled
// in from the package defaults.
func (c ListParseConfig) withDefaults() *ListParseConfig { //nolint:gocritic // works on a copy by design
	if c.DefaultPage <= 0 {
		c.DefaultPage = DefaultPage
	}
	if c.DefaultSize <= 0 {
		c.DefaultSize = DefaultSize
	}
	if c.MaxSize <= 0 {
		c.MaxSize = DefaultMaxSize
	}
	return &c
}

// FilterValue is one parsed filter: the raw value and the operator it should
// be matched with. A query value carries its operator inline as
// "value;operator" (e.g. "Ali;like"); no ";operator" suffix defaults to
// FilterOperatorEq, same as every filter before this existed.
type FilterValue struct {
	Value    string
	Operator repository.FilterOperator
}

// ListParams is the parsed result of ParseListParams: pagination and sorting
// (via the embedded common.BasePageRequest) plus filters, shared by every
// list endpoint so no feature needs its own params type.
type ListParams struct {
	common.BasePageRequest
	Filters map[string]FilterValue // field -> value+operator
}

// ParseListParams parses pagination, sort, and filter query parameters per
// an allow-list config shared by every list endpoint.
//
// Expected query format:
//
//		name=Event1&page=1&size=20&sort=column1,DESC&sort=column2,ASC
//
//	  - page: 1-based page number (int, defaults to cfg.DefaultPage).
//	  - size: items per page (int, defaults to cfg.DefaultSize, clamped to cfg.MaxSize).
//	  - sort: repeatable, format "field,DIRECTION" where DIRECTION is ASC or DESC (case-insensitive).
//	  - Any key matching cfg.AllowedFilterFields is a filter; its value may carry
//	    an operator suffix ("value;operator", e.g. "Ali;like") — see FilterValue.
func ParseListParams(q url.Values, cfg *ListParseConfig) (*ListParams, error) {
	if cfg == nil {
		cfg = &ListParseConfig{}
	}
	cfg = cfg.withDefaults()

	page, err := parsePage(q, cfg)
	if err != nil {
		return nil, err
	}
	size, err := parseSize(q, cfg)
	if err != nil {
		return nil, err
	}
	sorts, err := parseSorts(q, cfg)
	if err != nil {
		return nil, err
	}
	filters, err := parseFilters(q, cfg)
	if err != nil {
		return nil, err
	}

	return &ListParams{
		BasePageRequest: *common.NewBasePageRequest(page, size, sorts),
		Filters:         filters,
	}, nil
}

// ValidateListParams checks params' sort fields and filter keys against cfg's
// allow-lists, returning an error naming the first disallowed field.
//
// This runs the same check as ParseListParams, but against an already-built
// *ListParams instead of a raw HTTP query string, so it works regardless of
// which transport produced params (HTTP, gRPC, a subscriber, ...). Call this
// in the service — the service is the transport-agnostic authority on what's
// filterable/sortable, not the handler. See docs/PATTERNS.md#list-queries
// for why this is deliberate
// defense-in-depth alongside ParseListParams' own check, not duplication.
func ValidateListParams(params *ListParams, cfg *ListParseConfig) error {
	if params == nil {
		return nil
	}
	if cfg == nil {
		cfg = &ListParseConfig{}
	}
	allowedSorts := toSet(cfg.AllowedSortFields)
	for _, s := range params.Sorts {
		if !allowedSorts[s.Field] {
			return badParam("sort", "field not allowed: "+s.Field)
		}
	}
	allowedFilters := toSet(cfg.AllowedFilterFields)
	for field := range params.Filters {
		if !allowedFilters[field] {
			return badParam(field, "filter not allowed")
		}
	}
	return nil
}

// ToListOptions converts params to a *repository.ListOptions: page/size are
// clamped to sane bounds (defaulting to page 1, size 20, max 100) and turned
// into a limit/offset, filters become repository.FilterCondition entries
// (a FilterOperatorLike value is wrapped "%value%"), and sorts map to
// repository.Sort. A nil params returns zero-value options (page 1, default
// size, no filters/sorts).
//
// Every feature service shares this conversion — never hand-roll a
// per-feature copy (see docs/PATTERNS.md#list-queries).
func ToListOptions(params *ListParams) *repository.ListOptions {
	if params == nil {
		return &repository.ListOptions{}
	}

	page, size := params.Page, params.Size
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = DefaultSize
	}
	if size > DefaultMaxSize {
		size = DefaultMaxSize
	}
	offset := (page - 1) * size

	var conditions []repository.FilterCondition
	for field, fv := range params.Filters {
		value := fv.Value
		if fv.Operator == repository.FilterOperatorLike {
			value = "%" + value + "%"
		}
		conditions = append(conditions, repository.FilterCondition{
			Field:    field,
			Operator: fv.Operator,
			Value:    value,
		})
	}

	var sorts []repository.Sort
	for _, s := range params.Sorts {
		dir := repository.SortAsc
		if s.Direction == common.SortDesc {
			dir = repository.SortDesc
		}
		sorts = append(sorts, repository.Sort{Field: s.Field, Direction: dir})
	}

	return &repository.ListOptions{
		Filter:     repository.Filter{Conditions: conditions},
		Pagination: repository.Pagination{Limit: size, Offset: offset},
		Sorts:      sorts,
	}
}

// parsePage parses the "page" query parameter, defaulting to cfg.DefaultPage.
func parsePage(q url.Values, cfg *ListParseConfig) (int, error) {
	v := q.Get("page")
	if v == "" {
		return cfg.DefaultPage, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, badParam("page", "must be a positive integer")
	}
	return n, nil
}

// parseSize parses the "size" query parameter, defaulting to cfg.DefaultSize
// and clamping to cfg.MaxSize.
func parseSize(q url.Values, cfg *ListParseConfig) (int, error) {
	size := cfg.DefaultSize
	if v := q.Get("size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return 0, badParam("size", "must be a positive integer")
		}
		size = n
	}
	if size > cfg.MaxSize {
		size = cfg.MaxSize
	}
	return size, nil
}

// parseSorts parses repeatable "sort=field,DIRECTION" query parameters,
// rejecting fields not in cfg.AllowedSortFields.
func parseSorts(q url.Values, cfg *ListParseConfig) ([]common.SortSpec, error) {
	allowedSorts := toSet(cfg.AllowedSortFields)
	var sorts []common.SortSpec
	for _, sv := range q["sort"] {
		parts := strings.SplitN(sv, ",", 2)
		if len(parts) != 2 {
			return nil, badParam("sort", "expected field,DIRECTION")
		}
		field := strings.TrimSpace(parts[0])
		dirStr := strings.ToUpper(strings.TrimSpace(parts[1]))

		if !allowedSorts[field] {
			return nil, badParam("sort", "field not allowed: "+field)
		}
		var dir common.SortDirection
		switch dirStr {
		case string(common.SortAsc):
			dir = common.SortAsc
		case string(common.SortDesc):
			dir = common.SortDesc
		default:
			return nil, badParam("sort", "direction must be ASC or DESC")
		}
		sorts = append(sorts, common.SortSpec{Field: field, Direction: dir})
	}
	return sorts, nil
}

// parseFilters extracts filters for keys in cfg.AllowedFilterFields, ignoring
// pagination/sort keys and cfg.AllowedParams; any other key is rejected. Each
// raw value is split on the first ";" into a value and an optional operator
// suffix (see FilterValue); an unrecognized operator is rejected, same as an
// unknown sort/filter field.
func parseFilters(q url.Values, cfg *ListParseConfig) (map[string]FilterValue, error) {
	allowedFilters := toSet(cfg.AllowedFilterFields)
	allowedParams := toSet(cfg.AllowedParams)
	filters := make(map[string]FilterValue)
	for key := range q {
		if reservedParams[key] || allowedParams[key] {
			continue
		}
		if !allowedFilters[key] {
			return nil, badParam(key, "unknown query parameter")
		}
		fv, err := parseFilterValue(q.Get(key))
		if err != nil {
			return nil, badParam(key, err.Error())
		}
		filters[key] = fv
	}
	return filters, nil
}

// parseFilterValue splits raw on the first ";" into a value and an operator
// suffix. No suffix (or an empty one, e.g. trailing ";") defaults to
// FilterOperatorEq. An unrecognized operator is an error.
func parseFilterValue(raw string) (FilterValue, error) {
	value, opStr, hasOp := strings.Cut(raw, ";")
	if !hasOp || opStr == "" {
		return FilterValue{Value: value, Operator: repository.FilterOperatorEq}, nil
	}
	op := repository.FilterOperator(strings.ToLower(opStr))
	if !supportedFilterOperators[op] {
		return FilterValue{}, fmt.Errorf("unsupported filter operator %q", opStr)
	}
	return FilterValue{Value: value, Operator: op}, nil
}

// toSet converts a string slice to a set for O(1) lookup. TenantField is
// always left out, so it can never be allowed by mistake.
func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		if s != TenantField {
			m[s] = true
		}
	}
	return m
}
