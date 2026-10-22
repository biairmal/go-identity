package listquery

import (
	"errors"
	"net/url"
	"testing"

	common "github.com/biairmal/go-sdk/lib/common/dto"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/repository"
)

func TestParseListParamsDefaults(t *testing.T) {
	cfg := ListParseConfig{
		AllowedSortFields:   []string{"name"},
		AllowedFilterFields: []string{"name"},
	}

	params, err := ParseListParams(url.Values{}, &cfg)
	if err != nil {
		t.Fatalf("ParseListParams() error = %v, want nil", err)
	}
	if params.Page != DefaultPage {
		t.Errorf("Page = %d, want package default %d", params.Page, DefaultPage)
	}
	if params.Size != DefaultSize {
		t.Errorf("Size = %d, want package default %d", params.Size, DefaultSize)
	}
	if len(params.Sorts) != 0 {
		t.Errorf("Sorts = %v, want empty", params.Sorts)
	}
	if len(params.Filters) != 0 {
		t.Errorf("Filters = %v, want empty", params.Filters)
	}
}

func TestParseListParamsOverridesConfigDefaults(t *testing.T) {
	cfg := ListParseConfig{
		DefaultPage: 2,
		DefaultSize: 5,
		MaxSize:     10,
	}

	params, err := ParseListParams(url.Values{}, &cfg)
	if err != nil {
		t.Fatalf("ParseListParams() error = %v, want nil", err)
	}
	if params.Page != 2 {
		t.Errorf("Page = %d, want 2 (config default)", params.Page)
	}
	if params.Size != 5 {
		t.Errorf("Size = %d, want 5 (config default)", params.Size)
	}
}

func TestParseListParamsSizeClampedToMax(t *testing.T) {
	cfg := ListParseConfig{MaxSize: 10}
	q := url.Values{"size": {"999"}}

	params, err := ParseListParams(q, &cfg)
	if err != nil {
		t.Fatalf("ParseListParams() error = %v, want nil", err)
	}
	if params.Size != 10 {
		t.Errorf("Size = %d, want clamped to MaxSize 10", params.Size)
	}
}

func TestParseListParamsPageAndSize(t *testing.T) {
	q := url.Values{"page": {"3"}, "size": {"15"}}

	params, err := ParseListParams(q, &ListParseConfig{})
	if err != nil {
		t.Fatalf("ParseListParams() error = %v, want nil", err)
	}
	if params.Page != 3 || params.Size != 15 {
		t.Errorf("Page/Size = %d/%d, want 3/15", params.Page, params.Size)
	}
}

func TestParseListParamsInvalidPageAndSize(t *testing.T) {
	tests := []struct {
		name string
		q    url.Values
	}{
		{name: "non-numeric page", q: url.Values{"page": {"abc"}}},
		{name: "zero page", q: url.Values{"page": {"0"}}},
		{name: "negative page", q: url.Values{"page": {"-1"}}},
		{name: "non-numeric size", q: url.Values{"size": {"abc"}}},
		{name: "zero size", q: url.Values{"size": {"0"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseListParams(tt.q, &ListParseConfig{}); err == nil {
				t.Errorf("ParseListParams(%v) error = nil, want error", tt.q)
			}
		})
	}
}

func TestParseListParamsSort(t *testing.T) {
	cfg := ListParseConfig{AllowedSortFields: []string{"name", "id"}}
	q := url.Values{"sort": {"name,ASC", "id,desc"}}

	params, err := ParseListParams(q, &cfg)
	if err != nil {
		t.Fatalf("ParseListParams() error = %v, want nil", err)
	}
	want := []common.SortSpec{
		{Field: "name", Direction: common.SortAsc},
		{Field: "id", Direction: common.SortDesc},
	}
	if len(params.Sorts) != len(want) {
		t.Fatalf("Sorts = %v, want %v", params.Sorts, want)
	}
	for i, s := range want {
		if params.Sorts[i] != s {
			t.Errorf("Sorts[%d] = %v, want %v", i, params.Sorts[i], s)
		}
	}
}

func TestParseListParamsSortRejectsDisallowedField(t *testing.T) {
	cfg := ListParseConfig{AllowedSortFields: []string{"name"}}
	q := url.Values{"sort": {"secret,ASC"}}

	if _, err := ParseListParams(q, &cfg); err == nil {
		t.Error("ParseListParams() error = nil, want error for disallowed sort field")
	}
}

func TestParseListParamsSortRejectsMalformedValue(t *testing.T) {
	tests := []struct {
		name string
		sort string
	}{
		{name: "missing direction", sort: "name"},
		{name: "invalid direction", sort: "name,SIDEWAYS"},
	}

	cfg := ListParseConfig{AllowedSortFields: []string{"name"}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := url.Values{"sort": {tt.sort}}
			if _, err := ParseListParams(q, &cfg); err == nil {
				t.Errorf("ParseListParams(sort=%q) error = nil, want error", tt.sort)
			}
		})
	}
}

func TestParseListParamsFilters(t *testing.T) {
	cfg := ListParseConfig{
		AllowedSortFields:   []string{"name"},
		AllowedFilterFields: []string{"name", "source"},
		AllowedParams:       []string{"other"},
	}
	q := url.Values{
		"name":   {"Event1"},
		"source": {"app"},
		"other":  {"read by the handler"},
		"page":   {"1"},
		"size":   {"20"},
		"sort":   {"name,ASC"},
	}

	params, err := ParseListParams(q, &cfg)
	if err != nil {
		t.Fatalf("ParseListParams() error = %v, want nil", err)
	}
	want := map[string]string{"name": "Event1", "source": "app"}
	if len(params.Filters) != len(want) {
		t.Fatalf("filters = %v, want %v", params.Filters, want)
	}
	for k, v := range want {
		got := params.Filters[k]
		if got.Value != v || got.Operator != repository.FilterOperatorEq {
			t.Errorf("filters[%q] = %+v, want {%q eq}", k, got, v)
		}
	}
}

func TestParseListParamsFilterOperatorSuffix(t *testing.T) {
	cfg := ListParseConfig{AllowedFilterFields: []string{"name"}}

	t.Run("no suffix defaults to eq", func(t *testing.T) {
		params, err := ParseListParams(url.Values{"name": {"Ali"}}, &cfg)
		if err != nil {
			t.Fatalf("ParseListParams() error = %v, want nil", err)
		}
		got := params.Filters["name"]
		if got.Value != "Ali" || got.Operator != repository.FilterOperatorEq {
			t.Errorf("filters[name] = %+v, want {Ali eq}", got)
		}
	})

	t.Run("like suffix", func(t *testing.T) {
		params, err := ParseListParams(url.Values{"name": {"Ali;like"}}, &cfg)
		if err != nil {
			t.Fatalf("ParseListParams() error = %v, want nil", err)
		}
		got := params.Filters["name"]
		if got.Value != "Ali" || got.Operator != repository.FilterOperatorLike {
			t.Errorf("filters[name] = %+v, want {Ali like}", got)
		}
	})

	t.Run("trailing empty suffix defaults to eq", func(t *testing.T) {
		params, err := ParseListParams(url.Values{"name": {"Ali;"}}, &cfg)
		if err != nil {
			t.Fatalf("ParseListParams() error = %v, want nil", err)
		}
		got := params.Filters["name"]
		if got.Value != "Ali" || got.Operator != repository.FilterOperatorEq {
			t.Errorf("filters[name] = %+v, want {Ali eq}", got)
		}
	})

	t.Run("unrecognized operator is rejected", func(t *testing.T) {
		if _, err := ParseListParams(url.Values{"name": {"Ali;gt"}}, &cfg); err == nil {
			t.Error("ParseListParams() error = nil, want error for unsupported operator")
		}
	})
}

func TestValidateListParams(t *testing.T) {
	cfg := ListParseConfig{
		AllowedSortFields:   []string{"name"},
		AllowedFilterFields: []string{"name"},
	}

	tests := []struct {
		name    string
		params  *ListParams
		wantErr bool
	}{
		{name: "nil params", params: nil},
		{name: "empty params", params: &ListParams{}},
		{
			name: "allowed sort field",
			params: &ListParams{
				BasePageRequest: *common.NewBasePageRequest(1, 20, []common.SortSpec{{Field: "name", Direction: common.SortAsc}}),
			},
		},
		{
			name: "disallowed sort field",
			params: &ListParams{
				BasePageRequest: *common.NewBasePageRequest(1, 20, []common.SortSpec{{Field: "secret", Direction: common.SortAsc}}),
			},
			wantErr: true,
		},
		{
			name:   "allowed filter field",
			params: &ListParams{Filters: map[string]FilterValue{"name": {Value: "x", Operator: repository.FilterOperatorEq}}},
		},
		{
			name:    "disallowed filter field",
			params:  &ListParams{Filters: map[string]FilterValue{"secret": {Value: "x", Operator: repository.FilterOperatorEq}}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateListParams(tt.params, &cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateListParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestToListOptions(t *testing.T) {
	t.Run("nil params", func(t *testing.T) {
		opts := ToListOptions(nil)
		if opts == nil || opts.Pagination.Limit != 0 || opts.Pagination.Offset != 0 {
			t.Errorf("ToListOptions(nil) = %+v, want zero-value options", opts)
		}
	})

	t.Run("clamps and converts", func(t *testing.T) {
		params := &ListParams{
			BasePageRequest: *common.NewBasePageRequest(2, 500, []common.SortSpec{{Field: "name", Direction: common.SortDesc}}),
			Filters:         map[string]FilterValue{"name": {Value: "x", Operator: repository.FilterOperatorEq}},
		}
		opts := ToListOptions(params)

		if opts.Pagination.Limit != DefaultMaxSize {
			t.Errorf("Limit = %d, want clamped to %d", opts.Pagination.Limit, DefaultMaxSize)
		}
		if opts.Pagination.Offset != (2-1)*DefaultMaxSize {
			t.Errorf("Offset = %d, want %d", opts.Pagination.Offset, (2-1)*DefaultMaxSize)
		}
		if len(opts.Filter.Conditions) != 1 || opts.Filter.Conditions[0].Field != "name" ||
			opts.Filter.Conditions[0].Operator != repository.FilterOperatorEq {
			t.Errorf("Filter.Conditions = %+v, want one eq condition on name", opts.Filter.Conditions)
		}
		if len(opts.Sorts) != 1 || opts.Sorts[0] != (repository.Sort{Field: "name", Direction: repository.SortDesc}) {
			t.Errorf("Sorts = %+v, want [{name DESC}]", opts.Sorts)
		}
	})

	t.Run("like operator wraps value with %", func(t *testing.T) {
		params := &ListParams{Filters: map[string]FilterValue{"name": {Value: "x", Operator: repository.FilterOperatorLike}}}
		opts := ToListOptions(params)

		if len(opts.Filter.Conditions) != 1 || opts.Filter.Conditions[0].Value != "%x%" ||
			opts.Filter.Conditions[0].Operator != repository.FilterOperatorLike {
			t.Errorf("Filter.Conditions = %+v, want one like condition with value %%x%%", opts.Filter.Conditions)
		}
	})

	t.Run("defaults zero page and size", func(t *testing.T) {
		opts := ToListOptions(&ListParams{})
		if opts.Pagination.Limit != DefaultSize {
			t.Errorf("Limit = %d, want default %d", opts.Pagination.Limit, DefaultSize)
		}
		if opts.Pagination.Offset != 0 {
			t.Errorf("Offset = %d, want 0", opts.Pagination.Offset)
		}
	})
}

func TestParseListParamsRejectsUnknownAndTenantKeys(t *testing.T) {
	cfg := ListParseConfig{
		AllowedSortFields:   []string{"name", TenantField},
		AllowedFilterFields: []string{"name", TenantField},
		AllowedParams:       []string{"search"},
	}
	tests := []struct {
		name  string
		q     url.Values
		field string
	}{
		{name: "unknown filter", q: url.Values{"secret": {"x"}}, field: "secret"},
		{name: "tenant_id filter even when listed", q: url.Values{TenantField: {"t2"}}, field: TenantField},
		{name: "tenant_id sort even when listed", q: url.Values{"sort": {TenantField + ",ASC"}}, field: "sort"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseListParams(tt.q, &cfg)
			var e *errorz.Error
			if !errors.As(err, &e) || e.Code != errorz.CodeBadRequest {
				t.Fatalf("ParseListParams(%v) = %v, want a 400", tt.q, err)
			}
			fields, ok := e.Meta["fields"].(map[string]string)
			if !ok || fields[tt.field] == "" {
				t.Errorf("meta.fields = %v, want an entry for %q", e.Meta["fields"], tt.field)
			}
		})
	}

	if _, err := ParseListParams(url.Values{"search": {"x"}, "name": {"a"}}, &cfg); err != nil {
		t.Errorf("allowed param and filter rejected: %v", err)
	}
	params := &ListParams{Filters: map[string]FilterValue{TenantField: {Value: "t2"}}}
	if err := ValidateListParams(params, &cfg); err == nil {
		t.Error("ValidateListParams accepted a tenant_id filter")
	}
}
