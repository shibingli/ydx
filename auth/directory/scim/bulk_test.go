package scim

import (
	"errors"
	"math"
	"net/http"
	"strings"
	"testing"

	ydxjson "github.com/shibingli/ydx/json"
)

// bulkOperationResource decodes one bulk response body into T. | bulkOperationResource 把一个批量
// 响应体解码为 T。
func bulkOperationResource[T any](t *testing.T, operation BulkResponseOperation) T {
	t.Helper()
	raw, err := ydxjson.Marshal(operation.Response)
	if err != nil {
		t.Fatalf("marshal bulk response body: %v", err)
	}
	var out T
	if err := ydxjson.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode bulk response body: %v", err)
	}
	return out
}

// TestResolveBulkReferencesStructured verifies exact-value substitution, nested traversal and
// untouched substrings. | TestResolveBulkReferencesStructured 校验完整值替换、嵌套遍历与未改写的
// 子串。
func TestResolveBulkReferencesStructured(t *testing.T) {
	ids := map[string]string{"a": "user-1", "ab": "user-2"}
	input := map[string]any{
		"plain":    "prefix bulkId:a suffix",
		"exact":    "bulkId:a",
		"longest":  "bulkId:ab",
		"bulkId:a": "value under a reference-shaped key",
		"nested": map[string]any{
			"items": []any{
				"bulkId:ab",
				"text bulkId:a",
				map[string]any{"deep": "bulkId:a"},
			},
		},
		"number": int64(9007199254740993),
	}
	resolved, err := resolveBulkReferences(input, ids)
	if err != nil {
		t.Fatalf("resolveBulkReferences error = %v", err)
	}
	out, ok := resolved.(map[string]any)
	if !ok {
		t.Fatalf("resolved type = %T", resolved)
	}
	if out["plain"] != "prefix bulkId:a suffix" {
		t.Fatalf("embedded substring was rewritten: %q", out["plain"])
	}
	if out["exact"] != "user-1" {
		t.Fatalf("exact reference = %q", out["exact"])
	}
	if out["longest"] != "user-2" {
		t.Fatalf("prefix collision resolved to %q, want user-2", out["longest"])
	}
	if out["bulkId:a"] != "value under a reference-shaped key" {
		t.Fatalf("object key or its value was rewritten: %q", out["bulkId:a"])
	}
	if out["number"] != int64(9007199254740993) {
		t.Fatalf("number = %#v", out["number"])
	}
	nested, ok := out["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested type = %T", out["nested"])
	}
	items, ok := nested["items"].([]any)
	if !ok || len(items) != 3 {
		t.Fatalf("nested items = %#v", nested["items"])
	}
	if items[0] != "user-2" || items[1] != "text bulkId:a" {
		t.Fatalf("nested items = %#v", items)
	}
	deep, ok := items[2].(map[string]any)
	if !ok || deep["deep"] != "user-1" {
		t.Fatalf("deep nested item = %#v", items[2])
	}

	repeated, err := resolveBulkReferences([]any{"bulkId:a", "bulkId:a"}, ids)
	if err != nil {
		t.Fatalf("repeated references error = %v", err)
	}
	repeatedItems := repeated.([]any)
	if repeatedItems[0] != "user-1" || repeatedItems[1] != "user-1" {
		t.Fatalf("repeated references = %#v", repeatedItems)
	}

	_, err = resolveBulkReferences("bulkId:abc", ids)
	if !errors.Is(err, ErrBulkIDUnresolved) {
		t.Fatalf("prefix collision error = %v, want ErrBulkIDUnresolved", err)
	}
	pure, err := resolveBulkReferences("bulkId:ab", ids)
	if err != nil || pure != "user-2" {
		t.Fatalf("pure reference = %#v, %v", pure, err)
	}
}

// TestResolveBulkReferencesDeterministic verifies sorted traversal makes unresolved errors stable
// regardless of map iteration order. | TestResolveBulkReferencesDeterministic 校验排序遍历使未解析
// 错误不受 map 迭代顺序影响。
func TestResolveBulkReferencesDeterministic(t *testing.T) {
	for i := 0; i < 32; i++ {
		input := map[string]any{
			"z": "bulkId:late",
			"a": "bulkId:early",
		}
		_, err := resolveBulkReferences(input, map[string]string{"other": "id"})
		if !errors.Is(err, ErrBulkIDUnresolved) {
			t.Fatalf("error = %v, want ErrBulkIDUnresolved", err)
		}
		if !strings.Contains(err.Error(), "bulkId:early") {
			t.Fatalf("iteration %d reported %q, want the lowest sorted key", i, err)
		}
	}
}

// TestResolveBulkReferenceLimits verifies depth, container and node guards. |
// TestResolveBulkReferenceLimits 校验深度、容器与节点上限。
func TestResolveBulkReferenceLimits(t *testing.T) {
	newResolver := func() *bulkReferenceResolver {
		return &bulkReferenceResolver{
			ids:      map[string]string{},
			maxDepth: 2,
			maxItems: 2,
			maxNodes: 3,
		}
	}
	deep := map[string]any{"a": map[string]any{"b": map[string]any{"c": "value"}}}
	depthResolver := newResolver()
	depthResolver.maxNodes = 64
	if _, err := depthResolver.resolve(deep, 0); !errors.Is(err, ErrTooMany) {
		t.Fatalf("depth error = %v, want ErrTooMany", err)
	}
	wide := []any{"a", "b", "c"}
	if _, err := newResolver().resolve(wide, 0); !errors.Is(err, ErrTooMany) {
		t.Fatalf("array limit error = %v, want ErrTooMany", err)
	}
	object := map[string]any{"a": 1, "b": 2, "c": 3}
	if _, err := newResolver().resolve(object, 0); !errors.Is(err, ErrTooMany) {
		t.Fatalf("object limit error = %v, want ErrTooMany", err)
	}
	values := []any{"a", "b", "c", "d"}
	resolver := newResolver()
	resolver.maxItems = 8
	if _, err := resolver.resolve(values, 0); !errors.Is(err, ErrTooMany) {
		t.Fatalf("node limit error = %v, want ErrTooMany", err)
	}
}

// TestResolveBulkPathReferences verifies segment-wise path replacement. |
// TestResolveBulkPathReferences 校验按路径段替换。
func TestResolveBulkPathReferences(t *testing.T) {
	ids := map[string]string{"a": "user-1", "ab": "user-2"}
	cases := []struct {
		path string
		want string
	}{
		{"/Users/bulkId:a", "/Users/user-1"},
		{"/Users/bulkId:ab", "/Users/user-2"},
		{"/Users/user-bulkId:a", "/Users/user-bulkId:a"},
		{"https://idp.example/Users/bulkId:a?x=1", "/Users/user-1"},
		{"", ""},
		{"///", "///"},
	}
	for _, testCase := range cases {
		got, err := resolveBulkPathReferences(testCase.path, ids)
		if err != nil || got != testCase.want {
			t.Fatalf("resolveBulkPathReferences(%q) = %q, %v, want %q", testCase.path, got, err, testCase.want)
		}
	}
	for _, path := range []string{"/Users/bulkId:missing", "/Users/bulkId:a"} {
		var lookup map[string]string
		if path == "/Users/bulkId:a" {
			lookup = nil
		} else {
			lookup = ids
		}
		if _, err := resolveBulkPathReferences(path, lookup); !errors.Is(err, ErrBulkIDUnresolved) {
			t.Fatalf("resolveBulkPathReferences(%q) error = %v, want ErrBulkIDUnresolved", path, err)
		}
	}
}

// TestValidateBulkIDs verifies duplicate definitions are reported through a sentinel. |
// TestValidateBulkIDs 校验重复定义通过哨兵报告。
func TestValidateBulkIDs(t *testing.T) {
	if err := validateBulkIDs([]BulkOperation{{BulkID: "dup"}, {BulkID: "dup"}}); !errors.Is(err, ErrBulkIDDuplicate) {
		t.Fatalf("duplicate error = %v, want ErrBulkIDDuplicate", err)
	}
	if err := validateBulkIDs([]BulkOperation{{BulkID: ""}, {BulkID: ""}, {BulkID: "unique"}}); err != nil {
		t.Fatalf("empty bulkIds error = %v", err)
	}
}

// TestDecodeBulkDataPreservesNumbers verifies the structured walk does not round-trip numbers
// through float64. | TestDecodeBulkDataPreservesNumbers 校验结构化遍历不会让数字经过 float64 往返。
func TestDecodeBulkDataPreservesNumbers(t *testing.T) {
	var payload struct {
		Number int64  `json:"number"`
		Value  string `json:"value"`
		Note   string `json:"note"`
	}
	data := map[string]any{
		"number": int64(9007199254740993),
		"value":  "bulkId:a",
		"note":   "keep bulkId:a inside text",
	}
	if err := decodeBulkData(data, map[string]string{"a": "user-1"}, &payload); err != nil {
		t.Fatalf("decodeBulkData error = %v", err)
	}
	if payload.Number != 9007199254740993 {
		t.Fatalf("number = %d", payload.Number)
	}
	if payload.Value != "user-1" || payload.Note != "keep bulkId:a inside text" {
		t.Fatalf("payload = %+v", payload)
	}
}

// TestDecodeBulkDataErrors verifies invalid inputs and targets map to ErrInvalidValue. |
// TestDecodeBulkDataErrors 校验非法输入与目标映射为 ErrInvalidValue。
func TestDecodeBulkDataErrors(t *testing.T) {
	var target map[string]any
	if err := decodeBulkData(nil, nil, &target); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil data error = %v", err)
	}
	var nilMap map[string]any
	if err := decodeBulkData(nilMap, nil, &target); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil map error = %v", err)
	}
	if err := decodeBulkData(map[string]any{"bad": make(chan int)}, nil, &target); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("marshal error = %v", err)
	}
	var number int
	if err := decodeBulkData(map[string]any{"a": "b"}, nil, &number); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("target error = %v", err)
	}
}

// TestSubstituteBulkIDsSkipsEmpty verifies empty keys and identifiers never rewrite text. |
// TestSubstituteBulkIDsSkipsEmpty 校验空键与空标识绝不改写文本。
func TestSubstituteBulkIDsSkipsEmpty(t *testing.T) {
	ids := map[string]string{"": "empty-key-id", "a": ""}
	if got := substituteBulkIDs("bulkId: and bulkId:a", ids); got != "bulkId: and bulkId:a" {
		t.Fatalf("empty entries rewrote text: %q", got)
	}
	sameLength := map[string]string{"a": "1", "b": "2"}
	if got := substituteBulkIDs("bulkId:b bulkId:a", sameLength); got != "2 1" {
		t.Fatalf("same-length lexicographic substitution = %q", got)
	}
}

// TestBulkBulkIDStructuredReferences verifies User and Group bulk operations resolve exact
// references in nested objects and arrays while leaving unrelated strings untouched. |
// TestBulkBulkIDStructuredReferences 校验 User 与 Group 批量操作解析嵌套对象和数组中的完整引用，
// 同时不改写无关字符串。
func TestBulkBulkIDStructuredReferences(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Schemas: []string{BulkRequestSchema},
		Operations: []BulkOperation{
			{
				BulkID: "a",
				Method: "POST",
				Path:   "/Users",
				Data: map[string]any{
					"userName":    "bulk-ref-a",
					"displayName": "literal bulkId:ab text",
					"name":        map[string]any{"givenName": "literal bulkId:a text"},
				},
			},
			{
				BulkID: "ab",
				Method: "POST",
				Path:   "/Users",
				Data:   map[string]any{"userName": "bulk-ref-ab"},
			},
			{
				BulkID: "group",
				Method: "POST",
				Path:   "/Groups",
				Data: map[string]any{
					"displayName": "literal bulkId:a text",
					"members": []any{
						map[string]any{"value": "bulkId:ab", "type": "User"},
						map[string]any{"value": "bulkId:a", "type": "User"},
					},
				},
			},
			{
				BulkID: "c",
				Method: "POST",
				Path:   "/Users",
				Data:   map[string]any{"userName": "bulk-ref-c"},
			},
			{
				Method: "PATCH",
				Path:   "/Groups/bulkId:group",
				Data: map[string]any{
					"schemas": []string{PatchOpSchema},
					"Operations": []any{
						map[string]any{
							"op":   "add",
							"path": "members",
							"value": []any{
								map[string]any{"value": "bulkId:c", "type": "User"},
							},
						},
					},
				},
			},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response := decodeResponse[BulkResponse](t, recorder)
	wantStatuses := []string{"201", "201", "201", "201", "200"}
	if len(response.Operations) != len(wantStatuses) {
		t.Fatalf("operations = %+v", response.Operations)
	}
	for i, want := range wantStatuses {
		if response.Operations[i].Status != want {
			t.Fatalf("operation %d = %+v, want status %s", i, response.Operations[i], want)
		}
	}

	userA := bulkOperationResource[User](t, response.Operations[0])
	userAB := bulkOperationResource[User](t, response.Operations[1])
	group := bulkOperationResource[Group](t, response.Operations[2])
	userC := bulkOperationResource[User](t, response.Operations[3])
	if userA.DisplayName != "literal bulkId:ab text" {
		t.Fatalf("displayName was rewritten: %q", userA.DisplayName)
	}
	if userA.Name == nil || userA.Name.GivenName != "literal bulkId:a text" {
		t.Fatalf("nested name was rewritten: %+v", userA.Name)
	}
	if group.DisplayName != "literal bulkId:a text" {
		t.Fatalf("group displayName was rewritten: %q", group.DisplayName)
	}
	if len(group.Members) != 2 || group.Members[0].Value != userAB.ID || group.Members[1].Value != userA.ID {
		t.Fatalf("group members = %+v, user-a = %q, user-ab = %q", group.Members, userA.ID, userAB.ID)
	}
	stored, err := env.store.GetGroup(t.Context(), group.ID)
	if err != nil {
		t.Fatalf("GetGroup error = %v", err)
	}
	if len(stored.Members) != 3 || stored.Members[2].Value != userC.ID {
		t.Fatalf("patched members = %+v, user-c = %q", stored.Members, userC.ID)
	}
}

// TestBulkBulkIDUnresolved verifies missing, forward and failed references fail the operation
// without creating partial resources. | TestBulkBulkIDUnresolved 校验缺失、前向与失败引用使操作
// 失败且不创建部分资源。
func TestBulkBulkIDUnresolved(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{
				BulkID: "missing",
				Method: "POST",
				Path:   "/Groups",
				Data: map[string]any{
					"displayName": "missing-ref",
					"members":     []any{map[string]any{"value": "bulkId:absent"}},
				},
			},
			{
				Method: "PATCH",
				Path:   "/Users/bulkId:absent",
				Data: map[string]any{
					"schemas":    []string{PatchOpSchema},
					"Operations": []any{map[string]any{"op": "replace", "path": "displayName", "value": "x"}},
				},
			},
			{
				BulkID: "forward",
				Method: "POST",
				Path:   "/Groups",
				Data: map[string]any{
					"displayName": "forward-ref",
					"members":     []any{map[string]any{"value": "bulkId:later"}},
				},
			},
			{
				BulkID: "later",
				Method: "POST",
				Path:   "/Users",
				Data:   map[string]any{"userName": "forward-user"},
			},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response := decodeResponse[BulkResponse](t, recorder)
	if len(response.Operations) != 4 {
		t.Fatalf("operations = %+v", response.Operations)
	}
	for i := 0; i < 3; i++ {
		if response.Operations[i].Status != "400" {
			t.Fatalf("operation %d = %+v, want 400", i, response.Operations[i])
		}
		failure, ok := response.Operations[i].Response.(map[string]any)
		if !ok || failure["scimType"] != "invalidValue" {
			t.Fatalf("operation %d failure = %#v", i, response.Operations[i].Response)
		}
	}
	if response.Operations[3].Status != "201" {
		t.Fatalf("forward definition = %+v", response.Operations[3])
	}
	if _, total, err := env.store.ListGroups(t.Context(), ListQuery{}); err != nil || total != 0 {
		t.Fatalf("unresolved references created groups: total = %d, %v", total, err)
	}

	existing := env.mustCreateUser(map[string]any{"userName": "failed-definition"})
	recorder = env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{
				BulkID: "failed",
				Method: "POST",
				Path:   "/Users",
				Data:   map[string]any{"userName": existing.UserName},
			},
			{
				BulkID: "group",
				Method: "POST",
				Path:   "/Groups",
				Data: map[string]any{
					"displayName": "failed-definition-ref",
					"members":     []any{map[string]any{"value": "bulkId:failed"}},
				},
			},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response = decodeResponse[BulkResponse](t, recorder)
	if len(response.Operations) != 2 || response.Operations[0].Status != "409" || response.Operations[1].Status != "400" {
		t.Fatalf("failed definition response = %+v", response.Operations)
	}
	if _, total, err := env.store.ListGroups(t.Context(), ListQuery{}); err != nil || total != 0 {
		t.Fatalf("failed definition was referenced: total = %d, %v", total, err)
	}
}

// TestBulkPayloadLimitSaturation verifies the read limit does not overflow when configured as
// MaxInt64. | TestBulkPayloadLimitSaturation 校验读取上限配置为 MaxInt64 时不会溢出。
func TestBulkPayloadLimitSaturation(t *testing.T) {
	env := newTestEnv(t, Options{BulkMaxPayloadSize: math.MaxInt64}, "/scim")
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "saturated"}},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response := decodeResponse[BulkResponse](t, recorder)
	if len(response.Operations) != 1 || response.Operations[0].Status != "201" {
		t.Fatalf("operations = %+v", response.Operations)
	}
}

// TestBulkPatchPasswordWithoutHook verifies a missing password hook is rejected before the
// store write, so the bulk operation does not leave a partial update. |
// TestBulkPatchPasswordWithoutHook 校验缺少口令钩子时在存储写入前拒绝，避免批量操作留下部分更新。
func TestBulkPatchPasswordWithoutHook(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	user := env.mustCreateUser(map[string]any{"userName": "bulk-password"})
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{
				Method: "PATCH",
				Path:   "/Users/" + user.ID,
				Data: map[string]any{
					"schemas": []string{PatchOpSchema},
					"Operations": []any{
						map[string]any{"op": "replace", "path": "displayName", "value": "partial"},
						map[string]any{"op": "replace", "path": "password", "value": "test-password"},
					},
				},
			},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response := decodeResponse[BulkResponse](t, recorder)
	if len(response.Operations) != 1 || response.Operations[0].Status != "400" {
		t.Fatalf("operations = %+v", response.Operations)
	}
	failure, ok := response.Operations[0].Response.(map[string]any)
	if !ok || failure["scimType"] != "invalidValue" {
		t.Fatalf("failure = %#v", response.Operations[0].Response)
	}
	stored, err := env.store.GetUser(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if stored.DisplayName != "" {
		t.Fatalf("partial update was committed: displayName = %q", stored.DisplayName)
	}
}

// TestBulkFailOnErrorsBoundaries verifies validation and non-transactional stop semantics. |
// TestBulkFailOnErrorsBoundaries 校验校验规则与非事务性的停止语义。
func TestBulkFailOnErrorsBoundaries(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		FailOnErrors: -1,
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "negative"}},
		},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	if _, total, err := env.store.ListUsers(t.Context(), ListQuery{}); err != nil || total != 0 {
		t.Fatalf("negative failOnErrors mutated store: total = %d, %v", total, err)
	}

	recorder = env.do(http.MethodPost, "/Bulk", BulkRequest{
		FailOnErrors: 1,
		Operations: []BulkOperation{
			{BulkID: "kept", Method: "POST", Path: "/Users", Data: map[string]any{"userName": "kept"}},
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "kept"}},
			{BulkID: "skipped", Method: "POST", Path: "/Users", Data: map[string]any{"userName": "skipped"}},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response := decodeResponse[BulkResponse](t, recorder)
	if len(response.Operations) != 2 || response.Operations[0].Status != "201" || response.Operations[1].Status != "409" {
		t.Fatalf("failOnErrors response = %+v", response.Operations)
	}
	users, total, err := env.store.ListUsers(t.Context(), ListQuery{Count: -1})
	if err != nil || total != 1 || len(users) != 1 || users[0].UserName != "kept" {
		t.Fatalf("partial success was rolled back or skipped operation ran: total = %d, users = %+v, %v", total, users, err)
	}

	before := total
	recorder = env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{BulkID: "dup", Method: "POST", Path: "/Users", Data: map[string]any{"userName": "dup-one"}},
			{BulkID: "dup", Method: "POST", Path: "/Users", Data: map[string]any{"userName": "dup-two"}},
		},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	if _, after, err := env.store.ListUsers(t.Context(), ListQuery{}); err != nil || after != before {
		t.Fatalf("duplicate bulkIds mutated store: before = %d, after = %d, %v", before, after, err)
	}
}
