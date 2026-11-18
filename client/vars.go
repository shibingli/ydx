package client

import (
	"strconv"
	"strings"
	"sync"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// Vars is a concurrency-safe variable set shared by pipeline steps. | Vars 是 Pipeline 步骤共享的并发安全变量集合。
type Vars struct {
	values map[string]any
	mu     sync.RWMutex
}

// NewVars creates an empty variable set. | NewVars 创建空变量集合。
func NewVars() *Vars {
	return &Vars{values: make(map[string]any)}
}

// Set stores a value. | Set 存储一个值。
func (v *Vars) Set(name string, value any) {
	if v == nil {
		return
	}
	v.mu.Lock()
	if v.values == nil {
		v.values = make(map[string]any)
	}
	v.values[name] = value
	v.mu.Unlock()
}

// Get returns a value. | Get 返回一个值。
func (v *Vars) Get(name string) (any, bool) {
	if v == nil {
		return nil, false
	}
	v.mu.RLock()
	value, ok := v.values[name]
	v.mu.RUnlock()
	return value, ok
}

// String returns a string conversion of the value. | String 返回值的字符串形式。
func (v *Vars) String(name string) string {
	value, ok := v.Get(name)
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	case bool:
		return strconv.FormatBool(typed)
	case json.Number:
		return typed.String()
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case int32:
		return strconv.FormatInt(int64(typed), 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return ""
		}
		return string(data)
	}
}

// Int64 returns an integer conversion of the value. | Int64 返回值的整数形式。
func (v *Vars) Int64(name string) (int64, bool) {
	value, ok := v.Get(name)
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		return int64(typed), true
	case float64:
		return int64(typed), true
	case json.Number:
		result, err := typed.Int64()
		return result, err == nil
	case string:
		result, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return result, err == nil
	default:
		return 0, false
	}
}

// Bool returns a boolean conversion of the value. | Bool 返回值的布尔形式。
func (v *Vars) Bool(name string) (bool, bool) {
	value, ok := v.Get(name)
	if !ok {
		return false, false
	}
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		result, err := strconv.ParseBool(strings.TrimSpace(typed))
		return result, err == nil
	default:
		return false, false
	}
}

// JSON decodes the stored value into dst. | JSON 把存储的值解码到 dst。
func (v *Vars) JSON(name string, dst any) error {
	value, ok := v.Get(name)
	if !ok {
		return errs.Detail(ErrExtract, "missing variable | 缺少变量")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

// Clone returns a snapshot copy. | Clone 返回快照副本。
func (v *Vars) Clone() *Vars {
	if v == nil {
		return NewVars()
	}
	v.mu.RLock()
	copied := make(map[string]any, len(v.values))
	for key, value := range v.values {
		copied[key] = value
	}
	v.mu.RUnlock()
	return &Vars{values: copied}
}
