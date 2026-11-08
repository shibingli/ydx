package radius

import (
	"strings"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// AttributeDefinition describes one dictionary attribute. | AttributeDefinition 描述一个字典属性。
type AttributeDefinition struct {
	// Values maps enumerated numeric values to names. Callers must treat the returned map as
	// read-only. | Values 将枚举数值映射到名称。调用方必须将返回的映射视为只读。
	Values map[uint32]string
	// Name is the dictionary name, for example "User-Name". | Name 是字典名称，例如 "User-Name"。
	Name string
	// VendorID is the vendor identifier for vendor attributes and zero otherwise. | VendorID
	// 是厂商属性的厂商标识，其它情况为零。
	VendorID uint32
	// Type is the standard attribute type, or AttrVendorSpecific for vendor attributes. | Type
	// 是标准属性类型；厂商属性为 AttrVendorSpecific。
	Type AttributeType
	// VendorType is the vendor sub-attribute type for vendor attributes. | VendorType 是厂商子属性类型。
	VendorType uint8
}

// valueKey identifies an enumerated value namespace. | valueKey 标识一个枚举值命名空间。
type valueKey struct {
	vendorID   uint32
	vendorType uint8
	attrType   AttributeType
}

// vendorKey identifies a vendor sub-attribute. | vendorKey 标识一个厂商子属性。
type vendorKey struct {
	vendorID   uint32
	vendorType uint8
}

// Dictionary maps attribute names and enumerated values to their numeric forms. | Dictionary 将
// 属性名与枚举值映射为数值形式。
//
// A Dictionary is safe for concurrent lookups and registrations. NewClient uses a fresh built-in
// dictionary unless ClientConfig.Dictionary supplies another one. | Dictionary 可安全地并发查询与
// 注册。除非 ClientConfig.Dictionary 提供其它字典，NewClient 使用一份新的内置字典。
type Dictionary struct {
	byName   map[string]AttributeDefinition
	byType   map[AttributeType]AttributeDefinition
	byVendor map[vendorKey]AttributeDefinition
	values   map[valueKey]map[uint32]string
	numbers  map[valueKey]map[string]uint32
	mu       sync.RWMutex
}

// NewDictionary returns an empty dictionary. | NewDictionary 返回空字典。
func NewDictionary() *Dictionary {
	return &Dictionary{
		byName:   make(map[string]AttributeDefinition),
		byType:   make(map[AttributeType]AttributeDefinition),
		byVendor: make(map[vendorKey]AttributeDefinition),
		values:   make(map[valueKey]map[uint32]string),
		numbers:  make(map[valueKey]map[string]uint32),
	}
}

// NewBuiltinDictionary returns a dictionary preloaded with the standard attributes used by the
// package, their enumerated values, and the Microsoft and Cisco vendor attributes. | NewBuiltinDictionary
// 返回预载本包所用标准属性、其枚举值以及 Microsoft 与 Cisco 厂商属性的字典。
func NewBuiltinDictionary() *Dictionary {
	d := NewDictionary()
	for _, def := range builtinDefinitions() {
		// Built-in definitions are static and unique; a failure would be a programming error that
		// the tests catch by asserting the registrations succeed. | 内置定义是静态且唯一的；失败
		// 属于编程错误，测试会通过断言注册成功来捕获。
		_ = d.Register(def)
	}
	return d
}

// Register adds one attribute definition. | Register 添加一个属性定义。
//
// Names and value names are matched case-insensitively. Duplicate names, standard types or
// vendor sub-attribute types return ErrDuplicateAttribute. | 名称与值名称按大小写不敏感匹配。
// 重复的名称、标准类型或厂商子属性类型返回 ErrDuplicateAttribute。
func (d *Dictionary) Register(def AttributeDefinition) error {
	if d == nil {
		return errs.Detail(ErrInvalidAttribute, "nil dictionary")
	}
	name := strings.TrimSpace(def.Name)
	if name == "" {
		return errs.Detail(ErrInvalidAttribute, "attribute name is required")
	}
	if def.VendorID != 0 {
		if def.Type != 0 && def.Type != AttrVendorSpecific {
			return errs.Detail(ErrInvalidAttribute, "vendor attribute %q must use type %d", name, uint8(AttrVendorSpecific))
		}
		def.Type = AttrVendorSpecific
	} else if def.Type == 0 {
		return errs.Detail(ErrInvalidAttribute, "standard attribute %q requires a type", name)
	}
	def.Name = name

	values := make(map[uint32]string, len(def.Values))
	numbers := make(map[string]uint32, len(def.Values))
	for number, value := range def.Values {
		value = strings.TrimSpace(value)
		if value == "" {
			return errs.Detail(ErrInvalidAttribute, "attribute %q has an empty value name", name)
		}
		key := strings.ToLower(value)
		if _, exists := numbers[key]; exists {
			return errs.Detail(ErrDuplicateAttribute, "attribute %q value %q", name, value)
		}
		values[number] = value
		numbers[key] = number
	}
	if len(values) == 0 {
		def.Values = nil
	} else {
		def.Values = values
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	key := strings.ToLower(name)
	if _, exists := d.byName[key]; exists {
		return errs.Detail(ErrDuplicateAttribute, "attribute name %q", name)
	}
	if def.VendorID != 0 {
		vk := vendorKey{vendorID: def.VendorID, vendorType: def.VendorType}
		if _, exists := d.byVendor[vk]; exists {
			return errs.Detail(ErrDuplicateAttribute, "vendor %d attribute %d", def.VendorID, def.VendorType)
		}
		d.byVendor[vk] = def
		d.values[valueKey{vendorID: def.VendorID, vendorType: def.VendorType, attrType: AttrVendorSpecific}] = values
		d.numbers[valueKey{vendorID: def.VendorID, vendorType: def.VendorType, attrType: AttrVendorSpecific}] = numbers
	} else {
		if _, exists := d.byType[def.Type]; exists {
			return errs.Detail(ErrDuplicateAttribute, "attribute type %d", uint8(def.Type))
		}
		d.byType[def.Type] = def
		d.values[valueKey{attrType: def.Type}] = values
		d.numbers[valueKey{attrType: def.Type}] = numbers
	}
	d.byName[key] = def
	return nil
}

// Lookup returns the definition registered under name. | Lookup 返回以 name 注册的定义。
func (d *Dictionary) Lookup(name string) (AttributeDefinition, bool) {
	if d == nil {
		return AttributeDefinition{}, false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	def, ok := d.byName[strings.ToLower(strings.TrimSpace(name))]
	return def, ok
}

// TypeByName returns the attribute type registered under name. Vendor attributes report
// AttrVendorSpecific. | TypeByName 返回以 name 注册的属性类型。厂商属性返回 AttrVendorSpecific。
func (d *Dictionary) TypeByName(name string) (AttributeType, bool) {
	def, ok := d.Lookup(name)
	if !ok {
		return 0, false
	}
	return def.Type, true
}

// NameByType returns the dictionary name of a standard attribute type. | NameByType 返回标准属性类型
// 的字典名称。
func (d *Dictionary) NameByType(t AttributeType) (string, bool) {
	if d == nil {
		return "", false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	def, ok := d.byType[t]
	if !ok {
		return "", false
	}
	return def.Name, true
}

// VendorByName returns the vendor identifier and vendor type registered under name. | VendorByName
// 返回以 name 注册的厂商标识与厂商类型。
func (d *Dictionary) VendorByName(name string) (vendorID uint32, vendorType uint8, ok bool) {
	def, found := d.Lookup(name)
	if !found || def.VendorID == 0 {
		return 0, 0, false
	}
	return def.VendorID, def.VendorType, true
}

// NameByVendor returns the dictionary name of a vendor sub-attribute. | NameByVendor 返回厂商子属性的字典名称。
func (d *Dictionary) NameByVendor(vendorID uint32, vendorType uint8) (string, bool) {
	if d == nil {
		return "", false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	def, ok := d.byVendor[vendorKey{vendorID: vendorID, vendorType: vendorType}]
	if !ok {
		return "", false
	}
	return def.Name, true
}

// ValueName returns the name of an enumerated standard attribute value. | ValueName 返回标准属性枚举值的名称。
func (d *Dictionary) ValueName(t AttributeType, value uint32) (string, bool) {
	if d == nil {
		return "", false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	name, ok := d.values[valueKey{attrType: t}][value]
	return name, ok
}

// ValueNumber returns the number of a named standard attribute value. | ValueNumber 返回标准属性枚举值的数值。
func (d *Dictionary) ValueNumber(t AttributeType, name string) (uint32, bool) {
	if d == nil {
		return 0, false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	value, ok := d.numbers[valueKey{attrType: t}][strings.ToLower(strings.TrimSpace(name))]
	return value, ok
}

// VendorValueName returns the name of an enumerated vendor sub-attribute value. | VendorValueName
// 返回厂商子属性枚举值的名称。
func (d *Dictionary) VendorValueName(vendorID uint32, vendorType uint8, value uint32) (string, bool) {
	if d == nil {
		return "", false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	name, ok := d.values[valueKey{vendorID: vendorID, vendorType: vendorType, attrType: AttrVendorSpecific}][value]
	return name, ok
}

// VendorValueNumber returns the number of a named vendor sub-attribute value. | VendorValueNumber
// 返回厂商子属性枚举值的数值。
func (d *Dictionary) VendorValueNumber(vendorID uint32, vendorType uint8, name string) (uint32, bool) {
	if d == nil {
		return 0, false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	value, ok := d.numbers[valueKey{vendorID: vendorID, vendorType: vendorType, attrType: AttrVendorSpecific}][strings.ToLower(strings.TrimSpace(name))]
	return value, ok
}
