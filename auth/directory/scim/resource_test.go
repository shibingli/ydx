package scim

import (
	"testing"
	"time"
)

// TestSchemaCloneDeepCopies verifies schema discovery clones do not share slices. |
// TestSchemaCloneDeepCopies 校验 Schema 发现克隆不共享切片。
func TestSchemaCloneDeepCopies(t *testing.T) {
	var nilSchema *SchemaDefinition
	if nilSchema.Clone() != nil {
		t.Fatalf("nil schema clone")
	}
	schema := &SchemaDefinition{
		Schemas: []string{SchemaSchema},
		ID:      UserSchema,
		Attributes: []Attribute{{
			Name:            "emails",
			SubAttributes:   []Attribute{{Name: "value"}},
			CanonicalValues: []string{"work"},
			ReferenceTypes:  []string{"User"},
		}},
		Meta: &Meta{ResourceType: "Schema"},
	}
	clone := schema.Clone()
	if clone == schema || &clone.Attributes[0] == &schema.Attributes[0] {
		t.Fatalf("schema clone shares memory")
	}
	clone.Schemas[0] = "changed"
	clone.Attributes[0].Name = "changed"
	clone.Attributes[0].SubAttributes[0].Name = "changed"
	clone.Attributes[0].CanonicalValues[0] = "changed"
	clone.Attributes[0].ReferenceTypes[0] = "changed"
	clone.Meta.ResourceType = "changed"
	if schema.Schemas[0] != SchemaSchema || schema.Attributes[0].Name != "emails" ||
		schema.Attributes[0].SubAttributes[0].Name != "value" ||
		schema.Attributes[0].CanonicalValues[0] != "work" ||
		schema.Attributes[0].ReferenceTypes[0] != "User" ||
		schema.Meta.ResourceType != "Schema" {
		t.Fatalf("schema mutated through clone: %+v", schema)
	}
	if empty := cloneAttributes(nil); empty != nil {
		t.Fatalf("empty cloneAttributes = %#v", empty)
	}

	var nilResource *ResourceTypeDefinition
	if nilResource.Clone() != nil {
		t.Fatalf("nil resource type clone")
	}
	resourceType := &ResourceTypeDefinition{
		Schemas:          []string{ResourceTypeSchema},
		SchemaExtensions: []SchemaExtension{{Schema: EnterpriseUserSchema}},
		Meta:             &Meta{ResourceType: "ResourceType"},
	}
	resourceClone := resourceType.Clone()
	resourceClone.Schemas[0] = "changed"
	resourceClone.SchemaExtensions[0].Schema = "changed"
	resourceClone.Meta.ResourceType = "changed"
	if resourceType.Schemas[0] != ResourceTypeSchema ||
		resourceType.SchemaExtensions[0].Schema != EnterpriseUserSchema ||
		resourceType.Meta.ResourceType != "ResourceType" {
		t.Fatalf("resource type mutated through clone: %+v", resourceType)
	}

	var nilConfig *ServiceProviderConfig
	if nilConfig.Clone() != nil {
		t.Fatalf("nil config clone")
	}
	config := &ServiceProviderConfig{
		Schemas:               []string{ServiceProviderConfigSchema},
		AuthenticationSchemes: []AuthenticationScheme{{Type: "oauthbearertoken"}},
		Meta:                  &Meta{ResourceType: "ServiceProviderConfig"},
	}
	configClone := config.Clone()
	configClone.Schemas[0] = "changed"
	configClone.AuthenticationSchemes[0].Type = "changed"
	configClone.Meta.ResourceType = "changed"
	if config.Schemas[0] != ServiceProviderConfigSchema ||
		config.AuthenticationSchemes[0].Type != "oauthbearertoken" ||
		config.Meta.ResourceType != "ServiceProviderConfig" {
		t.Fatalf("config mutated through clone: %+v", config)
	}
}

// TestResourceClones verifies User and Group clones are independent deep copies. |
// TestResourceClones 校验 User 与 Group 克隆是独立的深拷贝。
func TestResourceClones(t *testing.T) {
	var nilUser *User
	if nilUser.Clone() != nil {
		t.Fatalf("nil user clone")
	}
	if nilUser.Sanitize() != nil {
		t.Fatalf("nil user sanitize")
	}
	active := true
	user := &User{
		Schemas:          []string{UserSchema},
		UserName:         "alice",
		Active:           &active,
		Password:         "secret",
		Name:             &Name{GivenName: "Alice"},
		Emails:           []MultiValue{{Value: "alice@example.com"}},
		PhoneNumbers:     []MultiValue{{Value: "+1"}},
		IMs:              []MultiValue{{Value: "alice"}},
		Photos:           []MultiValue{{Value: "https://example.com/p.png"}},
		Entitlements:     []MultiValue{{Value: "e"}},
		Roles:            []MultiValue{{Value: "r"}},
		X509Certificates: []MultiValue{{Value: "cert"}},
		Addresses:        []Address{{Locality: "L"}},
		Groups:           []GroupValue{{Value: "g1"}},
		EnterpriseUser: &EnterpriseUser{
			EmployeeNumber: "1",
			Manager:        &Manager{Value: "m1"},
		},
		Meta: &Meta{Version: `W/"1"`},
	}
	clone := user.Clone()
	if clone == user {
		t.Fatalf("user clone is identical")
	}
	*clone.Active = false
	clone.Schemas[0] = "changed"
	clone.Name.GivenName = "changed"
	clone.Emails[0].Value = "changed"
	clone.PhoneNumbers[0].Value = "changed"
	clone.IMs[0].Value = "changed"
	clone.Photos[0].Value = "changed"
	clone.Entitlements[0].Value = "changed"
	clone.Roles[0].Value = "changed"
	clone.X509Certificates[0].Value = "changed"
	clone.Addresses[0].Locality = "changed"
	clone.Groups[0].Value = "changed"
	clone.EnterpriseUser.EmployeeNumber = "changed"
	clone.EnterpriseUser.Manager.Value = "changed"
	clone.Meta.Version = "changed"
	if !*user.Active || user.Schemas[0] != UserSchema || user.Name.GivenName != "Alice" ||
		user.Emails[0].Value != "alice@example.com" || user.PhoneNumbers[0].Value != "+1" ||
		user.IMs[0].Value != "alice" || user.Photos[0].Value != "https://example.com/p.png" ||
		user.Entitlements[0].Value != "e" || user.Roles[0].Value != "r" ||
		user.X509Certificates[0].Value != "cert" || user.Addresses[0].Locality != "L" ||
		user.Groups[0].Value != "g1" || user.EnterpriseUser.EmployeeNumber != "1" ||
		user.EnterpriseUser.Manager.Value != "m1" || user.Meta.Version != `W/"1"` {
		t.Fatalf("user mutated through clone: %+v", user)
	}
	sanitized := user.Sanitize()
	if sanitized.Password != "" || user.Password != "secret" {
		t.Fatalf("sanitize password = %q, original = %q", sanitized.Password, user.Password)
	}
	minimal := &User{Schemas: []string{UserSchema}}
	minimalClone := minimal.Clone()
	if minimalClone.Name != nil || minimalClone.Addresses != nil || minimalClone.Groups != nil ||
		minimalClone.Active != nil || minimalClone.Meta != nil || minimalClone.EnterpriseUser != nil {
		t.Fatalf("minimal clone = %+v", minimalClone)
	}

	var nilGroup *Group
	if nilGroup.Clone() != nil {
		t.Fatalf("nil group clone")
	}
	group := &Group{
		Schemas:     []string{GroupSchema},
		DisplayName: "staff",
		Members:     []GroupMember{{Value: "u1"}},
		Meta:        &Meta{Version: "v1"},
	}
	groupClone := group.Clone()
	groupClone.Schemas[0] = "changed"
	groupClone.Members[0].Value = "changed"
	groupClone.Meta.Version = "changed"
	if group.Schemas[0] != GroupSchema || group.Members[0].Value != "u1" || group.Meta.Version != "v1" {
		t.Fatalf("group mutated through clone: %+v", group)
	}
	emptyGroup := (&Group{DisplayName: "empty"}).Clone()
	if emptyGroup.Members != nil || emptyGroup.Meta != nil {
		t.Fatalf("empty group clone = %+v", emptyGroup)
	}
	if (*GroupMember)(nil).Clone() != nil {
		t.Fatalf("nil group member clone")
	}
}

// TestPrimitiveClones verifies nil and value clone behavior of nested types. |
// TestPrimitiveClones 校验嵌套类型的空值与取值克隆行为。
func TestPrimitiveClones(t *testing.T) {
	if (*Name)(nil).Clone() != nil || (*MultiValue)(nil).Clone() != nil ||
		(*Address)(nil).Clone() != nil || (*GroupValue)(nil).Clone() != nil ||
		(*Manager)(nil).Clone() != nil || (*EnterpriseUser)(nil).Clone() != nil ||
		(*Meta)(nil).Clone() != nil {
		t.Fatalf("nil clone returned non-nil")
	}
	name := &Name{FamilyName: "Liddell"}
	if clone := name.Clone(); clone == name || clone.FamilyName != "Liddell" {
		t.Fatalf("name clone = %+v", clone)
	}
	multi := &MultiValue{Value: "v", Primary: true}
	if clone := multi.Clone(); clone == multi || clone.Value != "v" || !clone.Primary {
		t.Fatalf("multi clone = %+v", clone)
	}
	address := &Address{Locality: "L"}
	if clone := address.Clone(); clone == address || clone.Locality != "L" {
		t.Fatalf("address clone = %+v", clone)
	}
	groupValue := &GroupValue{Value: "g"}
	if clone := groupValue.Clone(); clone == groupValue || clone.Value != "g" {
		t.Fatalf("group value clone = %+v", clone)
	}
	manager := &Manager{Value: "m"}
	if clone := manager.Clone(); clone == manager || clone.Value != "m" {
		t.Fatalf("manager clone = %+v", clone)
	}
	enterprise := &EnterpriseUser{EmployeeNumber: "1", Manager: &Manager{Value: "m"}}
	if clone := enterprise.Clone(); clone == enterprise || clone.Manager == enterprise.Manager || clone.Manager.Value != "m" {
		t.Fatalf("enterprise clone = %+v", clone)
	}
	if clone := (&EnterpriseUser{EmployeeNumber: "2"}).Clone(); clone.Manager != nil {
		t.Fatalf("enterprise nil manager clone = %+v", clone)
	}
	meta := &Meta{Version: "v"}
	if clone := meta.Clone(); clone == meta || clone.Version != "v" {
		t.Fatalf("meta clone = %+v", clone)
	}
}

// TestTimeHelpers verifies SCIM dateTime formatting and parsing. | TestTimeHelpers 校验 SCIM
// dateTime 格式化与解析。
func TestTimeHelpers(t *testing.T) {
	if got := formatTime(time.Time{}); got != "" {
		t.Fatalf("zero format = %q", got)
	}
	moment := time.Date(2024, 5, 6, 7, 8, 9, 0, time.FixedZone("X", 3600))
	if got := formatTime(moment); got != "2024-05-06T06:08:09Z" {
		t.Fatalf("format = %q", got)
	}
	if got := parseTime(""); !got.IsZero() {
		t.Fatalf("empty parse = %v", got)
	}
	if got := parseTime("not-a-time"); !got.IsZero() {
		t.Fatalf("invalid parse = %v", got)
	}
	parsed := parseTime("2024-05-06T07:08:09+01:00")
	if !parsed.Equal(moment) || parsed.Location() != time.UTC {
		t.Fatalf("parse = %v", parsed)
	}
	if !isSchemaURN(UserSchema) || !isSchemaURN("URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:USER") {
		t.Fatalf("known schema URN not recognized")
	}
	if isSchemaURN("urn:example:unknown") || isSchemaURN("") {
		t.Fatalf("unknown schema URN recognized")
	}
}

// TestPrimaryValueHelpers verifies primary selection and fallbacks. | TestPrimaryValueHelpers 校验
// 首选值选择与回退。
func TestPrimaryValueHelpers(t *testing.T) {
	if primaryMultiIndex(nil) != -1 || primaryMultiIndex([]MultiValue{{Value: "a"}}) != -1 {
		t.Fatalf("primaryMultiIndex unexpected match")
	}
	if got := primaryMultiIndex([]MultiValue{{Value: "a"}, {Value: "b", Primary: true}, {Value: "c", Primary: true}}); got != 1 {
		t.Fatalf("primaryMultiIndex = %d", got)
	}
	list := []MultiValue{{Value: "a", Primary: true}, {Value: "b", Primary: true}, {Value: "c"}}
	normalizeMultiPrimary(list)
	if !list[0].Primary || list[1].Primary || list[2].Primary {
		t.Fatalf("normalizeMultiPrimary = %+v", list)
	}
	if cloneMultiValues(nil) != nil {
		t.Fatalf("cloneMultiValues nil")
	}

	var nilUser *User
	if nilUser.PrimaryEmail() != "" || nilUser.PrimaryPhone() != "" {
		t.Fatalf("nil user primary values")
	}
	if (&User{}).PrimaryEmail() != "" || (&User{}).PrimaryPhone() != "" {
		t.Fatalf("empty user primary values")
	}
	user := &User{
		Emails:       []MultiValue{{Value: ""}, {Value: "fallback@example.com"}, {Value: "primary@example.com", Primary: true}},
		PhoneNumbers: []MultiValue{{Value: ""}, {Value: "+1"}, {Value: "+2", Primary: true}},
	}
	if got := user.PrimaryEmail(); got != "primary@example.com" {
		t.Fatalf("PrimaryEmail = %q", got)
	}
	if got := user.PrimaryPhone(); got != "+2" {
		t.Fatalf("PrimaryPhone = %q", got)
	}
	user.Emails[2].Primary = false
	user.PhoneNumbers[2].Primary = false
	if got := user.PrimaryEmail(); got != "fallback@example.com" {
		t.Fatalf("PrimaryEmail fallback = %q", got)
	}
	if got := user.PrimaryPhone(); got != "+1" {
		t.Fatalf("PrimaryPhone fallback = %q", got)
	}
	user.Emails = []MultiValue{{Value: ""}, {Primary: true}}
	user.PhoneNumbers = []MultiValue{{Value: ""}, {Primary: true}}
	if user.PrimaryEmail() != "" || user.PrimaryPhone() != "" {
		t.Fatalf("empty-valued primary fallback")
	}
}
