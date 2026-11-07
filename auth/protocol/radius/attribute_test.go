package radius

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestAttributeValueAccessors(t *testing.T) {
	value := []byte{0, 0, 0, 42}
	attribute := NewAttribute(AttrSessionTimeout, value)
	value[3] = 0
	if got, ok := attribute.Uint32(); !ok || got != 42 {
		t.Fatalf("Uint32 = %d, %v", got, ok)
	}
	if _, ok := (&Attribute{Value: []byte{1}}).Uint32(); ok {
		t.Fatal("Uint32 accepted a one-byte value")
	}

	ipAttribute := NewAttribute(AttrFramedIPAddress, []byte{192, 0, 2, 7})
	ip, ok := ipAttribute.IPv4()
	if !ok || !ip.Equal(net.IPv4(192, 0, 2, 7)) {
		t.Fatalf("IPv4 = %v, %v", ip, ok)
	}
	if _, ok := (&Attribute{Value: make([]byte, 16)}).IPv4(); ok {
		t.Fatal("IPv4 accepted a sixteen-byte value")
	}

	timeAttribute := NewAttribute(AttrEventTimestamp, []byte{0x65, 0x00, 0x00, 0x00})
	unixTime, ok := timeAttribute.UnixTime()
	if !ok || unixTime.Unix() != 0x65000000 {
		t.Fatalf("UnixTime = %v, %v", unixTime, ok)
	}

	if tag, number, ok := NewAttribute(AttrTunnelType, []byte{0, 0, 0, 13}).TaggedUint32(); !ok || tag != 0 || number != 13 {
		t.Fatalf("untagged TaggedUint32 = %d, %d, %v", tag, number, ok)
	}
	if tag, number, ok := NewAttribute(AttrTunnelType, []byte{3, 0, 0, 0, 13}).TaggedUint32(); !ok || tag != 3 || number != 13 {
		t.Fatalf("tagged TaggedUint32 = %d, %d, %v", tag, number, ok)
	}
	if _, _, ok := NewAttribute(AttrTunnelType, []byte{1, 2}).TaggedUint32(); ok {
		t.Fatal("TaggedUint32 accepted a two-byte value")
	}

	if tag, text := NewAttribute(AttrTunnelPrivateGroupID, []byte{9, 'g', 'r', 'p'}).TaggedString(); tag != 9 || text != "grp" {
		t.Fatalf("tagged TaggedString = %d, %q", tag, text)
	}
	if tag, text := NewAttribute(AttrTunnelPrivateGroupID, []byte("vlan-7")).TaggedString(); tag != 0 || text != "vlan-7" {
		t.Fatalf("untagged TaggedString = %d, %q", tag, text)
	}
	if tag, text := NewAttribute(AttrTunnelPrivateGroupID, []byte{0x05}).TaggedString(); tag != 0 || text != "\x05" {
		t.Fatalf("single-byte TaggedString = %d, %q", tag, text)
	}
}

func TestAttributesOperations(t *testing.T) {
	attributes := Attributes{
		NewAttribute(AttrUserName, []byte("alice")),
		NewAttribute(AttrReplyMessage, []byte("one")),
		NewAttribute(AttrReplyMessage, []byte("two")),
		NewVendorAttribute(VendorCisco, VendorCiscoAVPair, []byte("shell:priv-lvl=15")),
	}
	if attribute, ok := attributes.Get(AttrUserName); !ok || attribute.String() != "alice" {
		t.Fatalf("Get = %+v, %v", attribute, ok)
	}
	if messages := attributes.Strings(AttrReplyMessage); len(messages) != 2 || messages[0] != "one" || messages[1] != "two" {
		t.Fatalf("Strings = %v", messages)
	}
	if attribute, ok := attributes.Vendor(VendorCisco, VendorCiscoAVPair); !ok || attribute.String() != "shell:priv-lvl=15" {
		t.Fatalf("Vendor = %+v, %v", attribute, ok)
	}
	if all := attributes.VendorAll(VendorCisco, VendorCiscoAVPair); len(all) != 1 {
		t.Fatalf("VendorAll = %+v", all)
	}

	clone := attributes.Clone()
	clone[0].Value[0] = 'A'
	if attributes[0].String() != "alice" {
		t.Fatal("Clone shares value storage with the original")
	}

	attributes.AddUint32(AttrSessionTimeout, 60)
	if timeout, ok := attributes.Uint32(AttrSessionTimeout); !ok || timeout != 60 {
		t.Fatalf("Uint32 = %d, %v", timeout, ok)
	}
	attributes.AddIPv4(AttrFramedIPAddress, net.IPv4(198, 51, 100, 9))
	if ip, ok := attributes.IP(AttrFramedIPAddress); !ok || !ip.Equal(net.IPv4(198, 51, 100, 9)) {
		t.Fatalf("IP = %v, %v", ip, ok)
	}
	if err := attributes.AddIPv4(AttrFramedIPAddress, net.ParseIP("2001:db8::1")); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("AddIPv4 IPv6 error = %v", err)
	}

	attributes.Remove(AttrReplyMessage)
	if _, ok := attributes.Get(AttrReplyMessage); ok {
		t.Fatal("Remove left a Reply-Message")
	}
	attributes.Set(AttrUserName, []byte("bob"))
	if values := attributes.Strings(AttrUserName); len(values) != 1 || values[0] != "bob" {
		t.Fatalf("Set User-Name = %v", values)
	}
}

func TestAttributesNamedAccessors(t *testing.T) {
	dictionary := NewBuiltinDictionary()
	attributes := Attributes{}
	if err := attributes.AddNamed(dictionary, "user-name", []byte("alice")); err != nil {
		t.Fatalf("AddNamed: %v", err)
	}
	if err := attributes.AddNamed(dictionary, "MS-CHAP-Challenge", []byte{1, 2, 3}); err != nil {
		t.Fatalf("AddNamed vendor: %v", err)
	}
	if attribute, ok := attributes.Named(dictionary, "User-Name"); !ok || attribute.String() != "alice" {
		t.Fatalf("Named User-Name = %+v, %v", attribute, ok)
	}
	if attribute, ok := attributes.Named(dictionary, "ms-chap-challenge"); !ok || attribute.VendorID != VendorMicrosoft {
		t.Fatalf("Named vendor = %+v, %v", attribute, ok)
	}
	if err := attributes.AddNamed(nil, "User-Name", nil); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("AddNamed nil dictionary error = %v", err)
	}
	if err := attributes.AddNamed(dictionary, "No-Such-Attribute", nil); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("AddNamed unknown error = %v", err)
	}
}

func TestDictionaryBuiltin(t *testing.T) {
	dictionary := NewBuiltinDictionary()
	if name, ok := dictionary.NameByType(AttrServiceType); !ok || name != "Service-Type" {
		t.Fatalf("NameByType = %q, %v", name, ok)
	}
	if attributeType, ok := dictionary.TypeByName("message-authenticator"); !ok || attributeType != AttrMessageAuthenticator {
		t.Fatalf("TypeByName = %d, %v", attributeType, ok)
	}
	if name, ok := dictionary.ValueName(AttrAcctStatusType, uint32(AcctStatusInterimUpdate)); !ok || name != "Interim-Update" {
		t.Fatalf("ValueName = %q, %v", name, ok)
	}
	if number, ok := dictionary.ValueNumber(AttrNASPortType, "wireless-802.11"); !ok || number != uint32(NASPortTypeWirelessIEEE80211) {
		t.Fatalf("ValueNumber = %d, %v", number, ok)
	}
	if vendorID, vendorType, ok := dictionary.VendorByName("MS-CHAP2-Response"); !ok || vendorID != VendorMicrosoft || vendorType != VendorMSCHAP2Response {
		t.Fatalf("VendorByName = %d, %d, %v", vendorID, vendorType, ok)
	}
	microsoftTypes := []struct {
		name string
		want uint8
	}{
		{"MS-MPPE-Encryption-Policy", 7},
		{"MS-MPPE-Encryption-Types", 8},
		{"MS-MPPE-Send-Key", 16},
		{"MS-MPPE-Recv-Key", 17},
		{"MS-CHAP2-Response", 25},
		{"MS-Primary-DNS-Server", 28},
		{"MS-Secondary-DNS-Server", 29},
		{"MS-Primary-NBNS-Server", 30},
		{"MS-Secondary-NBNS-Server", 31},
	}
	for _, attribute := range microsoftTypes {
		vendorID, vendorType, ok := dictionary.VendorByName(attribute.name)
		if !ok || vendorID != VendorMicrosoft || vendorType != attribute.want {
			t.Errorf("VendorByName(%q) = %d, %d, %v, want %d, %d, true", attribute.name, vendorID, vendorType, ok, VendorMicrosoft, attribute.want)
		}
	}
	if name, ok := dictionary.NameByVendor(VendorCisco, VendorCiscoAVPair); !ok || name != "Cisco-AVPair" {
		t.Fatalf("NameByVendor = %q, %v", name, ok)
	}
	if _, ok := dictionary.Lookup(""); ok {
		t.Fatal("Lookup accepted an empty name")
	}
}

func TestDictionaryRegister(t *testing.T) {
	dictionary := NewDictionary()
	definition := AttributeDefinition{
		Name:   "Example-Attribute",
		Type:   AttributeType(222),
		Values: map[uint32]string{1: "One", 2: "Two"},
	}
	if err := dictionary.Register(definition); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resolved, ok := dictionary.Lookup(" example-attribute "); !ok || resolved.Name != "Example-Attribute" {
		t.Fatalf("Lookup = %+v, %v", resolved, ok)
	}
	if attributeType, ok := dictionary.TypeByName("Example-Attribute"); !ok || attributeType != AttributeType(222) {
		t.Fatalf("TypeByName = %d, %v", attributeType, ok)
	}
	if name, ok := dictionary.ValueName(AttributeType(222), 2); !ok || name != "Two" {
		t.Fatalf("ValueName = %q, %v", name, ok)
	}
	if number, ok := dictionary.ValueNumber(AttributeType(222), "ONE"); !ok || number != 1 {
		t.Fatalf("ValueNumber = %d, %v", number, ok)
	}

	if err := dictionary.Register(AttributeDefinition{Name: "Example-Attribute", Type: AttributeType(223)}); !errors.Is(err, ErrDuplicateAttribute) {
		t.Fatalf("duplicate name error = %v", err)
	}
	if err := dictionary.Register(AttributeDefinition{Name: "Other-Attribute", Type: AttributeType(222)}); !errors.Is(err, ErrDuplicateAttribute) {
		t.Fatalf("duplicate type error = %v", err)
	}
	if err := dictionary.Register(AttributeDefinition{
		Name:   "Duplicate-Value",
		Type:   AttributeType(224),
		Values: map[uint32]string{1: "same", 2: "SAME"},
	}); !errors.Is(err, ErrDuplicateAttribute) {
		t.Fatalf("duplicate value error = %v", err)
	}
	if err := dictionary.Register(AttributeDefinition{Name: "", Type: AttributeType(225)}); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("empty name error = %v", err)
	}
	if err := dictionary.Register(AttributeDefinition{Name: "No-Type"}); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("missing type error = %v", err)
	}
	if err := dictionary.Register(AttributeDefinition{Name: "Bad-Vendor", Type: AttrUserName, VendorID: 9}); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("vendor type error = %v", err)
	}

	vendorDefinition := AttributeDefinition{
		Name:       "Example-Vendor",
		VendorID:   9999,
		VendorType: 5,
		Values:     map[uint32]string{7: "Seven"},
	}
	if err := dictionary.Register(vendorDefinition); err != nil {
		t.Fatalf("Register vendor: %v", err)
	}
	if vendorID, vendorType, ok := dictionary.VendorByName("example-vendor"); !ok || vendorID != 9999 || vendorType != 5 {
		t.Fatalf("VendorByName = %d, %d, %v", vendorID, vendorType, ok)
	}
	if name, ok := dictionary.NameByVendor(9999, 5); !ok || name != "Example-Vendor" {
		t.Fatalf("NameByVendor = %q, %v", name, ok)
	}
	if err := dictionary.Register(AttributeDefinition{Name: "Example-Vendor-2", VendorID: 9999, VendorType: 5}); !errors.Is(err, ErrDuplicateAttribute) {
		t.Fatalf("duplicate vendor error = %v", err)
	}
	if name, ok := dictionary.VendorValueName(9999, 5, 7); !ok || name != "Seven" {
		t.Fatalf("VendorValueName = %q, %v", name, ok)
	}
	if number, ok := dictionary.VendorValueNumber(9999, 5, "seven"); !ok || number != 7 {
		t.Fatalf("VendorValueNumber = %d, %v", number, ok)
	}
}

func TestDictionaryConcurrentAccess(t *testing.T) {
	dictionary := NewBuiltinDictionary()
	var waitGroup sync.WaitGroup
	failures := make(chan error, 16)
	for worker := 0; worker < 8; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			for i := 0; i < 200; i++ {
				if _, ok := dictionary.ValueName(AttrServiceType, uint32(ServiceTypeLogin)); !ok {
					failures <- errors.New("missing Service-Type Login")
					return
				}
				if _, ok := dictionary.TypeByName("User-Name"); !ok {
					failures <- errors.New("missing User-Name")
					return
				}
			}
		}(worker)
	}
	for worker := 0; worker < 4; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			definition := AttributeDefinition{Name: "Concurrent-Attribute-" + strconv.Itoa(worker), Type: AttributeType(230 + worker)}
			if err := dictionary.Register(definition); err != nil {
				failures <- err
			}
		}(worker)
	}
	waitGroup.Wait()
	close(failures)
	for err := range failures {
		t.Fatalf("concurrent dictionary failure: %v", err)
	}
}

func TestAttributeTime(t *testing.T) {
	expected := time.Unix(1_700_000_000, 0).UTC()
	attribute := NewAttribute(AttrEventTimestamp, []byte{0, 0, 0, 0})
	var value [4]byte
	value[0] = byte(expected.Unix() >> 24)
	value[1] = byte(expected.Unix() >> 16)
	value[2] = byte(expected.Unix() >> 8)
	value[3] = byte(expected.Unix())
	attribute.Value = value[:]
	actual, ok := attribute.UnixTime()
	if !ok || !actual.Equal(expected) {
		t.Fatalf("UnixTime = %v, %v", actual, ok)
	}
	if !bytes.Equal(attribute.Bytes(), value[:]) {
		t.Fatalf("Bytes = %x, want %x", attribute.Bytes(), value)
	}
}
