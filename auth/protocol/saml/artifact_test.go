package saml

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestArtifactCodec covers the type 0x0004 encoding, decoding and malformed inputs. |
// TestArtifactCodec 覆盖类型 0x0004 的编码、解码与非法输入。
func TestArtifactCodec(t *testing.T) {
	source, err := NewArtifactSourceID()
	if err != nil {
		t.Fatalf("source id: %v", err)
	}
	artifact, err := NewArtifact(3, source)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	if artifact.Type != ArtifactTypeHTTP || artifact.EndpointIndex != 3 || artifact.SourceID != source {
		t.Fatalf("artifact = %+v", artifact)
	}
	encoded := artifact.Bytes()
	if len(encoded) != ArtifactSize {
		t.Fatalf("encoded length = %d", len(encoded))
	}
	if encoded[0] != 0x00 || encoded[1] != 0x04 {
		t.Fatalf("type bytes = %x", encoded[:2])
	}
	value := artifact.String()
	if EncodeArtifact(*artifact) != value {
		t.Fatalf("EncodeArtifact mismatch")
	}
	decoded, err := DecodeArtifact(value)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if *decoded != *artifact {
		t.Fatalf("decoded = %+v want %+v", decoded, artifact)
	}
	padded, err := DecodeArtifact(" " + value + "\n")
	if err != nil || *padded != *artifact {
		t.Fatalf("whitespace decode = %+v err=%v", padded, err)
	}
	raw := strings.TrimRight(value, "=")
	unpadded, err := DecodeArtifact(raw)
	if err != nil || *unpadded != *artifact {
		t.Fatalf("unpadded decode = %+v err=%v", unpadded, err)
	}
	if !artifact.SameSource(*decoded) {
		t.Fatal("SameSource rejected identical source")
	}
	other, err := NewArtifact(3, source)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	if !artifact.SameSource(*other) {
		t.Fatal("SameSource rejected identical source")
	}
	different, err := NewArtifactSourceID()
	if err != nil {
		t.Fatalf("source id: %v", err)
	}
	other.SourceID = different
	if artifact.SameSource(*other) {
		t.Fatal("SameSource matched different source")
	}
	if artifact.sameMessage(*decoded) != true {
		t.Fatal("sameMessage rejected identical handle")
	}
	key := artifact.storeKey()
	if len(key) != ArtifactSize-ArtifactEndpointIndexSize {
		t.Fatalf("store key length = %d", len(key))
	}
	indexed := *artifact
	indexed.EndpointIndex = 9
	if indexed.storeKey() != key {
		t.Fatal("store key depends on endpoint index")
	}
	indexed.MessageHandle[0] ^= 0xff
	if indexed.storeKey() == key {
		t.Fatal("store key ignores message handle")
	}
	malformed := map[string]string{
		"empty":        "",
		"spaces":       "   ",
		"not base64":   "!!!not-base64!!!",
		"short":        artifact.String()[:20],
		"long":         artifact.String() + "AAAA",
		"wrong type":   encodeRawArtifact(t, artifact, 0x0002, artifact.EndpointIndex),
		"wrong length": encodeRawArtifact(t, artifact, ArtifactTypeHTTP, artifact.EndpointIndex)[:40],
	}
	for name, input := range malformed {
		if _, err := DecodeArtifact(input); !errors.Is(err, ErrArtifactInvalid) {
			t.Fatalf("%s error = %v", name, err)
		}
	}
}

// encodeRawArtifact returns a Base64 artifact with a substituted type. | encodeRawArtifact 返回替换
// 类型后的 Base64 工件。
func encodeRawArtifact(t *testing.T, artifact *Artifact, artifactType, index uint16) string {
	t.Helper()
	copy := *artifact
	copy.Type = artifactType
	copy.EndpointIndex = index
	return copy.String()
}

// TestMemoryStoreArtifactLifecycle covers expiry, replay, cleanup and concurrency. |
// TestMemoryStoreArtifactLifecycle 覆盖过期、重放、清理与并发。
func TestMemoryStoreArtifactLifecycle(t *testing.T) {
	store := NewMemoryStore()
	now := samlTestNow
	source := [ArtifactSourceIDSize]byte{}
	copy(source[:], bytes.Repeat([]byte{0x11}, ArtifactSourceIDSize))
	artifact, err := NewArtifact(0, source)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	record := &ArtifactRecord{
		Artifact:    *artifact,
		Message:     []byte("<Response/>"),
		SPEntityID:  "https://sp.example/metadata",
		IDPEntityID: "https://idp.example/metadata",
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Minute),
	}
	if err := store.SaveArtifact(context.Background(), record, now); err != nil {
		t.Fatalf("save: %v", err)
	}
	duplicate := record.Clone()
	if err := store.SaveArtifact(context.Background(), duplicate, now); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate save error = %v", err)
	}
	taken, err := store.TakeArtifact(context.Background(), *artifact, now)
	if err != nil || string(taken.Message) != "<Response/>" || !taken.Used {
		t.Fatalf("take = %+v err=%v", taken, err)
	}
	if _, err := store.TakeArtifact(context.Background(), *artifact, now); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay error = %v", err)
	}
	if _, err := store.TakeArtifact(context.Background(), Artifact{Type: ArtifactTypeHTTP}, now); !errors.Is(err, ErrArtifactInvalid) {
		t.Fatalf("unknown error = %v", err)
	}

	expired, err := NewArtifact(0, source)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	if err := store.SaveArtifact(context.Background(), &ArtifactRecord{
		Artifact:  *expired,
		Message:   []byte("<Response/>"),
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Second),
	}, now); err != nil {
		t.Fatalf("save expiring: %v", err)
	}
	if _, err := store.TakeArtifact(context.Background(), *expired, now.Add(2*time.Second)); !errors.Is(err, ErrResponseExpired) {
		t.Fatalf("expired error = %v", err)
	}
	if _, err := store.TakeArtifact(context.Background(), *expired, now.Add(2*time.Second)); !errors.Is(err, ErrArtifactInvalid) {
		t.Fatalf("expired removal error = %v", err)
	}

	cleanup, err := NewArtifact(0, source)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	if err := store.SaveArtifact(context.Background(), &ArtifactRecord{
		Artifact:  *cleanup,
		Message:   []byte("<Response/>"),
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Second),
	}, now); err != nil {
		t.Fatalf("save cleanup: %v", err)
	}
	if err := store.Cleanup(context.Background(), now.Add(time.Hour)); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := store.TakeArtifact(context.Background(), *cleanup, now); !errors.Is(err, ErrArtifactInvalid) {
		t.Fatalf("cleaned artifact error = %v", err)
	}

	invalid := []*ArtifactRecord{
		nil,
		{Artifact: *artifact},
		{Artifact: Artifact{Type: 0x0002}, Message: []byte("x")},
		{Artifact: *artifact, Message: []byte("x"), ExpiresAt: now},
	}
	for index, entry := range invalid {
		if err := store.SaveArtifact(context.Background(), entry, now); err == nil {
			t.Fatalf("invalid record %d accepted", index)
		}
	}
}

// TestMemoryStoreArtifactConcurrentTake checks exactly one successful consumption. |
// TestMemoryStoreArtifactConcurrentTake 校验并发下恰好一次成功消费。
func TestMemoryStoreArtifactConcurrentTake(t *testing.T) {
	store := NewMemoryStore()
	source := [ArtifactSourceIDSize]byte{}
	artifact, err := NewArtifact(0, source)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	if err := store.SaveArtifact(context.Background(), &ArtifactRecord{
		Artifact:  *artifact,
		Message:   []byte("<Response/>"),
		ExpiresAt: samlTestNow.Add(time.Minute),
	}, samlTestNow); err != nil {
		t.Fatalf("save: %v", err)
	}
	const workers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	replays := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.TakeArtifact(context.Background(), *artifact, samlTestNow)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrReplay):
				replays++
			default:
				t.Errorf("take error = %v", err)
			}
		}()
	}
	wg.Wait()
	if successes != 1 || replays != workers-1 {
		t.Fatalf("successes = %d replays = %d", successes, replays)
	}
}

// TestArtifactStoreLookup checks the optional store interface. | TestArtifactStoreLookup 校验可选
// 存储接口。
func TestArtifactStoreLookup(t *testing.T) {
	if _, err := artifactStoreOf(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil store error = %v", err)
	}
	if _, err := artifactStoreOf(storeWithoutArtifacts{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("legacy store error = %v", err)
	}
	if _, err := artifactStoreOf(NewMemoryStore()); err != nil {
		t.Fatalf("memory store error = %v", err)
	}
}

// storeWithoutArtifacts implements Store only. | storeWithoutArtifacts 仅实现 Store。
type storeWithoutArtifacts struct{}

func (storeWithoutArtifacts) SaveRequest(context.Context, *RequestState) error { return nil }
func (storeWithoutArtifacts) ConsumeRequest(context.Context, string, time.Time) (*RequestState, error) {
	return nil, nil
}
func (storeWithoutArtifacts) SaveAssertion(context.Context, string, time.Time, time.Time) (bool, error) {
	return true, nil
}
func (storeWithoutArtifacts) SaveSession(context.Context, *Session) error { return nil }
func (storeWithoutArtifacts) GetSession(context.Context, string) (*Session, error) {
	return nil, nil
}
func (storeWithoutArtifacts) DeleteSession(context.Context, string) error { return nil }
func (storeWithoutArtifacts) ListSessions(context.Context, string) ([]*Session, error) {
	return nil, nil
}
func (storeWithoutArtifacts) Cleanup(context.Context, time.Time) error { return nil }

// TestArtifactMetadata verifies IdP and SP metadata advertising. | TestArtifactMetadata 校验 IdP 与
// SP 元数据声明。
func TestArtifactMetadata(t *testing.T) {
	idp, _, _, _ := newArtifactTestIdP(t, nil)
	metadata := idp.Metadata()
	if metadata.IDPSSODescriptor == nil || len(metadata.IDPSSODescriptor.ArtifactResolutionService) != 1 {
		t.Fatalf("metadata = %+v", metadata)
	}
	endpoint := metadata.IDPSSODescriptor.ArtifactResolutionService[0]
	if endpoint.Binding != BindingSOAP || endpoint.Index != 0 || !endpoint.IsDefault {
		t.Fatalf("endpoint = %+v", endpoint)
	}
	if endpoint.Location != "https://idp.example/saml/artifact" {
		t.Fatalf("location = %q", endpoint.Location)
	}
	if metadata.ArtifactResolutionURL(0) != endpoint.Location || metadata.ArtifactResolutionURL(1) != "" {
		t.Fatalf("ArtifactResolutionURL = %q", metadata.ArtifactResolutionURL(0))
	}
	data, err := metadata.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(data, []byte("ArtifactResolutionService")) || !bytes.Contains(data, []byte(`index="0"`)) {
		t.Fatalf("metadata XML = %s", data)
	}
	parsed, err := ParseEntityDescriptor(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.ArtifactResolutionURL(0) != endpoint.Location {
		t.Fatalf("parsed location = %q", parsed.ArtifactResolutionURL(0))
	}

	explicit, _, _, _ := newArtifactTestIdP(t, func(config *IdentityProviderConfig) {
		config.ArtifactResolutionURL = "https://ars.example/artifact"
	})
	if explicit.Metadata().ArtifactResolutionURL(0) != "https://ars.example/artifact" {
		t.Fatalf("explicit location = %q", explicit.Metadata().ArtifactResolutionURL(0))
	}
	if _, err := NewIdentityProvider(IdentityProviderConfig{
		EntityID:         "https://idp.example/metadata",
		SSOURL:           "https://idp.example/sso",
		Authenticator:    testAuthenticator(),
		ArtifactSourceID: []byte("short"),
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("short source ID error = %v", err)
	}
	source := make([]byte, ArtifactSourceIDSize)
	for index := range source {
		source[index] = byte(index)
	}
	pinned, _, _, _ := newArtifactTestIdP(t, func(config *IdentityProviderConfig) {
		config.ArtifactSourceID = source
	})
	if pinned.ArtifactSourceID() != [ArtifactSourceIDSize]byte(source) {
		t.Fatalf("pinned source ID = %x", pinned.ArtifactSourceID())
	}

	sp, err := NewServiceProvider(ServiceProviderConfig{
		EntityID:    "https://sp.example/metadata",
		ACSURL:      "https://sp.example/saml/acs",
		IDPMetadata: testMetadata(),
	})
	if err != nil {
		t.Fatalf("sp: %v", err)
	}
	spMetadata := sp.Metadata()
	if len(spMetadata.SPSSODescriptor.AssertionConsumerService) != 2 {
		t.Fatalf("ACS entries = %+v", spMetadata.SPSSODescriptor.AssertionConsumerService)
	}
	if location := spMetadata.ACSURL(BindingHTTPArtifact); location != "https://sp.example/saml/acs" {
		t.Fatalf("artifact ACS location = %q", location)
	}
	if _, err := NewServiceProvider(ServiceProviderConfig{
		EntityID:         "https://sp.example/metadata",
		ACSURL:           "https://sp.example/saml/acs",
		IDPMetadata:      testMetadata(),
		ArtifactSourceID: []byte("short"),
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("short SP source ID error = %v", err)
	}
}

// TestSOAPHelpers covers envelope construction, parsing and fault handling. | TestSOAPHelpers 覆盖
// 信封构建、解析与异常处理。
func TestSOAPHelpers(t *testing.T) {
	payload := []byte(`<samlp:ArtifactResolve xmlns:samlp="` + NamespaceProtocol + `" ID="r1"><samlp:Artifact>AA==</samlp:Artifact></samlp:ArtifactResolve>`)
	body := buildSOAPEnvelope(payload)
	if !bytes.Contains(body, payload) || !bytes.Contains(body, []byte(NamespaceSOAP)) {
		t.Fatalf("envelope = %s", body)
	}
	envelope, err := parseSOAPEnvelope(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	node, err := envelope.payload()
	if err != nil || node.Name.Local != "ArtifactResolve" {
		t.Fatalf("payload = %+v err=%v", node, err)
	}
	for name, input := range map[string]string{
		"empty":     "",
		"not xml":   "not xml",
		"no body":   `<soapenv:Envelope xmlns:soapenv="` + NamespaceSOAP + `"/>`,
		"wrong rns": `<Envelope xmlns="urn:other"><Body xmlns="` + NamespaceSOAP + `"/></Envelope>`,
	} {
		if _, err := parseSOAPEnvelope([]byte(input)); err == nil {
			t.Fatalf("%s envelope accepted", name)
		}
	}
	emptyBody := `<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="` + NamespaceSOAP + `"><soapenv:Body></soapenv:Body></soapenv:Envelope>`
	if parsed, err := parseSOAPEnvelope([]byte(emptyBody)); err != nil {
		t.Fatalf("empty body envelope: %v", err)
	} else if _, err := parsed.payload(); err == nil {
		t.Fatal("empty body accepted")
	}

	recorder := httptest.NewRecorder()
	writeSOAPFault(recorder, http.StatusBadGateway, "soap:Server", "boom & bust")
	if recorder.Code != http.StatusBadGateway || recorder.Header().Get("Content-Type") != SOAPContentType {
		t.Fatalf("fault response = %d %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	faultEnvelope, err := parseSOAPEnvelope(recorder.Body.Bytes())
	if err != nil {
		t.Fatalf("fault envelope: %v", err)
	}
	_, err = faultEnvelope.payload()
	var fault *SOAPFault
	if !errors.As(err, &fault) || fault.Code != "soap:Server" || fault.Reason != "boom & bust" {
		t.Fatalf("fault = %+v err=%v", fault, err)
	}
	if !errors.Is(err, ErrSOAPFault) || !strings.Contains(fault.Error(), "boom") {
		t.Fatalf("fault error = %v", err)
	}

	recorder = httptest.NewRecorder()
	writeSOAPPayload(recorder, payload)
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte("ArtifactResolve")) {
		t.Fatalf("payload response = %d", recorder.Code)
	}

	for name, test := range map[string]struct {
		header string
		value  string
		want   bool
	}{
		"missing": {want: true},
		"exact":   {header: SOAPActionArtifactResolve, want: true},
		"quoted":  {header: `"` + SOAPActionArtifactResolve + `"`, want: true},
		"wrong":   {header: SOAPActionArtifactResponse, want: false},
	} {
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		if test.header != "" {
			request.Header.Set("SOAPAction", test.header)
		}
		err := checkSOAPAction(request, SOAPActionArtifactResolve)
		if (err == nil) != test.want {
			t.Fatalf("%s SOAPAction error = %v", name, err)
		}
	}
	if err := checkSOAPAction(nil, SOAPActionArtifactResolve); err == nil {
		t.Fatal("nil request accepted")
	}

	if _, err := readSOAPBody(nil); err == nil {
		t.Fatal("nil request body accepted")
	}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body"))
	if body, err := readSOAPBody(request); err != nil || string(body) != "body" {
		t.Fatalf("read body = %q err=%v", body, err)
	}
	oversized := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body"))
	oversized.ContentLength = MaxSOAPMessageBytes + 1
	if _, err := readSOAPBody(oversized); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized body error = %v", err)
	}
}
