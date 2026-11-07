package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	yxmlsig "github.com/shibingli/ydx/auth/crypto/xmlsig"
)

// testXMLDocument is a minimal XML document with an ID target for enveloped signatures. |
// testXMLDocument 是带 ID 目标的最小 XML 文档，用于 enveloped 签名。
const testXMLDocument = `<root ID="root"><child>value</child></root>`

// newXMLSigKey returns an RSA-2048 key, its certificate and the DER encoding. |
// newXMLSigKey 返回 RSA-2048 密钥、证书与 DER 编码。
func newXMLSigKey(b testing.TB) (*rsa.PrivateKey, *x509.Certificate, []byte) {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ydx-benchmark"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		b.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		b.Fatalf("ParseCertificate: %v", err)
	}
	return key, cert, der
}

// BenchmarkXMLSigSign compares enveloped XMLDSig signing. The ydx path parses the document; the
// goxmldsig path clones an already parsed element, so the comparison is indicative rather than
// byte-for-byte identical. | BenchmarkXMLSigSign 对比 enveloped XMLDSig 签名。ydx 路径解析文档；
// goxmldsig 路径克隆已解析元素，因此对比是参考性的，而非完全同口径。
func BenchmarkXMLSigSign(b *testing.B) {
	key, cert, der := newXMLSigKey(b)
	ours := yxmlsig.SignOptions{PrivateKey: key, Certificate: cert, ID: "root", IncludeKeyInfo: true}
	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := yxmlsig.Sign([]byte(testXMLDocument), ours); err != nil {
				b.Fatal(err)
			}
		}
	})
	ctx, err := dsig.NewSigningContext(key, [][]byte{der})
	if err != nil {
		b.Fatal(err)
	}
	b.Run("goxmldsig", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			doc := etree.NewDocument()
			if err := doc.ReadFromString(testXMLDocument); err != nil {
				b.Fatal(err)
			}
			if _, err := ctx.SignEnveloped(doc.Root()); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkXMLSigVerify compares verification of a ydx-signed document. |
// BenchmarkXMLSigVerify 对比 ydx 签名文档的校验。
func BenchmarkXMLSigVerify(b *testing.B) {
	key, cert, _ := newXMLSigKey(b)
	signed, err := yxmlsig.Sign([]byte(testXMLDocument), yxmlsig.SignOptions{
		PrivateKey: key, Certificate: cert, ID: "root", IncludeKeyInfo: true,
	})
	if err != nil {
		b.Fatal(err)
	}
	ours := yxmlsig.VerifyOptions{Certificates: []*x509.Certificate{cert}, ID: "root", RequireReference: true}
	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := yxmlsig.Verify(signed, ours); err != nil {
				b.Fatal(err)
			}
		}
	})
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(signed); err != nil {
		b.Fatal(err)
	}
	root := doc.Root()
	b.Run("goxmldsig", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := vc.Validate(root); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestXMLSigInteropWithGoXMLDSig checks that each implementation verifies the other's enveloped
// signature on the same document. | TestXMLSigInteropWithGoXMLDSig 检查两个实现互相校验对方对同一
// 文档生成的 enveloped 签名。
func TestXMLSigInteropWithGoXMLDSig(t *testing.T) {
	key, cert, der := newXMLSigKey(t)
	ydOptions := yxmlsig.SignOptions{PrivateKey: key, Certificate: cert, ID: "root", IncludeKeyInfo: true}
	ydSigned, err := yxmlsig.Sign([]byte(testXMLDocument), ydOptions)
	if err != nil {
		t.Fatalf("ydx Sign: %v", err)
	}
	if _, err := yxmlsig.Verify(ydSigned, yxmlsig.VerifyOptions{
		Certificates: []*x509.Certificate{cert}, ID: "root", RequireReference: true,
	}); err != nil {
		t.Fatalf("ydx Verify own signature: %v", err)
	}

	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	ydoc := etree.NewDocument()
	if err := ydoc.ReadFromBytes(ydSigned); err != nil {
		t.Fatalf("parse ydx-signed XML: %v", err)
	}
	if _, err := vc.Validate(ydoc.Root()); err != nil {
		t.Fatalf("goxmldsig rejected ydx signature: %v", err)
	}

	ctx, err := dsig.NewSigningContext(key, [][]byte{der})
	if err != nil {
		t.Fatalf("NewSigningContext: %v", err)
	}
	gdoc := etree.NewDocument()
	if err := gdoc.ReadFromString(testXMLDocument); err != nil {
		t.Fatalf("parse test XML: %v", err)
	}
	// SignEnveloped returns a copy with the signature appended; the input element is not mutated. |
	// SignEnveloped 返回附加签名后的副本，不会修改输入元素。
	signedElement, err := ctx.SignEnveloped(gdoc.Root())
	if err != nil {
		t.Fatalf("goxmldsig SignEnveloped: %v", err)
	}
	gdoc.SetRoot(signedElement)
	gSigned, err := gdoc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize goxmldsig signature: %v", err)
	}
	if _, err := yxmlsig.Verify(gSigned, yxmlsig.VerifyOptions{
		Certificates: []*x509.Certificate{cert}, ID: "root", RequireReference: true,
	}); err != nil {
		t.Fatalf("ydx rejected goxmldsig signature: %v", err)
	}
}
