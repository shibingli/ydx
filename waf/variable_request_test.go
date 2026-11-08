package waf

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"reflect"
	"testing"
)

// TestParseXMLFlattensElementsAndAttributes verifies the XML body collection through ydx/xml.
// | TestParseXMLFlattensElementsAndAttributes 验证通过 ydx/xml 的 XML 正文集合。
func TestParseXMLFlattensElementsAndAttributes(t *testing.T) {
	tx := &transaction{
		requestBody: []byte(`<root a="1"><item>v</item><item>w</item></root>`),
		argLimit:    16,
	}
	tx.parseXML()
	if tx.bodyParseError {
		t.Fatalf("parse error: %s", tx.bodyErrorMessage)
	}
	if !tx.xmlParsed {
		t.Fatal("xmlParsed = false")
	}
	want := []varValue{
		{Name: "XML", Key: "root.@a", Value: "1"},
		{Name: "XML", Key: "root.item", Value: "v"},
		{Name: "XML", Key: "root.item", Value: "w"},
	}
	if !reflect.DeepEqual(tx.xmlValues, want) {
		t.Fatalf("xmlValues = %#v want %#v", tx.xmlValues, want)
	}
}

// TestParseXMLRejectsMalformed verifies malformed bodies are reported. | TestParseXMLRejectsMalformed
// 验证非法正文会被报告。
func TestParseXMLRejectsMalformed(t *testing.T) {
	tx := &transaction{
		requestBody: []byte(`<root><item></root>`),
		argLimit:    16,
	}
	tx.parseXML()
	if !tx.bodyParseError || tx.xmlParsed {
		t.Fatalf("bodyParseError=%v xmlParsed=%v", tx.bodyParseError, tx.xmlParsed)
	}
}

// TestParseXMLRespectsArgumentsLimit verifies the XML collection stops at the configured limit.
// | TestParseXMLRespectsArgumentsLimit 验证 XML 集合在配置上限处停止。
func TestParseXMLRespectsArgumentsLimit(t *testing.T) {
	tx := &transaction{
		requestBody: []byte(`<root><i>one</i><i>two</i><i>attack</i></root>`),
		argLimit:    2,
	}
	tx.parseXML()
	if len(tx.xmlValues) != 2 {
		t.Fatalf("xmlValues = %#v", tx.xmlValues)
	}
	for _, value := range tx.xmlValues {
		if value.Value == "attack" {
			t.Fatalf("XML value beyond the limit was exposed: %#v", tx.xmlValues)
		}
	}
}

// multipartTransaction builds a transaction for direct multipart parser tests. | multipartTransaction
// 为 multipart 解析器单元测试构建事务。
func multipartTransaction(t *testing.T, body *bytes.Buffer, contentType string, limit int) *transaction {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Content-Type", contentType)
	return &transaction{requestBody: body.Bytes(), req: req, argLimit: limit}
}

// TestParseMultipartRespectsArgumentsLimit verifies form fields beyond the limit are not exposed.
// | TestParseMultipartRespectsArgumentsLimit 验证超出上限的表单字段不会被暴露。
func TestParseMultipartRespectsArgumentsLimit(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, field := range []string{"one", "two", "attack"} {
		if err := writer.WriteField(field, field); err != nil {
			t.Fatalf("WriteField: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	tx := multipartTransaction(t, &body, writer.FormDataContentType(), 2)
	tx.parseMultipart()
	if len(tx.argsPost) != 2 {
		t.Fatalf("argsPost = %#v", tx.argsPost)
	}
	for _, value := range tx.argsPost {
		if value.Value == "attack" {
			t.Fatalf("field beyond the limit was exposed: %#v", tx.argsPost)
		}
	}
}

// TestParseMultipartRespectsFileLimit verifies FILES and FILES_SIZES stop at the limit.
// | TestParseMultipartRespectsFileLimit 验证 FILES 与 FILES_SIZES 在上限处停止。
func TestParseMultipartRespectsFileLimit(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, name := range []string{"one.txt", "attack.txt"} {
		part, err := writer.CreateFormFile("upload", name)
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		if _, err := part.Write([]byte("content")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	tx := multipartTransaction(t, &body, writer.FormDataContentType(), 1)
	tx.parseMultipart()
	if len(tx.files) != 1 || len(tx.fileSizes) != 1 {
		t.Fatalf("files = %#v fileSizes = %#v", tx.files, tx.fileSizes)
	}
	if tx.files[0].Value == "attack.txt" {
		t.Fatalf("file beyond the limit was exposed: %#v", tx.files)
	}
}

// TestParseMultipartRespectsPartHeaderLimit verifies part header collections stop at the limit.
// | TestParseMultipartRespectsPartHeaderLimit 验证分段头集合在上限处停止。
func TestParseMultipartRespectsPartHeaderLimit(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreatePart(textproto.MIMEHeader{
		"X-First":  {"one"},
		"X-Second": {"two"},
	})
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	_ = part
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	tx := multipartTransaction(t, &body, writer.FormDataContentType(), 1)
	tx.parseMultipart()
	if len(tx.multipartPartHeaders) != 1 {
		t.Fatalf("multipartPartHeaders = %#v", tx.multipartPartHeaders)
	}
	if len(tx.multipartPartHeaderNames) != 1 {
		t.Fatalf("multipartPartHeaderNames = %#v", tx.multipartPartHeaderNames)
	}
}
