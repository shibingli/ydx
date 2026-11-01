package waf

import (
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
