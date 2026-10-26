package transport

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestEmbeddedSDKMatchesBuild(t *testing.T) {
	cases := []struct {
		source   string
		embedded []byte
	}{
		{"../sdk/browser/dist/yd-captcha.js", sdkScript},
		{"../sdk/browser/dist/yd-captcha.css", sdkStyle},
		{"assets/yd-captcha.js", sdkScript},
		{"assets/yd-captcha.css", sdkStyle},
		{"../pages/assets/yd-captcha.js", sdkScript},
		{"../pages/assets/yd-captcha.css", sdkStyle},
		{"../sdk/browser/src/yd-captcha.css", sdkStyle},
	}
	for _, tc := range cases {
		source, err := os.ReadFile(tc.source)
		if err != nil {
			t.Fatalf("read %s: %v (run npm run build in sdk/browser)", tc.source, err)
		}
		if !bytes.Equal(source, tc.embedded) {
			t.Fatalf("%s is not synchronized; run npm run build in sdk/browser", tc.source)
		}
	}
	source, err := os.ReadFile("../sdk/browser/src/yd-captcha.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "var LABELS_CATALOG = {};") {
		t.Fatal("source SDK lost its build-time locale marker")
	}
	if !bytes.Contains(sdkScript, []byte(`var LABELS_CATALOG = {`)) || !bytes.Contains(sdkScript, []byte(`"submit"`)) {
		t.Fatal("embedded SDK is missing the generated locale catalogs")
	}
	if len(SDKScript()) == 0 || len(SDKStyle()) == 0 {
		t.Fatal("SDK assets are empty")
	}
}
