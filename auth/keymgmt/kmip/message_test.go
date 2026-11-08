package kmip

import (
	"errors"
	"testing"
)

// TestDecodeRejectsDuplicateScalarTags covers duplicate-tag smuggling in message headers and batch
// items. | TestDecodeRejectsDuplicateScalarTags 覆盖消息头与批处理项中的重复标签夹带。
func TestDecodeRejectsDuplicateScalarTags(t *testing.T) {
	payload := mustItem(t, GetRequest{UniqueIdentifier: "dup"})
	batchItem := NewStructure(TagBatchItem,
		NewEnumeration(TagOperation, uint32(OpGet)),
		NewStructure(TagRequestPayload, payload.Children...),
	)
	tests := []struct {
		name    string
		message Item
		decode  func([]byte) error
	}{
		{
			name: "request header protocol version",
			message: NewStructure(TagRequestMessage,
				NewStructure(TagRequestHeader,
					protocolVersionItem(DefaultProtocolVersion),
					protocolVersionItem(DefaultProtocolVersion),
					NewInteger(TagBatchCount, 1),
				),
				batchItem,
			),
			decode: func(data []byte) error {
				_, err := DecodeRequest(data)
				return err
			},
		},
		{
			name: "request batch item operation",
			message: NewStructure(TagRequestMessage,
				NewStructure(TagRequestHeader,
					protocolVersionItem(DefaultProtocolVersion),
					NewInteger(TagBatchCount, 1),
				),
				NewStructure(TagBatchItem,
					NewEnumeration(TagOperation, uint32(OpGet)),
					NewEnumeration(TagOperation, uint32(OpLocate)),
					NewStructure(TagRequestPayload, payload.Children...),
				),
			),
			decode: func(data []byte) error {
				_, err := DecodeRequest(data)
				return err
			},
		},
		{
			name: "response header batch count",
			message: NewStructure(TagResponseMessage,
				NewStructure(TagResponseHeader,
					protocolVersionItem(DefaultProtocolVersion),
					NewInteger(TagBatchCount, 1),
					NewInteger(TagBatchCount, 1),
				),
				NewStructure(TagBatchItem,
					NewEnumeration(TagOperation, uint32(OpGet)),
					NewEnumeration(TagResultStatus, uint32(ResultStatusSuccess)),
				),
			),
			decode: func(data []byte) error {
				_, err := DecodeResponse(data)
				return err
			},
		},
		{
			name: "response batch item result status",
			message: NewStructure(TagResponseMessage,
				NewStructure(TagResponseHeader,
					protocolVersionItem(DefaultProtocolVersion),
					NewInteger(TagBatchCount, 1),
				),
				NewStructure(TagBatchItem,
					NewEnumeration(TagOperation, uint32(OpGet)),
					NewEnumeration(TagResultStatus, uint32(ResultStatusSuccess)),
					NewEnumeration(TagResultStatus, uint32(ResultStatusOperationFailed)),
				),
			),
			decode: func(data []byte) error {
				_, err := DecodeResponse(data)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := Encode(test.message)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if err := test.decode(data); !errors.Is(err, ErrMalformed) {
				t.Fatalf("decode err = %v, want ErrMalformed", err)
			}
		})
	}
}

// TestDecodeRejectsDuplicateProtocolVersionFields covers duplicate major/minor fields.
// | TestDecodeRejectsDuplicateProtocolVersionFields 覆盖重复的主/次版本字段。
func TestDecodeRejectsDuplicateProtocolVersionFields(t *testing.T) {
	payload := mustItem(t, GetRequest{UniqueIdentifier: "dup"})
	message := NewStructure(TagRequestMessage,
		NewStructure(TagRequestHeader,
			NewStructure(TagProtocolVersion,
				NewInteger(TagProtocolVersionMajor, 1),
				NewInteger(TagProtocolVersionMajor, 2),
				NewInteger(TagProtocolVersionMinor, 4),
			),
			NewInteger(TagBatchCount, 1),
		),
		NewStructure(TagBatchItem,
			NewEnumeration(TagOperation, uint32(OpGet)),
			NewStructure(TagRequestPayload, payload.Children...),
		),
	)
	data, err := Encode(message)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := DecodeRequest(data); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate protocol version fields err = %v, want ErrMalformed", err)
	}
}
