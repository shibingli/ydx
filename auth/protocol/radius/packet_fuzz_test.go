package radius

import "testing"

// FuzzParsePacket verifies attacker-controlled RADIUS bytes never panic the
// decoder. | FuzzParsePacket 校验攻击者控制的 RADIUS 字节不会使解码器 panic。
func FuzzParsePacket(f *testing.F) {
	valid, err := MarshalPacket(&Packet{Code: CodeAccessRequest, Identifier: 1, Attributes: Attributes{
		NewAttribute(AttrUserName, []byte("alice")),
	}})
	if err != nil {
		f.Fatalf("seed packet: %v", err)
	}
	f.Add(valid)
	f.Add([]byte{1})
	f.Add([]byte{1, 2, 3, 4})
	f.Add([]byte{0xff, 0xff, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		packet, err := ParsePacket(data)
		if err != nil {
			return
		}
		_ = packet.Code
	})
}
