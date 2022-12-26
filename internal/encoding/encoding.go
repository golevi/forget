package encoding

import "encoding/base64"

func Encode(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

func Decode(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(s)
}
