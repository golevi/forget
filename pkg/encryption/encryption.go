package encryption

type Keyer func(password, salt []byte) ([]byte, error)

type Cipher struct {
	Payload []byte
	Nonce   []byte
	Salt    []byte
}
