package manager

type Manager interface {
	AddKey(kid, secret string)
	GetKey(kid string) ([]byte, error)
}
