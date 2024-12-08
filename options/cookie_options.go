package options

import "net/http"

type CookieOptions struct {
	name     string
	Secure   bool
	HttpOnly bool
	Path     string
	MaxAge   int
	SameSite http.SameSite
}

func (c *CookieOptions) GetName() string {
	return c.name
}

func (c *CookieOptions) SetName(name string) {
	c.name = name
}
