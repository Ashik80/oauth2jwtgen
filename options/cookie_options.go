package options

type CookieOptions struct {
	name     string
	Secure   bool
	HttpOnly bool
	Path     string
	MaxAge   int
}

func (c *CookieOptions) MapFrom(cookieOptions *CookieOptions) {
	c.Secure = cookieOptions.Secure
	c.HttpOnly = cookieOptions.HttpOnly
	c.Path = cookieOptions.Path
	c.MaxAge = cookieOptions.MaxAge
}

func (c *CookieOptions) GetName() string {
	return c.name
}

func (c *CookieOptions) SetName(name string) {
	c.name = name
}
