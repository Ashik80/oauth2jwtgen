package options

type Validity struct {
	AccessExpiresIn  int64
	RefreshExpiresIn int64
}

func (v *Validity) GetAccessExpiresIn() int64 {
	return v.AccessExpiresIn
}

func (v *Validity) GetRefreshExpiresIn() int64 {
	return v.RefreshExpiresIn
}

func (v *Validity) SetDefaultAccessExpiresIn() {
	v.AccessExpiresIn = 10 * 60
}

func (v *Validity) SetDefaultRefreshExpiresIn() {
	v.RefreshExpiresIn = 60 * 60
}
