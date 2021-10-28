package models

import "time"

// Token represents an authentication access token.
type Token struct {
	ID       string
	Issued   time.Time
	Expires  time.Time
	UserID   string
	UserRole Role
}
