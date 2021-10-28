// Package models contains shared models.
package models

type Role int

const (
	// Admin is an organization's system administrator.
	Admin Role = 0
	// Member is someone within the organization, employee, student, etc.
	Member Role = 1
	// Guest is anyone outside of the organization.
	Guest Role = 2
)

// User represents the user model. Role could be: admin, member, guest.
// Where member could be an employee or student, and guest is anyone outside of the organization.
type User struct {
	Identifier string
	Username   string
	Password   string
	FirstName  string
	LastName   string
	Role       Role
	IsActive   bool
}
