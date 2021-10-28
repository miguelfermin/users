package database

import (
	"users/errors"
	"users/models"
)

// User is a database abstraction to communicate with an users database.
type User interface {
	// CreateUser creates a new user.
	CreateUser(user models.User) (*models.User, *errors.Error)

	// CreateToken creates a new Token.
	CreateToken(user models.User) (*models.Token, *errors.Error)

	// CountUsers returns the users count.
	CountUsers() (int, *errors.Error)

	// ReadUsers reads all users.
	ReadUsers() ([]models.User, *errors.Error)

	// ReadUserByID reads user by ID.
	ReadUserByID(id string) (*models.User, *errors.Error)

	// ReadUserByUsername reads user by username.
	ReadUserByUsername(username string) (*models.User, *errors.Error)

	// ReadTokens reads all tokens.
	ReadTokens() ([]models.Token, *errors.Error)

	// ReadTokenByID reads Token by ID.
	ReadTokenByID(id string) (*models.Token, *errors.Error)

	// UpdateUser updates the user.
	UpdateUser(user models.User) (*models.User, *errors.Error)

	// DeleteUser deletes the user that matches the passed "id".
	DeleteUser(id string) *errors.Error

	// DeleteToken deletes the token that matches the passed "id".
	DeleteToken(id string) *errors.Error

	// DeleteTokenByUserID deletes all tokens for the specified user ID.
	DeleteTokenByUserID(userID string) *errors.Error
}
