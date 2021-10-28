package demo

import (
	"github.com/google/uuid"
	"strconv"
	"time"
	"users/errors"
	"users/models"
)

// UsersDB is a demo implementation of the database.User type.
type UsersDB struct {
	idCount int
	tokens  []models.Token
	users   []models.User
}

func (u *UsersDB) CreateUser(user models.User) (*models.User, *errors.Error) {
	for _, dbUser := range u.users {
		if dbUser.Username == user.Username {
			return nil, errors.UserAlreadyExist()
		}
	}
	u.idCount++
	user.Identifier = strconv.Itoa(u.idCount)
	u.users = append(u.users, user)
	return &user, nil
}

func (u *UsersDB) CreateToken(user models.User) (*models.Token, *errors.Error) {
	token := models.Token{
		ID:       uuid.New().String(),
		Issued:   time.Now(),
		Expires:  time.Now().Add(time.Hour * 1),
		UserRole: user.Role,
		UserID:   user.Identifier,
	}
	u.tokens = append(u.tokens, token)
	return &token, nil
}

func (u *UsersDB) CountUsers() (int, *errors.Error) {
	return len(u.users), nil
}

func (u *UsersDB) ReadUsers() ([]models.User, *errors.Error) {
	return u.users, nil
}

func (u *UsersDB) ReadUserByID(id string) (*models.User, *errors.Error) {
	for _, user := range u.users {
		if user.Identifier == id {
			return &user, nil
		}
	}
	return nil, errors.UserNotFound()
}

func (u *UsersDB) ReadUserByUsername(username string) (*models.User, *errors.Error) {
	for _, user := range u.users {
		if user.Username == username {
			return &user, nil
		}
	}
	return nil, errors.UserNotFound()
}

func (u *UsersDB) ReadTokenByID(id string) (*models.Token, *errors.Error) {
	for _, token := range u.tokens {
		if token.ID == id {
			return &token, nil
		}
	}
	return nil, errors.AccessTokenNotFound()
}

func (u *UsersDB) ReadTokens() ([]models.Token, *errors.Error) {
	return u.tokens, nil
}

func (u *UsersDB) UpdateUser(user models.User) (*models.User, *errors.Error) {
	match := false
	index := 0
	for i, existingUser := range u.users {
		if existingUser.Identifier == user.Identifier {
			match = true
			index = i
			break
		}
	}
	if match == false {
		return nil, errors.UserNotFound()
	}
	u.users[index] = user
	return &user, nil
}

func (u *UsersDB) DeleteUser(id string) *errors.Error {
	index := -1
	for i, user := range u.users {
		if user.Identifier == id {
			index = i
		}
	}
	if index != -1 {
		u.users = removeUser(u.users, index)
		return nil
	}
	return errors.UserNotFound()
}

func (u *UsersDB) DeleteToken(id string) *errors.Error {
	for i, token := range u.tokens {
		if token.ID == id {
			u.tokens = remove(u.tokens, i)
			return nil
		}
	}
	return errors.AccessTokenNotFound()
}

func (u *UsersDB) DeleteTokenByUserID(userID string) *errors.Error {
	for i, token := range u.tokens {
		if token.UserID == userID {
			u.tokens = remove(u.tokens, i)
			return nil
		}
	}
	return errors.AccessTokenNotFound()
}

//region Helpers
func remove(slice []models.Token, i int) []models.Token {
	copy(slice[i:], slice[i+1:])
	return slice[:len(slice)-1]
}

func removeUser(slice []models.User, i int) []models.User {
	copy(slice[i:], slice[i+1:])
	return slice[:len(slice)-1]
}

//endregion
